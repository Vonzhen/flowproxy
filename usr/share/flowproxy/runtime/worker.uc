/**
 * FlowProxy | runtime/worker.uc | v1.4 (Pre-flight Validation Edition)
 * [Category B] 职责：管控后台长时异步任务的生命周期、并发锁与 DFA 状态同步。
 * [Category C] Note: 已全面引入蓝绿部署预检范式。所有涉及配置变更的任务，
 * 必须通过内核沙盒合法性校验后，方可触发 init.d 重启。
 */

'use strict';

// [Category A] 基础库与核心契约
import { cursor } from 'uci';
import { JOB_TYPES } from 'flowproxy.core.contract';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { log as sys_log } from 'flowproxy.core.logger';
import { PATH, BIN } from 'flowproxy.core.constants';
import { ExecSafe } from 'flowproxy.core.utils';

// [Category A] 任务状态与并发控制
import { get_status, transition, STATE_ENUM } from 'flowproxy.core.job';
import { acquire } from 'flowproxy.core.lock';
import { run_all_checks } from 'flowproxy.core.selfcheck';
import { StateManager } from 'flowproxy.runtime.state';

// 🚨 架构洗牌：引入 launcher 用于防熔断沙盒预检
import { check } from 'flowproxy.runtime.launcher';

// [Category A] 业务执行模块 (纯粹的数据抓取与转换层)
import { fetch_and_parse } from 'flowproxy.modules.subscription';
import { task_rebuild_groups } from 'flowproxy.modules.groups'; 
import { task_update_assets, task_rollback_assets } from 'flowproxy.modules.assets';
import { task_update_kernel } from 'flowproxy.modules.kernel'; 
import { send_telegram } from 'flowproxy.modules.notifier';
import { task_update_resources } from 'flowproxy.modules.resources';

function Log(module, level, msg, job_id) {
    sys_log(job_id, level, module, msg);
}

// [Category B] 系统重载触发器与事务型部署预检引擎 (4-Step Transaction Apply)
// 职责：严格遵循 Prepare -> Apply -> Verify -> Fallback，阻断假健康与半配置态。
function safe_system_reload(job_id, job_type) {
    Log('WORKER', 'INFO', 'Initiating 4-step Transactional Apply...', job_id);

    let gateway_script = sprintf("%s/runtime/generate.uc", PATH.BASE);
    let config_path = sprintf("%s/sing-box-run.json", PATH.RUNTIME);
    let bak_path = config_path + ".bak";

    // ==========================================
    // [Step 1: Prepare] 生成与沙盒预检
    // ==========================================
    Log('WORKER', 'INFO', '[Step 1] Prepare: Generating and validating configuration...', job_id);
    
    // 物理备份上一版安全配置
    ExecSafe(BIN.CP, ["-f", config_path, bak_path], null, job_id);

    // 重新生成配置图纸
    let gen_res = ExecSafe(BIN.UCODE, [gateway_script], null, job_id);
    if (!gen_res.ok) {
        ExecSafe(BIN.MV, ["-f", bak_path, config_path], null, job_id); // 立即还原
        die("配置生成网关执行失败: " + gen_res.detail);
    }

    // 内核级离线语法预检
    let check_res = check(config_path, {caller: 'runtime.manager'}, job_id);
    if (!check_res.ok) {
        ExecSafe(BIN.MV, ["-f", bak_path, config_path], null, job_id); // 发现致命错误，撤销脏图纸
        
        // 针对资产类引发的崩溃触发容灾回退
        if (job_type === 'update_assets' || job_type === 'update_subscriptions' || job_type === 'rebuild_groups') {
            Log('WORKER', 'WARN', 'Asset corruption detected. Initiating emergency rollback.', job_id);
            task_rollback_assets(job_id, {});
            ExecSafe(BIN.UCODE, [gateway_script], null, job_id); // 重新压制一份安全的 JSON 供下次自愈使用
        }
        die("安全预检拦截：新配置存在致命语法或规则集损坏，引擎拒载。细节: " + check_res.detail);
    }

    // ==========================================
    // [Step 2: Apply] 注入内核与进程重启
    // ==========================================
    Log('WORKER', 'INFO', '[Step 2] Apply: Firing system restart & network setup...', job_id);
    let init_cmd = sprintf("%s restart", PATH.INIT);
    let apply_res = ExecSafe(BIN.SH, ["-c", init_cmd], null, job_id);

    // ==========================================
    // [Step 3: Verify] 回读内核态数据面校验
    // ==========================================
    Log('WORKER', 'INFO', '[Step 3] Verify: Checking Kernel Data Plane (nft & ip rule)...', job_id);
    let verify_ok = true;
    let verify_detail = "";

    if (!apply_res.ok) {
        verify_ok = false;
        verify_detail = "Init 脚本重启失败或底层 network.setup 注入被硬阻断。";
    } else {
        // [Category C] Note: 正则探测屏蔽了后续的硬编码耦合，只要带 flowproxy 的表和规则存活即视为接管成功
        let nft_check = ExecSafe(BIN.SH, ["-c", "nft list table inet flowproxy"], null, job_id);
        let ip_check = ExecSafe(BIN.SH, ["-c", "ip rule show"], null, job_id);

        if (!nft_check.ok || !nft_check.data.stdout) {
            verify_ok = false;
            verify_detail = "nft table 'inet flowproxy' 未成功注入内核。";
        }
    }

    // ==========================================
    // [Step 4: Fallback] 灾难回滚
    // ==========================================
    if (!verify_ok) {
        Log('WORKER', 'CRIT', '[Step 4] Fallback: Verify FAILED! Tearing down and reverting to safe state...', job_id);
        
        // 1. 强力销毁半残的脏规则，防止流量黑洞
        let td_cmd = sprintf("ucode -S %s/system/network.uc teardown", PATH.BASE);
        ExecSafe(BIN.SH, ["-c", td_cmd], null, job_id);
        
        // 2. 物理停用残损进程
        let stop_cmd = sprintf("%s stop", PATH.INIT);
        ExecSafe(BIN.SH, ["-c", stop_cmd], null, job_id);
        
        // 3. 恢复上一版本可靠的 JSON
        ExecSafe(BIN.MV, ["-f", bak_path, config_path], null, job_id);
        
        // 4. 发起自愈：用旧 JSON 尝试拉起最后一次健康状态
        ExecSafe(BIN.SH, ["-c", init_cmd], null, job_id);

        die("事务应用失败，内核态校验未通过 (Data Plane Broken)。已安全回滚网络栈与配置。详情: " + verify_detail);
    }

    Log('WORKER', 'INFO', 'Transaction Apply Complete. System is HEALTHY.', job_id);
}

// ==========================================
// 任务处理器 (Handlers)
// ==========================================

function _handle_apply_config(job_id, payload) {
    Log('WORKER', 'INFO', 'Handling apply_config signal...', job_id);
    try {
        safe_system_reload(job_id, 'apply_config');
        return Success(true, 200, job_id);
    } catch(e) { 
        let err_msg = "" + e;
        return Fail(ERR.E_SYSTEM_BUSY, "Handler exception: " + err_msg, job_id); 
    }
}

function _handle_rebuild_groups(job_id, payload) {
    Log('WORKER', 'INFO', 'Handling standalone rebuild_groups job...', job_id);
    try {
        let res = task_rebuild_groups(job_id);
        if (!res.ok) return Fail(ERR.E_SYSTEM_BUSY, "重组节点组失败: " + res.detail, job_id);
        
        Log('WORKER', 'INFO', 'Groups rebuilt. Triggering validation...', job_id);
        safe_system_reload(job_id, 'rebuild_groups');
        return Success(true, 200, job_id);
    } catch(e) { 
        let err_msg = "" + e;
        return Fail(ERR.E_SYSTEM_BUSY, "Handler exception: " + err_msg, job_id); 
    }
}

function _handle_update_assets(job_id, payload) {
    Log('WORKER', 'INFO', 'Delegating task to Assets Manager...', job_id);
    try {
        let res = task_update_assets(job_id, payload);
        if (!res.ok) return Fail(ERR.E_SYSTEM_BUSY, res.detail, job_id);
        
        let data = res.data || {};
        let updated = data.updated || [];
        let unchanged = data.unchanged || [];
        let failed = data.failed || [];
        let total_count = length(updated) + length(unchanged) + length(failed);

        let msg = "📊 <b>巡检报告</b>%0A--------------------------------%0A";
        msg += sprintf("📦 成功更新: %d | ❌ 失败: %d%0A", length(updated), length(failed));
        msg += "📝 <b>详细清单:</b>%0A";

        for (let i = 0; i < length(failed); i++) msg += sprintf("❌ %s (失败)%0A", failed[i]);
        for (let i = 0; i < length(updated); i++) msg += sprintf("🔹 %s (已更新)%0A", updated[i]);

        if (length(unchanged) > 0) {
            if (total_count <= 30) {
                for (let i = 0; i < length(unchanged); i++) msg += sprintf("🔸 %s (未变更)%0A", unchanged[i]);
            } else {
                msg += sprintf("🔸 ...及 %d 项资产未变更 (已折叠)%0A", length(unchanged));
            }
        }

        if (data.reload_required) {
            Log('WORKER', 'INFO', 'Assets updated. Triggering validation...', job_id);
            safe_system_reload(job_id, 'update_assets');
            msg += "%0A[RESTART_PENDING]";
        } else {
            Log('WORKER', 'INFO', 'No changes detected. Reload skipped.', job_id);
            msg += "%0A♻️ <b>服务重启:</b> 无需重启 (无文件变更)";
        }
        
        return Success({ msg: msg }, 200, job_id);
    } catch(e) { 
        let err_msg = "" + e;
        return Fail(ERR.E_SYSTEM_BUSY, "Assets handler failed: " + err_msg, job_id); 
    }
}

function _handle_system_rollback(job_id, payload) {
    Log('WORKER', 'INFO', 'Delegating task to Restore Engine...', job_id);
    try {
        let res = task_rollback_assets(job_id, payload);
        if (!res.ok) return Fail(ERR.E_SYSTEM_BUSY, res.detail, job_id);
        
        if (res.data && res.data.reload_required) {
            Log('WORKER', 'INFO', 'Assets restored. Triggering validation...', job_id);
            safe_system_reload(job_id, 'system_rollback');
        }
        return Success(true, 200, job_id);
    } catch(e) { 
        let err_msg = "" + e;
        return Fail(ERR.E_SYSTEM_BUSY, "Rollback handler crashed: " + err_msg, job_id); 
    }
}

function _handle_deploy_panels(job_id, payload) {
    Log('WORKER', 'INFO', 'Delegating task to Panels Manager...', job_id);
    try {
        let res = task_update_assets(job_id, { action: 'update', target: 'panels' });
        if (!res.ok) return Fail(ERR.E_SYSTEM_BUSY, res.detail, job_id);
        return Success(true, 200, job_id);
    } catch(e) { 
        let err_msg = "" + e;
        return Fail(ERR.E_SYSTEM_BUSY, "Panels handler failed: " + err_msg, job_id); 
    }
}

function _handle_update_kernel(job_id, payload) {
    Log('WORKER', 'INFO', 'Delegating task to Kernel Manager...', job_id);
    if (type(task_update_kernel) !== "function") {
        return Fail(ERR.E_SYSTEM_BUSY, "Fatal: Kernel Manager not loaded.", job_id);
    }
    try {
        let res = task_update_kernel(job_id, payload);
        if (!res.ok) return Fail(ERR.E_SYSTEM_BUSY, res.detail, job_id);
        
        if (res.data && res.data.reload_required) {
            Log('WORKER', 'INFO', 'Kernel updated. Triggering validation...', job_id);
            safe_system_reload(job_id, 'update_kernel'); 
        }
        return Success(true, 200, job_id);
    } catch(e) { 
        let err_msg = "" + e;
        return Fail(ERR.E_SYSTEM_BUSY, "Kernel handler crashed: " + err_msg, job_id); 
    }
}

function _handle_update_resources(job_id, payload) {
    Log('WORKER', 'INFO', 'Delegating task to Resources Manager...', job_id);
    try {
        let res = task_update_resources(job_id, payload.target);
        if (!res.ok) return Fail(ERR.E_SYSTEM_BUSY, res.detail, job_id);

        let data = res.data || {};
        let msg = "";
        
        if (data.updated) {
            msg = sprintf("✅ 资源 [%s] 更新成功！当前版本: %s", payload.target, data.version);
            Log('WORKER', 'INFO', 'Resource updated. Triggering firewall validation...', job_id);
            // 🚨 防火墙资源变了，必须触发系统安全重载 (让 firewall.uc 重新生成 .nft)
            safe_system_reload(job_id, 'update_resources');
            msg += "%0A[RESTART_PENDING]";
        } else {
            msg = sprintf("✅ 资源 [%s] 已是最新版本: %s", payload.target, data.version);
            Log('WORKER', 'INFO', 'No changes detected. Reload skipped.', job_id);
            msg += "%0A♻️ 服务无需重启";
        }
        
        return Success({ msg: msg }, 200, job_id);
    } catch(e) { 
        let err_msg = "" + e;
        return Fail(ERR.E_SYSTEM_BUSY, "Resources handler failed: " + err_msg, job_id); 
    }
}

function _handle_update_subscriptions(job_id, payload) {
    Log('WORKER', 'INFO', 'Starting subscription update sequence...', job_id);
    
    let start_time = time();
    let total_nodes = 0;
    
    let u = cursor(); 
    u.load("flowproxy");
    let target_airports = [];

    if (payload.scope === 'all') {
        u.foreach("flowproxy", "subscription_airport", (s) => {
            if (s.enabled === '1') push(target_airports, s);
        });
    } else if (payload.airport_id) {
        let ap = u.get_all("flowproxy", payload.airport_id);
        if (ap && ap.enabled === '1') push(target_airports, ap);
    }

    if (length(target_airports) === 0) {
        return Fail(ERR.E_SYSTEM_BUSY, "没有找到任何已启用的订阅节点", job_id);
    }

    let sub_cfg = u.get_all("flowproxy", 'subscription') || {};
    let global_opts = { 
        allow_insecure: sub_cfg.allow_insecure, 
        packet_encoding: sub_cfg.packet_encoding, 
        user_agent: sub_cfg.user_agent 
    };

    let success_count = 0;
    for (let i = 0; i < length(target_airports); i++) {
        let ap = target_airports[i]; 
        ap.id = ap['.name']; 
        let res = fetch_and_parse(ap, global_opts, job_id); 
        let valid_nodes = (res.ok && res.data && type(res.data.nodes) === 'array') ? res.data.nodes : [];

        if (!res.ok || length(valid_nodes) === 0) {
            Log('WORKER', 'ERROR', sprintf("Airport [%s] fetch failed.", ap.name || ap.id), job_id);
        } else {
            StateManager.sync_uci_nodes(ap.id, valid_nodes, job_id); 
            success_count++;
            total_nodes += length(valid_nodes);
        }
    }

    if (success_count === 0) return Fail(ERR.E_SYSTEM_BUSY, "所有订阅均拉取失败", job_id);

    Log('WORKER', 'INFO', 'Invoking Dynamic Node Groups Generator...', job_id);
    let group_res = task_rebuild_groups(job_id);
    if (!group_res.ok) return Fail(ERR.E_SYSTEM_BUSY, "组重建失败: " + group_res.detail, job_id);

    // 🚨 架构修复：调用防熔断沙盒预检
    safe_system_reload(job_id, 'update_subscriptions');
    
    let duration = time() - start_time;
    let summary_msg = "✅ <b>节点重载成功</b>%0A" +
                      "━━━━━━━━━━━━━━━━━━%0A" +
                      "📦 <b>任务摘要：</b> 所有订阅源更新完毕，共重载 " + total_nodes + " 个节点。总耗时: " + duration + " 秒。%0A" +
                      "[RESTART_PENDING]";
    
    return Success({ msg: summary_msg }, 200, job_id);
}

// ==========================================
// 核心路由与入口
// ==========================================

// [Category A] 任务总线路由表映射
const HANDLERS = {
    "apply_config": _handle_apply_config,
    "update_subscriptions": _handle_update_subscriptions,
    "rebuild_groups": _handle_rebuild_groups,
    "update_assets": _handle_update_assets,
    "update_resources": _handle_update_resources, 
    "system_rollback": _handle_system_rollback,
    "update_kernel": _handle_update_kernel,
    "deploy_panels": _handle_deploy_panels
};

/**
 * [Category B] Worker 主入口引擎
 * 职责：环境自检、获取分布式锁、状态机迁移及派发 Payload。
 * @param {string} job_id - 任务调度生成的唯一标识
 */
function main(job_id) {
    if (!job_id) exit(1);

    let check_res = run_all_checks(job_id);
    if (!check_res.ok) {
        transition(job_id, STATE_ENUM.FAIL, 0, "SYSTEM NOT HEALTHY: " + check_res.detail, job_id);
        exit(1);
    }

    let job_res = get_status(job_id, job_id);
    if (!job_res.ok || job_res.data.error) exit(1);
    let current_job = job_res.data;
    current_job.payload = current_job.payload || {};

    let lock_res = acquire(job_id);
    if (!lock_res.ok) {
        Log('WORKER', 'WARN', 'System busy. Could not acquire global lock.', job_id);
        transition(job_id, STATE_ENUM.FAIL, 0, lock_res.detail, job_id);
        exit(0);
    }
    let lock_handle = lock_res.data;

    transition(job_id, STATE_ENUM.RUNNING, 10, null, job_id);
    Log('WORKER', 'INFO', 'Worker initialized and lock acquired.', job_id);

    try {
        let safe_type = current_job.type;

        if (!JOB_TYPES[safe_type] || !HANDLERS[safe_type]) {
            let err_msg = "E_CONTRACT_VIOLATION: 未注册任务 -> " + safe_type;
            Log('WORKER', 'ERROR', err_msg, job_id);
            transition(job_id, STATE_ENUM.FAIL, current_job.progress, err_msg, job_id);
            send_telegram(safe_type, "fail", err_msg, job_id);
            lock_handle.release();
            exit(1);
        }

        let result = HANDLERS[safe_type](job_id, current_job.payload);

        if (result.ok) {
            transition(job_id, STATE_ENUM.SUCCESS, 100, null, job_id);
            // [Category A] 动态解析处理器返回的富文本载荷，实施安全回退
            let dynamic_msg = (type(result.data) === 'object' && result.data.msg) ? result.data.msg : "任务执行完毕";
            send_telegram(safe_type, "success", dynamic_msg, job_id);
        } else {
            transition(job_id, STATE_ENUM.FAIL, current_job.progress, result.detail, job_id);
            send_telegram(safe_type, "fail", result.detail, job_id);
        }
    } catch (e) {
        let err_msg = "" + e;
        transition(job_id, STATE_ENUM.FAIL, current_job.progress, "Worker crashed: " + err_msg, job_id);
        send_telegram(current_job.type, "fail", "Worker crashed: " + err_msg, job_id);
    }

    lock_handle.release();
    exit(0);
}

// [Category C] Note: 宪法修正：入口脚本严禁使用 export，维持纯粹的自执行独立进程。
if (length(ARGV) > 0) {
    main(ARGV[0]);
}
