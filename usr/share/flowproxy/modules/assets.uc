/**
 * FlowProxy | modules/assets.uc | v1.3 (Local File & Auto-Inject Edition)
 * 职责：负责全局规则集、静态资产的更新、按需下载、动态 UCI 注册与紧急回滚。
 * 架构重构：
 * 1. 彻底支持 Local (本地二进制) 模式的全量更新。
 * 2. 引入批量入库引擎 (Download)，自动生成 URL 并回写 UCI 配置。
 * 3. 严格遵循正则沙箱契约，清理所有字面量正则。
 */

'use strict';

// 1. [解构原生库]
import { stat, unlink, readfile, writefile } from 'fs';
import { cursor } from 'uci';

// 2. [引入基石法则]
import { PATH, BIN } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { ExecSafe, shell_escape } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';

const UCICONFIG = 'flowproxy';
const RULE_DIR = PATH.RULESET;
const TMP_DIR = sprintf("%s/assets_tmp", PATH.RUNTIME); 
const LOCAL_PROXY = "socks5h://127.0.0.1:5330"; 

function _ensure_dirs(trace_id) {
    let dirs = [RULE_DIR, TMP_DIR];
    for (let i = 0; i < length(dirs); i++) {
        if (!stat(dirs[i])) ExecSafe(BIN.MKDIR, ["-p", dirs[i]], null, trace_id);
    }
}

function _get_file_md5(file_path, trace_id) {
    let s = stat(file_path);
    if (!s || s.size === 0) return null;
    let safe_path = shell_escape(file_path);
    let res = ExecSafe(BIN.SH, ["-c", "md5sum " + safe_path], null, trace_id);
    if (res.ok && res.data && res.data.stdout) {
        return trim(split(res.data.stdout, ' ')[0]);
    }
    return null;
}

/**
 * 带有 HTTP 状态熔断与物理体积校验的下载探针
 */
function _fetch_with_retry(url, dest_path, timeout_sec, trace_id) {
    let t = "" + (timeout_sec || 15);
    
    log(trace_id, 'INFO', 'ASSETS', '尝试直连下载: ' + url);
    // [Category A] 注入 -f (--fail) 参数，强制 HTTP >= 400 时返回非零退出码 (22)
    let res = ExecSafe(BIN.CURL, ["-sSLf", "--connect-timeout", t, "-o", dest_path, url], null, trace_id);
    
    // [Category B] 职能：验证物理落盘状态，引入 50 Bytes 最小体积阈值，防御 CDN 返回 200 OK 的错误提示页
    let f_stat = stat(dest_path);
    if (res.ok && f_stat && f_stat.size > 50) {
        return true;
    }

    log(trace_id, 'WARN', 'ASSETS', '直连失败或文件损坏，尝试通过代理下载...');
    // [Category A] 代理通道同步应用严格校验
    res = ExecSafe(BIN.CURL, ["-sSLf", "--connect-timeout", t, "-x", LOCAL_PROXY, "-o", dest_path, url], null, trace_id);
    
    f_stat = stat(dest_path);
    if (res.ok && f_stat && f_stat.size > 50) {
        return true;
    }

    // [Category C] Warning: 发生致命错误或被体积探针拦截。必须清理残骸，防止污染下一次全量巡检的 MD5 比对。
    if (f_stat) {
        unlink(dest_path);
    }
    
    return false;
}

/**
 * 🛡️ 核心防线：原子替换并建立物理快照 (.bak)
 */
function _atomic_swap_with_bak(tmp_path, final_path, trace_id) {
    let stage_path = final_path + ".stage";
    let bak_path = final_path + ".bak";

    if (stat(final_path)) {
        ExecSafe(BIN.MV, ["-f", final_path, bak_path], null, trace_id);
    }

    let cp_res = ExecSafe(BIN.CP, ["-f", tmp_path, stage_path], null, trace_id);
    unlink(tmp_path);
    if (!cp_res.ok) return false;
    
    let mv_res = ExecSafe(BIN.MV, ["-f", stage_path, final_path], null, trace_id);
    return mv_res.ok;
}

/**
 * 🛡️ 容灾核心：物理回滚引擎
 */
function _restore_assets_backup(trace_id) {
    let targets = [RULE_DIR];
    let restored = 0;
    
    for (let i = 0; i < length(targets); i++) {
        let dir = targets[i];
        let safe_dir = shell_escape(dir);
        let find_cmd = sprintf("find %s -type f -name '*.bak'", safe_dir);
        let res = ExecSafe(BIN.SH, ["-c", find_cmd], null, trace_id);
        
        if (res.ok && res.data && res.data.stdout) {
            let files = split(trim(res.data.stdout), "\n");
            for (let f_idx = 0; f_idx < length(files); f_idx++) {
                let bak_file = files[f_idx];
                if (!bak_file) continue;
                // 安全字符串替换去后缀
                let orig_file = replace(bak_file, regexp('\\.bak$'), "");
                if (ExecSafe(BIN.MV, ["-f", bak_file, orig_file], null, trace_id).ok) {
                    restored++;
                }
            }
        }
    }
    return restored;
}

/**
 * 🌟 核心引擎 1：动态 UCI 注册挂载点
 */
function _auto_inject_uci(name, file_path, trace_id) {
    let uctx = cursor();
    uctx.load(UCICONFIG);
    
    let exists = false;
    uctx.foreach(UCICONFIG, 'ruleset', (s) => {
        if (s.path === file_path) exists = true;
    });

    if (exists) {
        log(trace_id, 'INFO', 'ASSETS', sprintf("规则集 [%s] 已在 UCI 中，跳过注册。", name));
        return;
    }

    log(trace_id, 'INFO', 'ASSETS', sprintf("正在为 [%s] 动态注册 UCI 节点...", name));
    
    // 🚨 命名格式重构：直接删除所有非字母、非数字的字符，且不加前缀
    let sec_id = replace(name, regexp('[^a-zA-Z0-9]', 'g'), '');
    
    uctx.delete(UCICONFIG, sec_id);
    uctx.set(UCICONFIG, sec_id, "ruleset");
    uctx.set(UCICONFIG, sec_id, "label", name);
    uctx.set(UCICONFIG, sec_id, "enabled", "1");
    uctx.set(UCICONFIG, sec_id, "type", "local");
    uctx.set(UCICONFIG, sec_id, "format", "binary");
    uctx.set(UCICONFIG, sec_id, "path", file_path);
    
    uctx.commit(UCICONFIG);
    log(trace_id, 'INFO', 'ASSETS', sprintf("成功注册节点: %s", sec_id));
}

/**
 * URL 生成器：对齐原生 Shell 算法
 */
function _generate_urls(name, base_url, private_repo) {
    let urls = [];
    if (private_repo) {
        push(urls, sprintf("%s/%s.srs", private_repo, name));
    }
    let type = match(name, regexp('^geosite-')) ? 'geosite' : 'geoip';
    let core_name = replace(name, regexp('^(geosite-|geoip-)'), '');
    
    push(urls, sprintf("%s/geo/%s/%s.srs", base_url, type, core_name));
    push(urls, sprintf("%s/geo-lite/%s/%s.srs", base_url, type, core_name));
    return urls;
}

/**
 * 🌟 核心引擎 2：批量入库引擎 (响应前端 Action: download)
 */
function _download_manual(target_str, trace_id) {
    if (!target_str) return Fail(ERR.E_SYSTEM_BUSY, "未提供规则集名称", trace_id);
    
    let names = split(trim(target_str), regexp('\\s+'));
    let uctx = cursor();
    uctx.load(UCICONFIG);
    let base_url = uctx.get(UCICONFIG, 'assets', 'base_url') || 'https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing';
    let private_repo = uctx.get(UCICONFIG, 'assets', 'private_repo');

    // [Category A] 引入多维物理清单收集器
    let updated_items = [];
    let fail_items = [];
    
    for (let i = 0; i < length(names); i++) {
        let name = names[i];
        if (!name) continue;
        
        let final_path = sprintf("%s/%s.srs", RULE_DIR, name);
        let tmp_path = sprintf("%s/%s.srs.tmp", TMP_DIR, name);
        let urls = _generate_urls(name, base_url, private_repo);
        
        let dl_ok = false;
        for (let j = 0; j < length(urls); j++) {
            if (_fetch_with_retry(urls[j], tmp_path, 15, trace_id)) {
                dl_ok = true;
                break;
            }
        }
        
        if (dl_ok) {
            ExecSafe(BIN.MV, ["-f", tmp_path, final_path], null, trace_id);
            log(trace_id, 'INFO', 'ASSETS', '✅ 入库成功: ' + name);
            _auto_inject_uci(name, final_path, trace_id);
            push(updated_items, name);
        } else {
            log(trace_id, 'ERROR', 'ASSETS', '❌ 下载失败: ' + name);
            push(fail_items, name);
        }
    }
    
    // [Category B] 抛出富结构数据载荷
    return Success({ 
        reload_required: (length(updated_items) > 0), 
        updated: updated_items, 
        unchanged: [], 
        failed: fail_items 
    }, 200, trace_id);
}

/**
 * 🌟 核心引擎 3：全量巡检更新 (响应前端 Action: update)
 */
function _update_all_rulesets(trace_id) {
    let uctx = cursor();
    uctx.load(UCICONFIG);
    let base_url = uctx.get(UCICONFIG, 'assets', 'base_url') || 'https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing';
    let private_repo = uctx.get(UCICONFIG, 'assets', 'private_repo');

    let active_files = [];
    uctx.foreach(UCICONFIG, 'ruleset', (s) => {
        if (s.enabled === '1' && s.path && match(s.path, regexp('\\.srs$'))) {
            push(active_files, s.path);
        }
    });

    if (length(active_files) === 0) {
        log(trace_id, 'INFO', 'ASSETS', '未发现任何激活的 .srs 本地规则集。');
        return Success({ reload_required: false, updated: [], unchanged: [], failed: [] }, 200, trace_id);
    }

    let updated_items = [];
    let unchanged_items = [];
    let fail_items = [];

    for (let i = 0; i < length(active_files); i++) {
        let live_path = active_files[i];
        
        let fname_res = ExecSafe(BIN.SH, ["-c", sprintf("basename %s", shell_escape(live_path))], null, trace_id);
        if (!fname_res.ok || !fname_res.data || !fname_res.data.stdout) continue;
        
        let filename = trim(fname_res.data.stdout);
        let name = replace(filename, regexp('\\.srs$'), '');
        let tmp_file = sprintf("%s/%s", TMP_DIR, filename);

        let urls = _generate_urls(name, base_url, private_repo);
        let dl_ok = false;
        
        for (let j = 0; j < length(urls); j++) {
            if (_fetch_with_retry(urls[j], tmp_file, 15, trace_id)) {
                dl_ok = true;
                break;
            }
        }

        if (!dl_ok) {
            log(trace_id, 'ERROR', 'ASSETS', '巡检下载失败: ' + name);
            push(fail_items, name);
            continue;
        }

        let new_md5 = _get_file_md5(tmp_file, trace_id);
        let old_md5 = _get_file_md5(live_path, trace_id);

        if (new_md5 && new_md5 === old_md5) {
            push(unchanged_items, name);
            unlink(tmp_file);
        } else {
            if (_atomic_swap_with_bak(tmp_file, live_path, trace_id)) {
                push(updated_items, name);
            } else {
                push(fail_items, name);
            }
        }
    }

    log(trace_id, 'INFO', 'ASSETS', sprintf("全量巡检完成. 成功:%d 不变:%d 失败:%d", length(updated_items), length(unchanged_items), length(fail_items)));
    
    return Success({ 
        reload_required: (length(updated_items) > 0), 
        updated: updated_items, 
        unchanged: unchanged_items, 
        failed: fail_items 
    }, 200, trace_id);
}

/**
 * 🚨 [业务入口 1] 紧急安全回滚
 */
function task_rollback_assets(trace_id, payload) {
    log(trace_id, 'WARN', 'ASSETS', '🚨 收到紧急回退指令，正在启动时光机引擎...');
    try {
        let count = _restore_assets_backup(trace_id);
        if (count > 0) {
            log(trace_id, 'INFO', 'ASSETS', sprintf('成功物理恢复 %d 个资产文件。', count));
            return Success({ restored: count, reload_required: true }, 200, trace_id);
        }
        return Fail(ERR.E_SYSTEM_BUSY, "未发现可用的备份文件 (.bak)", trace_id);
    } catch (e) {
        let err_msg = "" + e;
        return Fail(ERR.E_SYSTEM_BUSY, "回滚过程发生致命错误: " + err_msg, trace_id);
    }
}

/**
 * 🚨 [业务入口 2] 资产更新分发路由
 */
function task_update_assets(trace_id, payload) {
    log(trace_id, 'INFO', 'ASSETS', 'Starting assets management execution...');

    try {
        _ensure_dirs(trace_id);
        let safe_payload = payload || {};
        let action = safe_payload.action || 'update';
        let target = safe_payload.target;
        log(trace_id, 'INFO', 'ASSETS', sprintf("Action: %s, Target: %s", action, target || "all"));

        if (action === 'download') {
            return _download_manual(target, trace_id);
        } 
        else if (action === 'update') {
            // 如果目标是 rulesets 或 manual，只走巡检逻辑
            return _update_all_rulesets(trace_id);
        }
        return Fail(ERR.E_SYSTEM_BUSY, "未知的动作指令", trace_id);
    } catch (e) {
        let err_msg = "" + e;
        log(trace_id, 'CRIT', 'ASSETS', 'Assets 引擎崩溃: ' + err_msg);
        return Fail(ERR.E_SYSTEM_BUSY, err_msg, trace_id);
    }
}

// 🚨 铁律 1
export { task_update_assets, task_rollback_assets };
