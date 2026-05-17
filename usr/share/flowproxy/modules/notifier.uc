/**
 * FlowProxy | modules/notifier.uc | v1.1 (Refactored)
 * 职责：业务模块层。负责截获任务结果并向 Telegram 下发带轮询容错的格式化告警。
 * 架构防线：引入 Initial Backoff 与 Linear Polling，免疫守护进程异步重启时的“进程空窗期”误报。
 */

'use strict';

// [Category A] 解构原生库与基石法则
import { cursor } from 'uci';
import { PATH, BIN } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { ExecSafe, shell_escape } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';

/**
 * 模块对外导出的主接口：下发 Telegram 告警
 * @param {string} trace_id - 贯穿始终的链路 ID
 * @param {string} task_type - 任务类型 (如 update_subscriptions)
 * @param {string} status - 任务状态 (success | fail)
 * @param {string} msg_text - 详细信息
 */
function send_telegram(task_type, status, msg_text, trace_id) {
    try {
        let u = cursor();
        u.load("flowproxy");
        
        let enabled = u.get("flowproxy", "config", "tg_notify_enabled");
        let mode = u.get("flowproxy", "config", "tg_notify_mode");
        let token = trim(u.get("flowproxy", "config", "tg_token") || "");
        let chat_id = trim(u.get("flowproxy", "config", "tg_chat_id") || "");
        // [Category B] 严格继承 loc_name，保障告警上下文的可追溯性
        let loc_name = trim(u.get("flowproxy", "config", "location_name") || "FlowProxy");

        if (enabled !== '1' || !token || !chat_id) {
            return Success({ sent: false, reason: "disabled or missing credentials" }, 200, trace_id);
        }

        if (status === "success" && mode === "fail_only") {
            return Success({ sent: false, reason: "fail_only mode active" }, 200, trace_id);
        }

        // [Category B] 格式化安全文本与转义
        let safe_msg = msg_text || "";
        // [Category C] Warning: 必须使用 regexp() 沙箱，严禁在此处使用 /.../g 导致进程抛出 Syntax Error
        safe_msg = replace(safe_msg, regexp('<br>', 'g'), "%0A");
        safe_msg = replace(safe_msg, regexp('\\n', 'g'), "%0A");

        let final_status = status;
        let is_sub_task = (task_type === "subscription" || task_type === "update_subscriptions");

        // ============================================================================
        // 探针轮询与富文本组装区 (Generalized Probe & Payload Structuring)
        // ============================================================================
        
        // [Category A] 幻影标记拦截：解耦任务类型，任何携带挂起标记的任务均触发健康巡检
        if (match(safe_msg, regexp('\\[RESTART_PENDING\\]'))) {
            let is_alive = false;
            let active_pid = "";
            
            log(trace_id, 'INFO', 'NOTIFIER', 'Detected [RESTART_PENDING] phantom marker. Entering backoff window (3s)...');
            system("sleep 3"); 

            log(trace_id, 'INFO', 'NOTIFIER', 'Starting generalized PID polling sequence...');
            for (let i = 0; i < 10; i++) {
                let pid_res = ExecSafe(BIN.PIDOF, ["sing-box"], null, trace_id);
                if (pid_res.ok && pid_res.data && length(trim(pid_res.data.stdout || "")) > 0) {
                    is_alive = true;
                    active_pid = trim(pid_res.data.stdout);
                    log(trace_id, 'INFO', 'NOTIFIER', sprintf('Captured active PID: %s at attempt %d', active_pid, i + 1));
                    break;
                }
                system("sleep 2"); 
            }

            // [Category B] 依据任务类型与探针终态，精准渲染对齐文本格式
            if (is_alive) {
                if (is_sub_task) {
                    let ok_tail = "⚡ <b>内核状态：</b> 运行中 (PID: " + active_pid + ")%0A🛡️ <b>运行说明：</b> 内存树已重新映射，服务平稳过渡。";
                    safe_msg = replace(safe_msg, regexp('\\[RESTART_PENDING\\]', 'g'), ok_tail);
                } else {
                    safe_msg = replace(safe_msg, regexp('\\[RESTART_PENDING\\]', 'g'), "♻️ <b>服务重启:</b> ✅ 成功 (PID: " + active_pid + ")");
                }
            } else {
                final_status = "fail";
                if (is_sub_task) {
                    let err_tail = "💥 <b>故障定性：内核冷启动失败</b> (Timeout: 23s)%0A🔍 <b>探针反馈：</b> 轮询窗口期内未探测到活跃进程。%0A🎯 <b>行动建议：</b> 请立刻登录 OpenWrt 检查底层堆栈。";
                    safe_msg = replace(safe_msg, regexp('\\[RESTART_PENDING\\]', 'g'), err_tail);
                } else {
                    safe_msg = replace(safe_msg, regexp('\\[RESTART_PENDING\\]', 'g'), "♻️ <b>服务重启:</b> ❌ 失败 (探针未捕获到进程，Timeout: 23s)");
                }
            }
        } 
        // 兜底异常拦截
        else if (status === "fail" && !match(safe_msg, regexp('服务重启'))) {
            safe_msg = "⚠️ <b>任务中断或异常</b>%0A━━━━━━━━━━━━━━━━━━%0A原因：" + safe_msg;
        }

        // ============================================================================
        // HTTP API 下发区
        // ============================================================================
        let title_prefix = "[" + loc_name + "]";
        if (is_sub_task) {
            title_prefix += " 📡 <b>订阅管理</b>";
        } else if (task_type === "ruleset" || task_type === "update_assets") {
            title_prefix += " 🗂️ <b>资产规则</b>";
        } else if (task_type === "kernel" || task_type === "update_kernel") {
            title_prefix += " 🚀 <b>内核管理</b>";
        } else if (task_type === "apply_config") {
            title_prefix += " ⚙️ <b>配置部署</b>";
        }

        let final_text = title_prefix + "%0A" + safe_msg;

        let api_url = sprintf("https://api.telegram.org/bot%s/sendMessage", token);
        let curl_args = [
            "-sk", 
            "-x", "socks5h://127.0.0.1:5330", // 🚨 核心装甲：强制让 Sing-box 代理 DNS 解析与 TCP 握手，无视运营商投毒！
            "-X", "POST", api_url,
            "-d", "chat_id=" + chat_id,
            "-d", "parse_mode=HTML",
            "-d", "disable_web_page_preview=true",
            "-d", "text=" + final_text
        ];

        log(trace_id, 'INFO', 'NOTIFIER', 'Dispatching formatted Telegram notification...');
        
        // 🚨 战术微调：由于通过代理走出国门，将超时时间从 10 秒稍微放宽到 15 秒，增加容错率
        let res = ExecSafe(BIN.CURL, curl_args, { timeout: 15 }, trace_id);

        if (res.ok) {
            return Success({ sent: true }, 200, trace_id);
        } else {
            log(trace_id, 'WARN', 'NOTIFIER', 'Failed to send notification: ' + res.detail);
            return Fail(ERR.E_SYSTEM_BUSY, "Telegram API request failed", trace_id);
        }

    } catch (e) {
        // 🚨 铁律 6：隐式异常捕获
        let err_msg = "" + e;
        log(trace_id, 'CRIT', 'NOTIFIER', 'Exception: ' + err_msg);
        return Fail(ERR.E_SYSTEM_BUSY, "Notifier exception: " + err_msg, trace_id);
    }
}

// 🚨 铁律 1: 文件末尾统一导出
export { send_telegram };
