/**
 * FlowProxy | modules/notifier.uc
 * Role: send worker/runtime supplied notification facts. This module does not
 * judge runtime health, poll processes, or change job outcomes.
 */

'use strict';

import { cursor } from 'uci';

import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { log } from 'flowproxy.core.logger';
import { fetch_with_policy } from 'flowproxy.core.resource_fetch';

const TELEGRAM_MAX_TEXT = 3900;

function _plain_text(s) {
    s = sprintf("%s", s || "");
    s = replace(s, regexp('<br\\s*/?>', 'g'), "\n");
    s = replace(s, regexp('<BR\\s*/?>', 'g'), "\n");
    s = replace(s, regexp('%0A', 'g'), "\n");
    s = replace(s, regexp('<[^>]+>', 'g'), "");
    return s;
}

function _truncate_text(s) {
    if (length(s) <= TELEGRAM_MAX_TEXT) return s;
    return substr(s, 0, TELEGRAM_MAX_TEXT - 80) + "\n...[message truncated]";
}

function _title(task_type, status, loc_name) {
    let task = "任务通知";
    if (task_type === "update_subscriptions") task = "📡 订阅管理";
    else if (task_type === "update_assets") task = "📊 规则集管理";
    else if (task_type === "update_resources") task = "🧩 资源管理";
    else if (task_type === "apply_config") task = "⚙️ 配置应用";
    else if (task_type === "watchdog_report") task = "🩺 健康监控";
    else if (task_type === "maintenance_logrotate") task = "🧹 日志维护";
    else if (task_type === "rebuild_groups") task = "🧱 节点组管理";
    else if (task_type === "system_rollback") task = "🛟 系统回滚";
    else if (task_type === "repair_current_mode") task = "🛠️ 网络修复";
    else if (task_type === "update_kernel") task = "🚀 内核管理";
    else if (task_type === "mode_switch_apply") task = "🔀 模式切换";
    return sprintf("[%s] %s", loc_name || "FlowProxy", task);
}

function _http_success(code) {
    let c = int(trim(code || ""));
    return c >= 200 && c < 300;
}

function _safe_body(body) {
    let s = sprintf("%s", body || "");
    s = replace(s, "\n", " ");
    s = replace(s, "\r", " ");
    s = replace(s, regexp('/bot[0-9]+:[A-Za-z0-9_-]+', 'g'), '/bot<redacted>');
    if (length(s) > 240) s = substr(s, 0, 240) + "...";
    return s || "(empty)";
}

function send_telegram(task_type, status, msg_text, trace_id) {
    try {
        let u = cursor();
        u.load("flowproxy");

        let enabled = u.get("flowproxy", "config", "tg_notify_enabled");
        let mode = u.get("flowproxy", "config", "tg_notify_mode");
        let token = trim(u.get("flowproxy", "config", "tg_token") || "");
        let chat_id = trim(u.get("flowproxy", "config", "tg_chat_id") || "");
        let loc_name = trim(u.get("flowproxy", "config", "location_name") || "FlowProxy");
        let token_had_bot_prefix = index(token, "bot") === 0;
        if (token_had_bot_prefix) token = substr(token, 3);

        if (enabled !== '1' || !token || !chat_id) {
            return Success({ sent: false, reason: "disabled or missing credentials" }, 200, trace_id);
        }

        if (status === "success" && mode === "fail_only") {
            return Success({ sent: false, reason: "fail_only mode active" }, 200, trace_id);
        }

        let final_text = _truncate_text(_title(task_type, status, loc_name) + "\n" + _plain_text(msg_text));
        let token_present = length(token) > 0;
        let chat_id_present = length(chat_id) > 0;
        let parse_mode_sent = "none";
        log(trace_id, 'INFO', 'NOTIFIER', sprintf(
            'Dispatching Telegram notification telegram_fields=chat_id,text,disable_web_page_preview parse_mode_sent=%s token_present=%s token_had_bot_prefix=%s chat_id_present=%s chat_id_len=%d text_len=%d payload=plain-urlencoded',
            parse_mode_sent,
            token_present ? "true" : "false",
            token_had_bot_prefix ? "true" : "false",
            chat_id_present ? "true" : "false",
            length(chat_id),
            length(final_text)
        ));

        let api_url = sprintf("https://api.telegram.org/bot%s/sendMessage", token);
        let res = fetch_with_policy(api_url, null, "notifier_api", trace_id, {
            timeout_sec: 15,
            method: "POST",
            insecure: true,
            fail_on_http: false,
            extra_args: [
                "--data-urlencode", "chat_id=" + chat_id,
                "--data-urlencode", "text=" + final_text,
                "--data-urlencode", "disable_web_page_preview=true"
            ],
            form_data: []
        });

        if (res.ok && _http_success(res.http_code)) {
            return Success({ sent: true }, 200, trace_id);
        }

        log(trace_id, 'WARN', 'NOTIFIER', sprintf(
            'Failed to send notification: effective=%s exit=%d http=%s telegram_body=%s telegram_fields=chat_id,text,disable_web_page_preview token_present=%s token_had_bot_prefix=%s chat_id_present=%s chat_id_len=%d text_len=%d parse_mode_sent=%s payload=plain-urlencoded stderr=%s',
            res.effective_mode || res.effective || "none",
            res.exit_code || 0,
            res.http_code || "000",
            _safe_body(res.response_body || res.stdout || ""),
            token_present ? "true" : "false",
            token_had_bot_prefix ? "true" : "false",
            chat_id_present ? "true" : "false",
            length(chat_id),
            length(final_text),
            parse_mode_sent,
            res.stderr || res.error || ""
        ));
        return Fail(ERR.E_SYSTEM_BUSY, "Telegram API request failed", trace_id);

    } catch (e) {
        let err_msg = "" + e;
        log(trace_id, 'CRIT', 'NOTIFIER', 'Exception: ' + err_msg);
        return Fail(ERR.E_SYSTEM_BUSY, "Notifier exception: " + err_msg, trace_id);
    }
}

function send_telegram_best_effort(task_type, status, msg, trace_id, log_module) {
    let log_tag = log_module || 'NOTIFIER';
    try {
        let tg_res = send_telegram(task_type, status, msg, trace_id);
        if (!tg_res || !tg_res.ok) {
            log(trace_id, 'WARN', log_tag, 'Telegram notify failed; job result is unchanged.');
        }
        return tg_res;
    } catch (e) {
        log(trace_id, 'WARN', log_tag, 'Telegram notify crashed; job result is unchanged: ' + ("" + e));
        return null;
    }
}

function _limit_list(items, max_items) {
    items = (type(items) === 'array') ? items : [];
    max_items = max_items || 12;
    let out = [];
    for (let i = 0; i < length(items) && i < max_items; i++) {
        push(out, sprintf("%s", items[i]));
    }
    if (length(items) > max_items) push(out, sprintf("...and %d more", length(items) - max_items));
    return out;
}

function _divider() {
    return "━━━━━━━━━━━━━━━━━━";
}

function _restart_status(data) {
    data = (type(data) === 'object') ? data : {};
    if (data.next_action === "manual_apply_required") return "待手动应用";
    if (data.runtime_applied === true) return "成功";
    if (data.changed === false) return "无需重启";
    if (data.restart_only === true || data.restart_only_handled === true) return "成功";
    if (data.rollback_success === true) return "失败，已回滚";
    return "未执行";
}

function _failure_stage_label(data) {
    data = (type(data) === 'object') ? data : {};
    return data.failed_stage || data.error_stage || "";
}

function _status_line(ok_text, warn_text, fail_text, status, has_fail) {
    if (status === "fail") return "❌ " + fail_text;
    if (has_fail) return "⚠️ " + warn_text;
    return "✅ " + ok_text;
}

function _append_bullet_list(msg, label, items, suffix, max_items) {
    items = _limit_list(items, max_items || 12);
    if (length(items) === 0) return msg;
    msg += "\n" + label + ":";
    for (let i = 0; i < length(items); i++) msg += "\n🔹 " + items[i] + (suffix || "");
    return msg;
}

function _append_failed_list(msg, label, items, suffix, max_items) {
    items = _limit_list(items, max_items || 12);
    if (length(items) === 0) return msg;
    msg += "\n" + label + ":";
    for (let i = 0; i < length(items); i++) msg += "\n🔸 " + items[i] + (suffix || "");
    return msg;
}

function _format_subscription_summary(status, data) {
    let failed_airports = (type(data.failed_airports) === 'array') ? data.failed_airports : [];
    let airport_stats = (type(data.airport_stats) === 'array') ? data.airport_stats : [];
    let failed_stage = _failure_stage_label(data);
    let has_warn = length(failed_airports) > 0 || data.dataplane_success === false || failed_stage;
    let msg = _status_line("订阅全局更新成功", "订阅部分更新成功", "订阅更新失败", status, has_warn);
    msg += "\n" + _divider();
    msg += sprintf("\n⏳ 总耗时: %d 秒 | 总节点: %d", data.duration_sec || data.duration || 0, data.total_nodes || 0);

    if (length(airport_stats) > 0) {
        msg += "\n\n📝 更新清单:";
        let max_items = 20;
        for (let i = 0; i < length(airport_stats) && i < max_items; i++) {
            let ap = airport_stats[i] || {};
            msg += sprintf("\n🔹 %s: %d 节点", ap.name || "未命名订阅", ap.nodes || 0);
        }
        if (length(airport_stats) > max_items) {
            msg += sprintf("\n🔹 ...另有 %d 个订阅已折叠", length(airport_stats) - max_items);
        }
    }

    msg = _append_failed_list(msg + (length(failed_airports) > 0 ? "\n" : ""), "❌ 失败订阅", failed_airports, "", 20);
    if (failed_stage) msg += "\n\n📍 失败阶段: " + failed_stage;
    if (data.detail) msg += "\n🧾 错误详情: " + data.detail;
    msg += sprintf("\n\n♻️ 服务自动重启: %s", _restart_status(data));
    if (data.runtime_applied === true) {
        msg += "\n🛡️ 运行说明: 内存树已重新映射，服务平稳过渡";
    } else if (data.next_action === "manual_apply_required") {
        msg += "\n🛡️ 运行说明: 配置已更新，等待手动应用后生效";
    }
    return msg;
}

function _format_list_update_summary(title_ok, title_warn, title_fail, status, data, item_label) {
    let updated = (type(data.updated) === 'array') ? data.updated : [];
    let failed = (type(data.failed) === 'array') ? data.failed : [];
    let unchanged = (type(data.unchanged) === 'array') ? data.unchanged : [];
    let msg = _status_line(
        length(updated) > 0 ? title_ok : item_label + "已是最新",
        title_warn,
        title_fail,
        status,
        length(failed) > 0
    );
    msg += "\n" + _divider();
    msg += sprintf("\n📦 更新数量: %d", length(updated));
    if (length(failed) > 0) msg += sprintf("\n❌ 失败数量: %d", length(failed));
    if (length(unchanged) > 0) msg += sprintf("\n🟦 未变化数量: %d", length(unchanged));

    msg = _append_bullet_list(msg + (length(updated) > 0 ? "\n" : ""), "📝 更新清单", updated, " (更新)", 20);
    msg = _append_failed_list(msg + (length(failed) > 0 ? "\n" : ""), "❌ 失败清单", failed, " (失败)", 20);

    let failed_stage = _failure_stage_label(data);
    if (failed_stage) msg += "\n\n📍 失败阶段: " + failed_stage;
    if (status === "fail" && data.detail) msg += "\n🧾 错误详情: " + data.detail;
    msg += sprintf("\n\n♻️ 服务自动重启: %s", _restart_status(data));
    return msg;
}

function _format_apply_summary(status, data, fallback_msg) {
    let msg = status === "fail" ? "❌ 配置应用失败" : "✅ 配置应用成功";
    msg += "\n" + _divider();
    if (status === "fail") {
        let failed_stage = _failure_stage_label(data);
        if (failed_stage) msg += "\n📍 失败阶段: " + failed_stage;
        msg += "\n🧾 错误详情: " + (fallback_msg || data.detail || "未知错误");
        msg += sprintf("\n\n🛟 回滚状态: %s", data.rollback_success ? "成功" : "未完成");
        return msg;
    }
    msg += sprintf("\n♻️ 服务重载: %s", data.runtime_applied === false ? "未执行" : "成功");
    if (data.old_mode || data.new_mode) msg += sprintf("\n🔀 模式切换: %s → %s", data.old_mode || "unknown", data.new_mode || "unknown");
    msg += "\n🛡️ 运行说明: 新配置已生效，服务平稳过渡";
    return msg;
}

function _format_watchdog_summary(status, data) {
    let healthy = data.healthy !== false && status !== "fail";
    let msg = healthy ? "✅ 服务已恢复" : "❌ 服务异常";
    let drift = (type(data.drift) === 'array') ? data.drift : [];
    msg += "\n" + _divider();
    if (length(drift) > 0) {
        msg += "\n📍 异常项目:";
        for (let i = 0; i < length(drift); i++) msg += "\n🔸 " + drift[i];
    }
    msg += sprintf("\n📊 连续失败: %d 次", data.fail_count || 0);
    if (!healthy) msg += "\n🛠️ 建议操作: 请执行“应用配置”进行恢复";
    return msg;
}

function _format_maintenance_summary(status, data) {
    let cleanup_msg = status === "fail" ? "❌ 日志清理失败" : "✅ 日志清理完成";
    cleanup_msg += "\n" + _divider();
    cleanup_msg += "\n📝 维护内容: 运行日志截断与过期文件清理";
    cleanup_msg += "\n🛡️ 运行说明: 不影响当前代理服务";
    return cleanup_msg;
}

function notification_summary(task_type, status, data, fallback_msg) {
    data = (type(data) === 'object') ? data : {};
    let updated = (type(data.updated) === 'array') ? data.updated : [];
    let failed = (type(data.failed) === 'array') ? data.failed : [];
    let unchanged = (type(data.unchanged) === 'array') ? data.unchanged : [];
    let msg = "";

    if (task_type === "update_subscriptions") {
        return _format_subscription_summary(status, data);
    }

    if (task_type === "update_assets") {
        return _format_list_update_summary("规则集更新完成", "规则集部分更新失败", "规则集更新失败", status, data, "规则集");
    }

    if (task_type === "update_resources") {
        if (length(updated) > 0 || length(failed) > 0 || length(unchanged) > 0) {
            return _format_list_update_summary("资源更新完成", "资源部分更新失败", "资源更新失败", status, data, "资源");
        }
        msg = status === "fail" ? "❌ 资源更新失败" : (data.changed ? "✅ 资源更新成功" : "✅ 资源已是最新");
        msg += "\n" + _divider();
        if (data.version) msg += "\n🏷️ 当前版本: " + data.version;
        msg += sprintf("\n♻️ 服务自动重启: %s", _restart_status(data));
        return msg;
    }

    if (task_type === "apply_config" || task_type === "mode_switch_apply") return _format_apply_summary(status, data, fallback_msg);
    if (task_type === "watchdog_report") return _format_watchdog_summary(status, data);
    if (task_type === "maintenance_logrotate") return _format_maintenance_summary(status, data);
    if (task_type === "rebuild_groups") {
        msg = status === "fail" ? "❌ 节点组重建失败" : "✅ 节点组重建完成";
        msg += "\n" + _divider();
        msg += "\n📝 处理结果: 已根据当前订阅节点重新生成分组";
        msg += sprintf("\n♻️ 服务自动重启: %s", _restart_status(data));
        return msg;
    }
    if (task_type === "system_rollback") {
        msg = status === "fail" ? "❌ 回滚失败" : "✅ 回滚完成";
        msg += "\n" + _divider();
        if (data.restored != null) msg += sprintf("\n📦 恢复资源数量: %d", data.restored || 0);
        msg += sprintf("\n♻️ 服务自动重启: %s", _restart_status(data));
        msg += "\n🛡️ 运行说明: 已尝试恢复到上一个可用状态";
        return msg;
    }

    if (data.next_action === "manual_apply_required") {
        msg = "✅ 业务数据更新完成";
        msg += "\n" + _divider();
        msg += "\n♻️ 服务自动重启: 待手动应用";
        msg += "\n🛡️ 运行说明: 当前运行服务尚未变更";
        return msg;
    }

    msg = status === "fail" ? "❌ 任务执行失败" : "✅ 任务执行完成";
    msg += "\n" + _divider();
    if (fallback_msg) msg += "\n🧾 详情: " + fallback_msg;
    return msg;
}

export { send_telegram, send_telegram_best_effort, notification_summary };
