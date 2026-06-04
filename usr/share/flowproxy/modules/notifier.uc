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
    let task = task_type || "task";
    if (task_type === "update_subscriptions") task = "subscription update";
    else if (task_type === "update_assets") task = "ruleset update";
    else if (task_type === "update_resources") task = "resource update";
    else if (task_type === "apply_config") task = "apply config";
    else if (task_type === "watchdog_report") task = "watchdog report";
    let status_label = status === "fail" ? "FAIL" : "OK";
    return sprintf("[%s] %s %s", loc_name || "FlowProxy", status_label, task);
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

function _append_list(msg, label, items) {
    items = _limit_list(items, 12);
    if (length(items) === 0) return msg;
    msg += "\n" + label + ":";
    for (let i = 0; i < length(items); i++) msg += "\n- " + items[i];
    return msg;
}

function notification_summary(task_type, status, data, fallback_msg) {
    data = (type(data) === 'object') ? data : {};
    let updated = (type(data.updated) === 'array') ? data.updated : [];
    let failed = (type(data.failed) === 'array') ? data.failed : [];
    let unchanged = (type(data.unchanged) === 'array') ? data.unchanged : [];
    let failed_airports = (type(data.failed_airports) === 'array') ? data.failed_airports : [];
    let msg = "";

    if (data.next_action === "manual_apply_required") {
        return "Manual update completed\nruntime_applied=false\nnext_action=manual_apply_required";
    }

    if (task_type === "update_subscriptions") {
        msg = "Task: cron subscription update";
        msg += sprintf("\nsubscription_success=%s", data.subscription_success === false ? "false" : "true");
        msg += sprintf("\nsuccess_count=%d", data.success_count || 0);
        msg += sprintf("\nfailed_count=%d", data.failed_count || length(failed_airports));
        msg += sprintf("\ntotal_nodes=%d", data.total_nodes || 0);
        msg += sprintf("\nruntime_applied=%s", data.runtime_applied ? "true" : "false");
        msg += sprintf("\nrestart_only=%s", data.restart_only ? "true" : "false");
        msg += sprintf("\nrollback_success=%s", data.rollback_success ? "true" : "false");
        if (data.error_stage) msg += "\nerror_stage=" + data.error_stage;
        msg = _append_list(msg, "failed", failed_airports);
        return msg;
    }

    if (task_type === "update_assets") {
        msg = "Task: cron ruleset update";
        msg += sprintf("\nupdated_count=%d", length(updated));
        msg += sprintf("\nfailed_count=%d", length(failed));
        msg += sprintf("\nunchanged_count=%d", length(unchanged));
        msg += sprintf("\nruntime_applied=%s", data.runtime_applied ? "true" : "false");
        msg += sprintf("\nrollback_success=%s", data.rollback_success ? "true" : "false");
        if (data.error_stage) msg += "\nerror_stage=" + data.error_stage;
        msg = _append_list(msg, "updated", updated);
        msg = _append_list(msg, "failed", failed);
        return msg;
    }

    if (task_type === "update_resources") {
        msg = "Task: cron resource update";
        msg += sprintf("\nupdated_count=%d", length(updated));
        msg += sprintf("\nfailed_count=%d", length(failed));
        msg += sprintf("\nunchanged_count=%d", length(unchanged));
        msg += sprintf("\nruntime_applied=%s", data.runtime_applied ? "true" : "false");
        msg += sprintf("\nrollback_success=%s", data.rollback_success ? "true" : "false");
        if (data.error_stage) msg += "\nerror_stage=" + data.error_stage;
        msg = _append_list(msg, "updated", updated);
        msg = _append_list(msg, "failed", failed);
        return msg;
    }

    return fallback_msg || "Task completed";
}

export { send_telegram, send_telegram_best_effort, notification_summary };
