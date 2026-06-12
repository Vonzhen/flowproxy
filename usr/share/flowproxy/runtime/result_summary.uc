/**
 * FlowProxy | runtime/result_summary.uc
 * Role: build and persist compact Job result summaries.
 */

'use strict';

import { set_result_summary } from 'flowproxy.core.job';
import { log } from 'flowproxy.core.logger';

const RESULT_SUMMARY_LIST_LIMIT = 20;

function _as_array(v) {
    return (type(v) === 'array') ? v : [];
}

function _copy_summary_flag(summary, data, key) {
    if (type(data) === 'object' && data[key] != null) {
        summary[key] = data[key];
    }
}

function _limit_string_list(items) {
    items = _as_array(items);
    let out = [];
    for (let i = 0; i < length(items) && i < RESULT_SUMMARY_LIST_LIMIT; i++) {
        push(out, sprintf("%s", items[i]));
    }
    return out;
}

function _limit_airport_stats(items) {
    items = _as_array(items);
    let out = [];
    for (let i = 0; i < length(items) && i < RESULT_SUMMARY_LIST_LIMIT; i++) {
        let item = items[i] || {};
        push(out, {
            name: sprintf("%s", item.name || "unknown"),
            nodes: int(item.nodes || 0)
        });
    }
    return out;
}

function build_result_summary(job_type, state, data, detail) {
    data = (type(data) === 'object') ? data : {};
    let summary = {
        kind: job_type || "unknown",
        message: "",
        counts: {},
        items: {}
    };

    _copy_summary_flag(summary, data, "manual_apply_required");
    _copy_summary_flag(summary, data, "runtime_applied");
    _copy_summary_flag(summary, data, "dataplane_success");
    _copy_summary_flag(summary, data, "next_action");
    _copy_summary_flag(summary, data, "error_stage");
    _copy_summary_flag(summary, data, "failed_stage");
    _copy_summary_flag(summary, data, "config_committed");
    _copy_summary_flag(summary, data, "rollback_success");
    _copy_summary_flag(summary, data, "old_mode");
    _copy_summary_flag(summary, data, "new_mode");

    if (detail) summary.error_message = detail;
    else if (data.detail) summary.error_message = data.detail;

    if (job_type === "update_subscriptions") {
        let failed_airports = _as_array(data.failed_airports);
        let failed_count = data.failed_count != null ? int(data.failed_count) : length(failed_airports);
        summary.message = (state === "fail")
            ? "订阅更新失败"
            : (failed_count > 0 ? "订阅部分更新成功" : "订阅全局更新成功");
        summary.duration_sec = int(data.duration_sec || data.duration || 0);
        summary.counts.success = int(data.success_count || 0);
        summary.counts.failed = failed_count;
        summary.counts.total_nodes = int(data.total_nodes || 0);
        summary.counts.total = summary.counts.success + summary.counts.failed;
        summary.items.airport_stats = _limit_airport_stats(data.airport_stats);
        summary.items.failed = _limit_string_list(failed_airports);
        return summary;
    }

    if (job_type === "rebuild_groups") {
        summary.message = (state === "fail") ? "节点组重建失败" : "节点组重建完成";
        if (data.changed != null) summary.changed = !!data.changed;
        return summary;
    }

    if (job_type === "update_assets" || job_type === "update_resources") {
        let updated = _as_array(data.updated);
        let unchanged = _as_array(data.unchanged);
        let failed = _as_array(data.failed);
        let failed_count = length(failed);
        let label = job_type === "update_assets" ? "规则集" : "资源";
        summary.message = (state === "fail")
            ? label + "更新失败"
            : (failed_count > 0 ? label + "部分更新成功" : label + "更新完成");
        summary.counts.updated = length(updated);
        summary.counts.unchanged = length(unchanged);
        summary.counts.failed = failed_count;
        summary.counts.total = length(updated) + length(unchanged) + failed_count;
        summary.items.updated = _limit_string_list(updated);
        summary.items.unchanged = _limit_string_list(unchanged);
        summary.items.failed = _limit_string_list(failed);
        if (data.version) summary.version = data.version;
        if (data.changed != null) summary.changed = !!data.changed;
        return summary;
    }

    if (job_type === "apply_config" || job_type === "mode_switch_apply") {
        summary.message = (state === "fail") ? "配置应用失败" : "配置已应用";
        return summary;
    }

    summary.message = (state === "fail") ? "任务失败" : "任务完成";
    return summary;
}

function persist_result_summary(job_id, job_type, state, data, detail, log_module) {
    let summary = build_result_summary(job_type, state, data, detail);
    let res = set_result_summary(job_id, summary, job_id);
    if (!res || !res.ok) {
        log(job_id, 'WARN', log_module || 'RESULT_SUMMARY', 'result_summary persist failed: ' + ((res && res.detail) ? res.detail : "unknown"));
    }
    return res;
}

export { build_result_summary, persist_result_summary };
