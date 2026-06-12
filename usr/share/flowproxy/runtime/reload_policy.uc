/**
 * FlowProxy | runtime/reload_policy.uc
 * Role: decide whether a job should trigger runtime reload.
 */

'use strict';

import { job_allows_dataplane_reload } from 'flowproxy.core.contract';

function _business_job(job_type) {
    return job_type === 'update_subscriptions' ||
        job_type === 'update_assets' ||
        job_type === 'update_resources' ||
        job_type === 'rebuild_groups';
}

function _truthy_auto_apply(v) {
    return v === true || v === 1 || v === "1" || v === "true" || v === "yes";
}

function _falsey_auto_apply(v) {
    return v === false || v === 0 || v === "0" || v === "false" || v === "no";
}

function is_manual_business_task(job_type, payload) {
    if (!_business_job(job_type)) return false;
    payload = payload || {};
    let source = sprintf("%s", payload.source || "");
    return source === "manual" || _falsey_auto_apply(payload.auto_apply);
}

function is_cron_auto_apply(job_type, payload) {
    if (!_business_job(job_type)) return false;
    payload = payload || {};
    let source = sprintf("%s", payload.source || "");
    return source === "cron" && _truthy_auto_apply(payload.auto_apply);
}

function mark_manual_apply_required(result) {
    result.data = (type(result.data) === 'object') ? result.data : {};
    result.data.business_success = true;
    result.data.manual_apply_required = true;
    result.data.runtime_applied = false;
    result.data.next_action = "manual_apply_required";
    result.data.config_committed = false;
    result.data.dataplane_touched = false;
    result.data.restart_only = false;
    result.data.rollback_success = false;
    if (result.data.msg) {
        result.data.msg += "%0ABusiness data updated; runtime apply is pending.%0Anext_action=manual_apply_required";
    } else {
        result.data.msg = "Business data updated; runtime apply is pending.%0Anext_action=manual_apply_required";
    }
    return result;
}

function needs_reload(job_type, result, payload) {
    if (!job_allows_dataplane_reload(job_type)) return false;
    if (!result || !result.ok) return false;
    let data = result.data;

    if (type(data) === 'object' && data.next_action === "manual_apply_required") return false;
    if (type(data) === 'object' && data.restart_only_handled) return false;

    if (_business_job(job_type) && !is_cron_auto_apply(job_type, payload)) return false;

    if (job_type === 'apply_config' || job_type === 'update_subscriptions' || job_type === 'rebuild_groups') {
        return true;
    }
    if (type(data) === 'object' && data.changed) return true;
    return false;
}

export {
    is_manual_business_task,
    is_cron_auto_apply,
    mark_manual_apply_required,
    needs_reload
};
