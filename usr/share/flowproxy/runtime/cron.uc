/**
 * FlowProxy | runtime/cron.uc
 * Role: cron transaction policy and cron auto-apply orchestration.
 */

'use strict';

import { access, readfile } from 'fs';
import { cursor } from 'uci';

import { PATH } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Fail, Success } from 'flowproxy.core.result';
import { log } from 'flowproxy.core.logger';
import { safe_apply_config as apply_safe_apply_config } from 'flowproxy.runtime.apply';
import {
    backup_flowproxy_uci,
    restore_flowproxy_uci,
    rollback_run_json_if_needed,
    restart_process_rollback_if_needed
} from 'flowproxy.runtime.rollback';
import { task_rollback_assets } from 'flowproxy.modules.assets';

function Log(module, level, msg, trace_id) {
    log(trace_id, level, module || 'CRON', msg);
}

function _truthy(v) {
    return v === true || v === 1 || v === "1" || v === "true" || v === "yes";
}

function _cron_mode_switch_scope(payload) {
    payload = payload || {};
    let scope = sprintf("%s", payload.cron_mode_switch_scope || payload.mode_switch_scope || "");
    if (scope === "maintenance" || scope === "debug" || scope === "emergency" || scope === "internal") {
        return scope;
    }
    if (_truthy(payload.maintenance_mode_switch)) return "maintenance";
    return "";
}

function fill_cron_observation_fields(data, payload, failed, stage) {
    data = (type(data) === 'object') ? data : {};
    payload = payload || {};
    let requested = _truthy(payload.allow_cron_mode_switch);
    let scope = _cron_mode_switch_scope(payload);

    data.cron_auto_apply = true;
    data.cron_auto_apply_failed = !!failed;
    data.allow_cron_mode_switch = !!(requested && scope);
    data.allow_cron_mode_switch_requested = requested;
    data.cron_mode_switch_scope = scope;

    if (data.runtime_applied !== true) data.runtime_applied = false;
    if (data.cron_mode_switch === true || data.mode_switch_applied === true || data.apply_branch === "mode_switch") {
        data.restart_only = false;
    } else if (data.restart_only !== false) {
        data.restart_only = true;
    }
    data.restart_only_handled = true;
    if (data.dataplane_touched !== true) data.dataplane_touched = false;
    if (data.rollback_success !== true) data.rollback_success = false;
    data.error_stage = stage || data.error_stage || "";
    data.healthy = failed ? false : (data.healthy === false ? false : true);

    return data;
}

function _normalize_proxy_mode(mode) {
    mode = trim(sprintf("%s", mode || ""));
    if (mode === "redirect" || mode === "redirect_tproxy") return "redirect_tproxy";
    if (mode === "redirect_tun" || mode === "tun") return "tun";
    return mode;
}

function _read_uci_proxy_mode(trace_id, log_module) {
    try {
        let u = cursor();
        u.load("flowproxy");
        return _normalize_proxy_mode(u.get("flowproxy", "config", "proxy_mode") || u.get("flowproxy", "routing", "proxy_mode") || "redirect_tproxy");
    } catch (e) {
        Log(log_module, 'WARN', 'uci_proxy_mode_before_generate read failed: ' + e, trace_id);
        return "";
    }
}

function _detect_run_json_proxy_mode(trace_id, log_module) {
    if (!access(PATH.RUN_JSON)) return "";
    try {
        let cfg = json(readfile(PATH.RUN_JSON) || "{}");
        let inbounds = (cfg && type(cfg.inbounds) === 'array') ? cfg.inbounds : [];
        let has_redirect = false;
        for (let i = 0; i < length(inbounds); i++) {
            let t = inbounds[i] ? inbounds[i].type : "";
            if (t === "tun") return "tun";
            if (t === "redirect" || t === "tproxy") has_redirect = true;
        }
        if (has_redirect) return "redirect_tproxy";
    } catch (e) {
        Log(log_module, 'WARN', 'run.json mode detect failed: ' + e, trace_id);
    }
    return "";
}

function safe_cron_apply_config(trace_id, job_type, payload, dfa_cb, log_module) {
    payload = payload || {};
    let allow_mode_switch_requested = _truthy(payload.allow_cron_mode_switch);
    let maintenance_scope = _cron_mode_switch_scope(payload);
    let allow_mode_switch = allow_mode_switch_requested && maintenance_scope;
    let run_mode = _detect_run_json_proxy_mode(trace_id, log_module);
    let uci_proxy_mode = _read_uci_proxy_mode(trace_id, log_module);

    Log(log_module, 'INFO', sprintf(
        'cron apply_config guard job_type=%s run_mode=%s uci_proxy_mode=%s allow_cron_mode_switch=%s requested=%s scope=%s',
        job_type || "unknown",
        run_mode || "(unknown)",
        uci_proxy_mode || "(unknown)",
        allow_mode_switch ? "true" : "false",
        allow_mode_switch_requested ? "true" : "false",
        maintenance_scope || "(none)"
    ), trace_id);

    if (!allow_mode_switch && run_mode && uci_proxy_mode && run_mode !== uci_proxy_mode) {
        if (allow_mode_switch_requested && !maintenance_scope) {
            Log(log_module, 'WARN', 'cron mode switch request denied: maintenance scope missing', trace_id);
        }
        let res = Fail(ERR.E_SYSTEM_BUSY, sprintf(
            "cron_mode_switch_denied: run_mode=%s uci_proxy_mode=%s",
            run_mode,
            uci_proxy_mode
        ), trace_id);
        res.data = {
            cron_auto_apply: true,
            cron_auto_apply_failed: true,
            allow_cron_mode_switch: !!allow_mode_switch,
            allow_cron_mode_switch_requested: !!allow_mode_switch_requested,
            cron_mode_switch_scope: maintenance_scope || "",
            error_stage: "cron_mode_switch_denied",
            old_mode: run_mode,
            new_mode: uci_proxy_mode,
            config_committed: false,
            runtime_applied: false,
            dataplane_touched: false,
            rollback_success: false,
            healthy: false
        };
        return res;
    }

    let res = apply_safe_apply_config(trace_id, dfa_cb, log_module);
    if (res && type(res.data) === 'object') {
        res.data.cron_auto_apply = true;
        res.data.allow_cron_mode_switch = !!allow_mode_switch;
        res.data.allow_cron_mode_switch_requested = !!allow_mode_switch_requested;
        res.data.cron_mode_switch_scope = maintenance_scope || "";
        if (res.data.apply_branch === "mode_switch" || res.data.mode_switch_applied === true) {
            res.data.cron_mode_switch = true;
        } else {
            res.data.restart_only = true;
        }
    }
    return res;
}

function _reload_failure_stage(res) {
    let detail = (res && res.detail) ? res.detail : "";
    if (index(detail, "cron_mode_switch_denied") >= 0) return "cron_mode_switch_denied";
    if (index(detail, "candidate generation failed") >= 0) return "candidate_generation_failed";
    if (index(detail, "candidate check failed") >= 0) return "candidate_check_failed";
    if (index(detail, "commit candidate") >= 0 || index(detail, "Atomic") >= 0) return "commit_failed";
    if (index(detail, "process restart dispatch failed") >= 0) return "restart_process_failed";
    if (index(detail, "process restart verify failed") >= 0) return "restart_process_failed";
    if (index(detail, "core proxy verify failed") >= 0) return "core_verify_failed";
    return "auto_apply_failed";
}

function _restart_only_failure_stage(res) {
    return _reload_failure_stage(res);
}

function _cron_subscription_failure(trace_id, stage, detail, uci_bak_path, apply_res, subscription_success, payload, log_module) {
    Log(log_module, 'WARN', sprintf('cron update_subscriptions transaction failed stage=%s detail=%s', stage, detail || "unknown"), trace_id);

    let uci_rb = restore_flowproxy_uci(trace_id, uci_bak_path, log_module);
    let runjson_rb_ok = rollback_run_json_if_needed(trace_id, apply_res, "update_subscriptions", log_module);
    let restart_rb_ok = restart_process_rollback_if_needed(trace_id, apply_res, "", log_module);

    let rollback_success = !!(uci_rb && uci_rb.ok && runjson_rb_ok && restart_rb_ok);
    let sub_ok = subscription_success !== false;
    return Success(fill_cron_observation_fields({
        subscription_success: sub_ok,
        cron_auto_apply: true,
        cron_auto_apply_failed: true,
        runtime_applied: false,
        rollback_success: rollback_success,
        dataplane_touched: false,
        restart_only: true,
        restart_only_handled: true,
        healthy: false,
        error_stage: stage,
        detail: detail || "unknown",
        msg: sub_ok ? "cron subscription updated but auto-apply failed, rollback attempted" : "cron subscription update failed, rollback attempted"
    }, payload, true, stage), 200, trace_id);
}

function handle_cron_update_subscriptions_transaction(trace_id, payload, deps, dfa_cb, log_module) {
    Log(log_module, 'INFO', 'cron update_subscriptions transaction begin', trace_id);

    let bak_res = backup_flowproxy_uci(trace_id, log_module);
    if (!bak_res.ok) return bak_res;
    let uci_bak_path = bak_res.data.path;

    let sub_res = deps.update_subscriptions(trace_id, payload);
    if (!sub_res.ok) {
        return _cron_subscription_failure(trace_id, "subscription_update_failed", sub_res.detail, uci_bak_path, null, false, payload, log_module);
    }

    Log(log_module, 'INFO', 'subscription update success', trace_id);

    let apply_res = safe_cron_apply_config(trace_id, "update_subscriptions", payload, dfa_cb, log_module);
    if (!apply_res.ok) {
        let stage = _reload_failure_stage(apply_res);
        return _cron_subscription_failure(trace_id, stage, apply_res.detail || "unknown", uci_bak_path, apply_res, true, payload, log_module);
    }

    Log(log_module, 'INFO', 'cron update_subscriptions transaction success', trace_id);
    let data = (type(sub_res.data) === 'object') ? sub_res.data : {};
    data.subscription_success = true;
    data.cron_auto_apply = true;
    data.runtime_applied = true;
    data.restart_only = !(type(apply_res.data) === 'object' && apply_res.data.cron_mode_switch === true);
    data.restart_only_handled = true;
    data.dataplane_touched = !!(type(apply_res.data) === 'object' && apply_res.data.dataplane_touched === true);
    data.rollback_success = false;
    data.cron_mode_switch = !!(type(apply_res.data) === 'object' && apply_res.data.cron_mode_switch === true);
    data.msg = data.restart_only ? "cron subscription updated and applied by restart-only" : "cron subscription updated and applied by mode-switch lifecycle";
    data = fill_cron_observation_fields(data, payload, false, "");
    return Success(data, 200, trace_id);
}

function _cron_restart_only_apply(trace_id, job_type, payload, data, success_msg, dfa_cb, log_module) {
    if (!data || !data.changed) {
        data = (type(data) === 'object') ? data : {};
        data.cron_auto_apply = true;
        data.runtime_applied = false;
        data.restart_only = true;
        data.restart_only_handled = true;
        data.dataplane_touched = false;
        data.rollback_success = false;
        data.msg = success_msg + " (no runtime restart required)";
        data = fill_cron_observation_fields(data, payload, false, "");
        return Success(data, 200, trace_id);
    }

    let apply_res = safe_cron_apply_config(trace_id, job_type, payload, dfa_cb, log_module);
    if (!apply_res.ok) {
        return apply_res;
    }

    let apply_data = (type(apply_res.data) === 'object') ? apply_res.data : {};
    data.cron_auto_apply = true;
    data.runtime_applied = true;
    data.restart_only = apply_data.cron_mode_switch === true ? false : true;
    data.restart_only_handled = true;
    data.dataplane_touched = !!apply_data.dataplane_touched;
    data.rollback_success = false;
    data.cron_mode_switch = !!(apply_data.cron_mode_switch === true);
    data.msg = data.restart_only ? success_msg : replace(success_msg, "restart-only", "mode-switch lifecycle");
    data = fill_cron_observation_fields(data, payload, false, "");
    return Success(data, 200, trace_id);
}

function handle_cron_update_assets_transaction(trace_id, payload, deps, dfa_cb, log_module) {
    Log(log_module, 'INFO', 'cron update_assets transaction begin', trace_id);

    let update_res = deps.update_assets(trace_id, payload);
    if (!update_res.ok) {
        Log(log_module, 'WARN', sprintf('cron update_assets transaction failed stage=assets_update_failed detail=%s', update_res.detail || "unknown"), trace_id);
        Log(log_module, 'WARN', 'rollback assets attempted', trace_id);
        let asset_rb = task_rollback_assets(trace_id, {});
        return Success(fill_cron_observation_fields({
            assets_success: false,
            cron_auto_apply: true,
            cron_auto_apply_failed: true,
            runtime_applied: false,
            restart_only: true,
            restart_only_handled: true,
            dataplane_touched: false,
            rollback_success: !!(asset_rb && asset_rb.ok),
            error_stage: "assets_update_failed",
            detail: update_res.detail || "unknown",
            healthy: false,
            msg: "cron update_assets failed, rollback attempted"
        }, payload, true, "assets_update_failed"), 200, trace_id);
    }

    let data = (type(update_res.data) === 'object') ? update_res.data : {};
    let apply_res = _cron_restart_only_apply(trace_id, "update_assets", payload, data, "cron update_assets updated and applied by restart-only", dfa_cb, log_module);
    if (apply_res.ok) {
        Log(log_module, 'INFO', 'cron update_assets transaction success', trace_id);
        return apply_res;
    }

    let stage = _restart_only_failure_stage(apply_res);
    Log(log_module, 'WARN', sprintf('cron update_assets transaction failed stage=%s detail=%s', stage, apply_res.detail || "unknown"), trace_id);
    Log(log_module, 'WARN', 'rollback assets attempted', trace_id);
    let asset_rb = task_rollback_assets(trace_id, {});
    let runjson_rb_ok = rollback_run_json_if_needed(trace_id, apply_res, "update_assets", log_module);
    let restart_rb_ok = restart_process_rollback_if_needed(trace_id, apply_res, "update_assets", log_module);

    return Success(fill_cron_observation_fields({
        assets_success: true,
        cron_auto_apply: true,
        cron_auto_apply_failed: true,
        runtime_applied: false,
        restart_only: true,
        restart_only_handled: true,
        dataplane_touched: false,
        rollback_success: !!(asset_rb && asset_rb.ok && runjson_rb_ok && restart_rb_ok),
        error_stage: stage,
        detail: apply_res.detail || "unknown",
        updated: data.updated || [],
        unchanged: data.unchanged || [],
        failed: data.failed || [],
        healthy: false,
        msg: "cron update_assets updated but auto-apply failed, rollback attempted"
    }, payload, true, stage), 200, trace_id);
}

function handle_cron_update_resources_transaction(trace_id, payload, deps, dfa_cb, log_module) {
    Log(log_module, 'INFO', 'cron update_resources transaction begin', trace_id);

    let bak_res = deps.backup_resources(trace_id, log_module);
    if (!bak_res.ok) return bak_res;
    let bak_path = bak_res.data.path;

    let target = payload.target || "all";
    let update_res = (target === "all")
        ? deps.update_resources_all(trace_id, payload)
        : deps.update_resources(trace_id, payload);
    if (!update_res.ok) {
        Log(log_module, 'WARN', sprintf('cron update_resources transaction failed stage=resources_update_failed detail=%s', update_res.detail || "unknown"), trace_id);
        let resource_rb = deps.restore_resources(trace_id, bak_path, log_module);
        return Success(fill_cron_observation_fields({
            resources_success: false,
            cron_auto_apply: true,
            cron_auto_apply_failed: true,
            runtime_applied: false,
            restart_only: true,
            restart_only_handled: true,
            dataplane_touched: false,
            rollback_success: !!(resource_rb && resource_rb.ok),
            error_stage: "resources_update_failed",
            detail: update_res.detail || "unknown",
            healthy: false,
            msg: "cron update_resources failed, rollback attempted"
        }, payload, true, "resources_update_failed"), 200, trace_id);
    }

    let data = (type(update_res.data) === 'object') ? update_res.data : {};
    let apply_res = _cron_restart_only_apply(trace_id, "update_resources", payload, data, "cron update_resources updated and applied by restart-only", dfa_cb, log_module);
    if (apply_res.ok) {
        Log(log_module, 'INFO', 'cron update_resources transaction success', trace_id);
        return apply_res;
    }

    let stage = _restart_only_failure_stage(apply_res);
    Log(log_module, 'WARN', sprintf('cron update_resources transaction failed stage=%s detail=%s', stage, apply_res.detail || "unknown"), trace_id);
    let resource_rb = deps.restore_resources(trace_id, bak_path, log_module);
    let runjson_rb_ok = rollback_run_json_if_needed(trace_id, apply_res, "update_resources", log_module);
    let restart_rb_ok = restart_process_rollback_if_needed(trace_id, apply_res, "update_resources", log_module);

    return Success(fill_cron_observation_fields({
        resources_success: true,
        cron_auto_apply: true,
        cron_auto_apply_failed: true,
        runtime_applied: false,
        restart_only: true,
        restart_only_handled: true,
        dataplane_touched: false,
        rollback_success: !!(resource_rb && resource_rb.ok && runjson_rb_ok && restart_rb_ok),
        error_stage: stage,
        detail: apply_res.detail || "unknown",
        updated: data.updated || [],
        unchanged: data.unchanged || [],
        failed: data.failed || [],
        healthy: false,
        msg: "cron update_resources updated but auto-apply failed, rollback attempted"
    }, payload, true, stage), 200, trace_id);
}

export {
    fill_cron_observation_fields,
    safe_cron_apply_config,
    handle_cron_update_subscriptions_transaction,
    handle_cron_update_assets_transaction,
    handle_cron_update_resources_transaction
};
