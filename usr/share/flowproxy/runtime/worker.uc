/**
 * FlowProxy | runtime/worker.uc | v2.1 (Lifecycle ABI Stable Edition)
 * 职责：Job DFA、Handler 调度、reload 门闸；lifecycle 交由 procd 派发 + barrier。
 */

'use strict';

import { cursor } from 'uci';

import { JOB_TYPES, job_allows_dataplane_reload } from 'flowproxy.core.contract';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { with_changed } from 'flowproxy.core.module_result';
import { log as sys_log } from 'flowproxy.core.logger';

import { get_status, transition, STATE_ENUM } from 'flowproxy.core.job';
import { acquire } from 'flowproxy.core.lock';
import { run_all_checks } from 'flowproxy.core.selfcheck';
import { StateManager } from 'flowproxy.runtime.state';
import { RuntimeOrchestrator } from 'flowproxy.runtime.runtime';
import {
    safe_system_reload as apply_safe_system_reload,
    safe_process_reload as apply_safe_process_reload,
    safe_mode_switch_apply as apply_safe_mode_switch_apply,
    safe_apply_config as apply_safe_apply_config
} from 'flowproxy.runtime.apply';
import {
    fill_cron_observation_fields as cron_fill_cron_observation_fields,
    safe_cron_apply_config as cron_safe_cron_apply_config,
    handle_cron_update_subscriptions_transaction as cron_handle_update_subscriptions_transaction,
    handle_cron_update_assets_transaction as cron_handle_update_assets_transaction,
    handle_cron_update_resources_transaction as cron_handle_update_resources_transaction
} from 'flowproxy.runtime.cron';
import {
    begin_lifecycle_epoch as lifecycle_begin_lifecycle_epoch,
    clear_lifecycle_protect as lifecycle_clear_lifecycle_protect,
    dispatch_procd_lifecycle as lifecycle_dispatch_procd_lifecycle,
    dispatch_restart_only_lifecycle as lifecycle_dispatch_restart_only_lifecycle,
    wait_lifecycle_ready as lifecycle_wait_lifecycle_ready,
    wait_process_ready as lifecycle_wait_process_ready
} from 'flowproxy.runtime.lifecycle';

import { task_update_subscriptions } from 'flowproxy.modules.subscription';
import { task_rebuild_groups } from 'flowproxy.modules.groups';
import { task_update_assets_summary, task_rollback_assets } from 'flowproxy.modules.assets';
import { task_update_kernel } from 'flowproxy.modules.kernel';
import { send_telegram_best_effort as notifier_send_telegram_best_effort, notification_summary } from 'flowproxy.modules.notifier';
import {
    task_update_resources_summary,
    task_update_resources_all,
    backup_resources as resources_backup_resources,
    restore_resources as resources_restore_resources
} from 'flowproxy.modules.resources';
import { observe } from 'flowproxy.runtime.watchdog';
import { logrotate } from 'flowproxy.core.logger';

function Log(module, level, msg, job_id) {
    sys_log(job_id, level, module, msg);
}

function _dfa(job_id, state, progress, err) {
    transition(job_id, state, progress, err, job_id);
}

function _is_manual_business_task(job_type, payload) {
    if (!(job_type === 'update_subscriptions' || job_type === 'update_assets' || job_type === 'update_resources' || job_type === 'rebuild_groups')) {
        return false;
    }
    payload = payload || {};
    let source = sprintf("%s", payload.source || "");
    let auto_apply = payload.auto_apply;
    let auto_apply_disabled = (auto_apply === false || auto_apply === 0 || auto_apply === "0" || auto_apply === "false" || auto_apply === "no");
    return source === "manual" || auto_apply_disabled;
}

function _is_cron_auto_apply(job_type, payload) {
    if (!(job_type === 'update_subscriptions' || job_type === 'update_assets' || job_type === 'update_resources' || job_type === 'rebuild_groups')) {
        return false;
    }
    payload = payload || {};
    let source = sprintf("%s", payload.source || "");
    let auto_apply = payload.auto_apply;
    let auto_apply_enabled = (auto_apply === true || auto_apply === 1 || auto_apply === "1" || auto_apply === "true" || auto_apply === "yes");
    return source === "cron" && auto_apply_enabled;
}

function _mark_manual_apply_required(result) {
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

function _bool_text(v) {
    return v ? "true" : "false";
}

function _log_manual_apply_required(job_id, job_type, data) {
    data = (type(data) === 'object') ? data : {};
    Log('WORKER', 'WARN', sprintf(
        'manual_task_result job_type=%s business_success=%s runtime_applied=false next_action=manual_apply_required changed=%s',
        job_type || "unknown",
        _bool_text(data.business_success === true),
        _bool_text(data.changed === true)
    ), job_id);
}

function _log_cron_apply_result(job_id, job_type, data) {
    data = (type(data) === 'object') ? data : {};
    let branch = "none";
    if (data.error_stage === "cron_mode_switch_denied") branch = "mode_switch_denied";
    else if (data.cron_mode_switch === true || data.mode_switch_applied === true || data.apply_branch === "mode_switch") branch = "mode_switch";
    else if (data.restart_only === true || data.apply_branch === "same_mode") branch = "same_mode";

    Log('WORKER', 'WARN', sprintf(
        'cron_apply_result job_type=%s branch=%s runtime_applied=%s restart_only=%s dataplane_touched=%s rollback_success=%s error_stage=%s allow_cron_mode_switch=%s',
        job_type || "unknown",
        branch,
        _bool_text(data.runtime_applied === true),
        _bool_text(data.restart_only === true),
        _bool_text(data.dataplane_touched === true),
        _bool_text(data.rollback_success === true),
        data.error_stage || "",
        _bool_text(data.allow_cron_mode_switch === true)
    ), job_id);
}

function _fill_cron_observation_fields(data, payload, failed, stage) {
    return cron_fill_cron_observation_fields(data, payload, failed, stage);
}

function _send_telegram_best_effort(task_type, status, msg, job_id) {
    return notifier_send_telegram_best_effort(task_type, status, msg, job_id, 'WORKER');
}

function _needs_reload(job_type, result, payload) {
    if (!job_allows_dataplane_reload(job_type)) return false;
    if (!result || !result.ok) return false;
    let data = result.data;

    if (type(data) === 'object' && data.next_action === "manual_apply_required") return false;
    if (type(data) === 'object' && data.restart_only_handled) return false;

    if (job_type === 'update_subscriptions' || job_type === 'update_assets' || job_type === 'update_resources' || job_type === 'rebuild_groups') {
        if (!_is_cron_auto_apply(job_type, payload)) return false;
    }

    if (job_type === 'apply_config' || job_type === 'update_subscriptions' || job_type === 'rebuild_groups') {
        return true;
    }
    if (type(data) === 'object' && data.changed) return true;
    return false;
}

function _begin_lifecycle_epoch(job_id, reason) {
    return lifecycle_begin_lifecycle_epoch(job_id, reason, 'WORKER');
}

function _clear_lifecycle_protect() {
    return lifecycle_clear_lifecycle_protect();
}

function _dispatch_procd_lifecycle(job_id, epoch) {
    return lifecycle_dispatch_procd_lifecycle(job_id, epoch, 'WORKER');
}

function _dispatch_restart_only_lifecycle(job_id, epoch) {
    return lifecycle_dispatch_restart_only_lifecycle(job_id, epoch, 'WORKER');
}

function _wait_lifecycle_ready(job_id, epoch) {
    return lifecycle_wait_lifecycle_ready(job_id, epoch, 'WORKER');
}

function _wait_process_ready(job_id, epoch) {
    return lifecycle_wait_process_ready(job_id, epoch, 'WORKER');
}

function _release_and_return(lock_handle, res) {
    if (lock_handle) lock_handle.release();
    return res;
}

function safe_system_reload(job_id, job_type, payload) {
    let dfa_cb = function(st, prog, err) {
        _dfa(job_id, st, prog, err);
    };
    return apply_safe_system_reload(job_id, job_type, payload, dfa_cb, 'WORKER');
}

function safe_process_reload(job_id, job_type) {
    let dfa_cb = function(st, prog, err) {
        _dfa(job_id, st, prog, err);
    };
    return apply_safe_process_reload(job_id, job_type, dfa_cb, 'WORKER');
}

function safe_mode_switch_apply(job_id, job_type, opts) {
    let dfa_cb = function(st, prog, err) {
        _dfa(job_id, st, prog, err);
    };
    return apply_safe_mode_switch_apply(job_id, job_type, opts, dfa_cb, 'WORKER');
}

function safe_apply_config(job_id) {
    let dfa_cb = function(st, prog, err) {
        _dfa(job_id, st, prog, err);
    };
    return apply_safe_apply_config(job_id, dfa_cb, 'WORKER');
}

function _normalize_proxy_mode(mode) {
    mode = trim(sprintf("%s", mode || ""));
    if (mode === "redirect" || mode === "redirect_tproxy") return "redirect_tproxy";
    if (mode === "redirect_tun" || mode === "tun") return "tun";
    return mode;
}

function _read_uci_proxy_mode(job_id) {
    try {
        let u = cursor();
        u.load("flowproxy");
        return _normalize_proxy_mode(u.get("flowproxy", "config", "proxy_mode") || u.get("flowproxy", "routing", "proxy_mode") || "redirect_tproxy");
    } catch (e) {
        Log('WORKER', 'WARN', 'uci_proxy_mode_before_generate read failed: ' + e, job_id);
        return "";
    }
}

function safe_cron_apply_config(job_id, job_type, payload) {
    let dfa_cb = function(st, prog, err) {
        _dfa(job_id, st, prog, err);
    };
    return cron_safe_cron_apply_config(job_id, job_type, payload, dfa_cb, 'WORKER');
}

function _handle_mode_switch_apply(job_id, payload) {
    Log('WORKER', 'WARN', 'mode_switch_apply requested; explicit Level 5 mode switch lifecycle', job_id);
    let res = safe_mode_switch_apply(job_id, "mode_switch_apply");
    if (res && res.ok) {
        res.data = (type(res.data) === 'object') ? res.data : {};
        res.data.restart_only_handled = true;
        res.data.changed = false;
        res.data.msg = "mode_switch_apply completed";
    }
    return res;
}

function _handle_apply_config(job_id, payload) {
    payload = payload || {};
    let expected_proxy_mode = _normalize_proxy_mode(payload.expected_proxy_mode || "");
    let uci_proxy_mode = _read_uci_proxy_mode(job_id);
    Log('WORKER', 'INFO', sprintf(
        'expected_proxy_mode=%s uci_proxy_mode_before_generate=%s',
        expected_proxy_mode || "(none)",
        uci_proxy_mode || "(unreadable)"
    ), job_id);

    if (expected_proxy_mode && uci_proxy_mode && expected_proxy_mode !== uci_proxy_mode) {
        let res = Fail(ERR.E_SYSTEM_BUSY, sprintf(
            "E_CONFIG_STALE: expected_proxy_mode=%s uci_proxy_mode_before_generate=%s",
            expected_proxy_mode,
            uci_proxy_mode
        ), job_id);
        res.data = {
            error_code: "E_CONFIG_STALE",
            expected_proxy_mode: expected_proxy_mode,
            uci_proxy_mode: uci_proxy_mode,
            config_committed: false,
            runtime_applied: false,
            need_restart: false
        };
        Log('WORKER', 'WARN', sprintf(
            'action=fail reason=E_CONFIG_STALE expected_proxy_mode=%s uci_proxy_mode_before_generate=%s',
            expected_proxy_mode,
            uci_proxy_mode
        ), job_id);
        return res;
    }

    Log('WORKER', 'INFO', 'apply_config: changed=true (job policy)', job_id);
    Log('WORKER', 'INFO', 'apply_config requested explicit runtime apply', job_id);
    return Success(with_changed(true, {}), 200, job_id);
}

function _handle_rebuild_groups(job_id, payload) {
    let res = task_rebuild_groups(job_id);
    if (!res.ok) return Fail(ERR.E_SYSTEM_BUSY, "重组节点组失败: " + res.detail, job_id);
    return res;
}

function _handle_update_assets(job_id, payload) {
    return task_update_assets_summary(job_id, payload);
}

function _handle_system_rollback(job_id, payload) {
    let res = task_rollback_assets(job_id, payload);
    if (!res.ok) return Fail(ERR.E_SYSTEM_BUSY, res.detail, job_id);
    return res;
}

function _handle_repair_current_mode(job_id, payload) {
    Log('WORKER', 'INFO', 'repair_current_mode requested', job_id);

    let lock_res = acquire(job_id, "worker");
    if (!lock_res.ok) {
        return lock_res;
    }
    let lock_handle = lock_res.data;

    try {
        let res = RuntimeOrchestrator.setup_network_only(job_id, {
            reason: "repair",
            gc_policy: "skip"
        });
        if (!res || !res.ok) {
            return _release_and_return(lock_handle, Fail(
                ERR.E_SYSTEM_BUSY,
                "repair_current_mode failed: " + ((res && res.detail) ? res.detail : "unknown"),
                job_id
            ));
        }

        return _release_and_return(lock_handle, Success({
            repair_success: true,
            runtime_applied: false,
            restarted: false,
            reason: "repair",
            gc_policy: "skip",
            msg: "repair_current_mode completed"
        }, 200, job_id));
    } catch (e) {
        return _release_and_return(lock_handle, Fail(ERR.E_SYSTEM_BUSY, "repair_current_mode crashed: " + ("" + e), job_id));
    }
}

function _handle_deploy_panels(job_id, payload) {
    let res = task_update_assets_summary(job_id, { action: 'update', target: 'panels' });
    if (!res.ok) return Fail(ERR.E_SYSTEM_BUSY, res.detail, job_id);
    return res;
}

function _handle_update_kernel(job_id, payload) {
    if (type(task_update_kernel) !== "function") {
        return Fail(ERR.E_SYSTEM_BUSY, "Fatal: Kernel Manager not loaded.", job_id);
    }
    let res = task_update_kernel(job_id, payload);
    if (!res.ok) return Fail(ERR.E_SYSTEM_BUSY, res.detail, job_id);
    return res;
}

function _handle_update_resources(job_id, payload) {
    return task_update_resources_summary(job_id, payload);
}

function _handle_update_subscriptions(job_id, payload) {
    return task_update_subscriptions(job_id, payload);
}

function _handle_cron_update_subscriptions_transaction(job_id, payload) {
    let dfa_cb = function(st, prog, err) {
        _dfa(job_id, st, prog, err);
    };
    return cron_handle_update_subscriptions_transaction(job_id, payload, {
        update_subscriptions: _handle_update_subscriptions
    }, dfa_cb, 'WORKER');
}

function _handle_cron_update_assets_transaction(job_id, payload) {
    let dfa_cb = function(st, prog, err) {
        _dfa(job_id, st, prog, err);
    };
    return cron_handle_update_assets_transaction(job_id, payload, {
        update_assets: _handle_update_assets
    }, dfa_cb, 'WORKER');
}

function _handle_update_resources_all(job_id, payload) {
    return task_update_resources_all(job_id, payload);
}

function _handle_cron_update_resources_transaction(job_id, payload) {
    let dfa_cb = function(st, prog, err) {
        _dfa(job_id, st, prog, err);
    };
    return cron_handle_update_resources_transaction(job_id, payload, {
        backup_resources: resources_backup_resources,
        restore_resources: resources_restore_resources,
        update_resources: _handle_update_resources,
        update_resources_all: _handle_update_resources_all
    }, dfa_cb, 'WORKER');
}
function _handle_watchdog_report(job_id, payload) {
    let obs = observe(job_id);

    if (obs.skipped) {
        StateManager.record_state({
            last_observed_at: time(),
            watchdog: {
                healthy: true,
                fail_count: 0,
                drift: [],
                skipped: true,
                last_state: "healthy",
                last_notified_state: obs.last_notified_state || "healthy"
            }
        });
        return Success({
            healthy: true,
            fail_count: 0,
            drift: [],
            skipped: true,
            notify: false,
            edge: "none",
            message: obs.message || "Watchdog skipped (service disabled)",
            msg: obs.message || "Watchdog skipped (service disabled)"
        }, 200, job_id);
    }

    let drift = (obs.health && obs.health.failed) ? obs.health.failed : [];
    let fail_count = obs.consecutive_fails || 0;
    let healthy = !!obs.healthy;

    StateManager.record_state({
        last_observed_at: time(),
        degraded_reason: healthy ? "" : ("drift:" + join(",", drift)),
        watchdog: {
            healthy: healthy,
            fail_count: fail_count,
            drift: drift,
            skipped: false,
            last_state: obs.last_state || (healthy ? "healthy" : "broken"),
            last_notified_state: obs.last_notified_state || (healthy ? "healthy" : "broken")
        }
    });

    if (!healthy) {
        let msg = sprintf(
            "Drift observed: %s (fail_count=%d). No auto-repair; use apply_config if needed.",
            join(", ", drift), fail_count
        );
        return Success({
            healthy: false,
            fail_count: fail_count,
            drift: drift,
            notify: !!obs.notify,
            edge: obs.edge || "none",
            next_notified_state: obs.next_notified_state || "broken",
            message: msg,
            msg: msg
        }, 200, job_id);
    }

    return Success({
        healthy: true,
        fail_count: 0,
        drift: [],
        notify: !!obs.notify,
        edge: obs.edge || "none",
        next_notified_state: obs.next_notified_state || "healthy",
        message: obs.message || "Watchdog: system healthy",
        msg: obs.message || "Watchdog: system healthy"
    }, 200, job_id);
}
function _handle_maintenance_logrotate(job_id, payload) {
    logrotate();
    Log('WORKER', 'INFO', 'Log archive maintenance completed.', job_id);
    return Success({ msg: "Log maintenance complete" }, 200, job_id);
}

const HANDLERS = {
    "apply_config": _handle_apply_config,
    "mode_switch_apply": _handle_mode_switch_apply,
    "update_subscriptions": _handle_update_subscriptions,
    "rebuild_groups": _handle_rebuild_groups,
    "update_assets": _handle_update_assets,
    "update_resources": _handle_update_resources,
    "system_rollback": _handle_system_rollback,
    "repair_current_mode": _handle_repair_current_mode,
    "update_kernel": _handle_update_kernel,
    "deploy_panels": _handle_deploy_panels,
    "watchdog_report": _handle_watchdog_report,
    "maintenance_logrotate": _handle_maintenance_logrotate
};

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

    transition(job_id, STATE_ENUM.RUNNING, 10, null, job_id);
    Log('WORKER', 'INFO', 'Worker initialized. Dataplane lock will be acquired only during reload.', job_id);

    try {
        let safe_type = current_job.type;

        if (!JOB_TYPES[safe_type]) {
            let err_msg = "E_CONTRACT_VIOLATION: Job not in contract -> " + safe_type;
            Log('WORKER', 'ERROR', err_msg, job_id);
            transition(job_id, STATE_ENUM.FAIL, current_job.progress, err_msg, job_id);
            exit(1);
        }
        if (!HANDLERS[safe_type]) {
            let err_msg = "E_CONTRACT_VIOLATION: Handler missing for contract job -> " + safe_type;
            Log('WORKER', 'ERROR', err_msg, job_id);
            transition(job_id, STATE_ENUM.FAIL, current_job.progress, err_msg, job_id);
            _send_telegram_best_effort(safe_type, "fail", err_msg, job_id);
            exit(1);
        }

        let result = null;
        if (safe_type === "update_subscriptions" && _is_cron_auto_apply(safe_type, current_job.payload)) {
            result = _handle_cron_update_subscriptions_transaction(job_id, current_job.payload);
        } else if (safe_type === "update_assets" && _is_cron_auto_apply(safe_type, current_job.payload)) {
            result = _handle_cron_update_assets_transaction(job_id, current_job.payload);
        } else if (safe_type === "update_resources" && _is_cron_auto_apply(safe_type, current_job.payload)) {
            result = _handle_cron_update_resources_transaction(job_id, current_job.payload);
        } else {
            result = HANDLERS[safe_type](job_id, current_job.payload);
        }
        let manual_business_complete = false;

        if (result.ok && _is_manual_business_task(safe_type, current_job.payload)) {
            Log('WORKER', 'INFO', 'business data updated; runtime apply pending', job_id);
            result = _mark_manual_apply_required(result);
            _log_manual_apply_required(job_id, safe_type, result.data);
            manual_business_complete = true;
        } else if (result.ok && _is_cron_auto_apply(safe_type, current_job.payload) && !(type(result.data) === 'object' && result.data.restart_only_handled)) {
            Log('WORKER', 'INFO', 'cron auto_apply=true; entering runtime apply chain', job_id);
        }

        if (result.ok && !manual_business_complete && _needs_reload(safe_type, result, current_job.payload)) {
            let reload_res = (safe_type === "apply_config")
                ? safe_apply_config(job_id)
                : (_is_cron_auto_apply(safe_type, current_job.payload)
                    ? safe_cron_apply_config(job_id, safe_type, current_job.payload)
                    : safe_system_reload(job_id, safe_type, current_job.payload));
            if (!reload_res.ok) {
                let reload_detail = reload_res.detail || "unknown";
                if (type(reload_res.data) === 'object') {
                    reload_detail += " | data=" + sprintf("%.J", reload_res.data);
                }
                if (safe_type === "update_subscriptions") {
                    let msg = ((type(result.data) === 'object' && result.data.msg) ? result.data.msg : "Subscription update completed");
                    msg += "%0A[WARN] Runtime reload failed after subscription update";
                    msg += "%0Asubscription_success=true, dataplane_success=false";
                    msg += "%0Adetail=" + reload_detail;
                    Log('WORKER', 'WARN', "Subscription business succeeded but dataplane reload failed: subscription_success=true dataplane_success=false detail=" + reload_detail, job_id);
                    transition(job_id, STATE_ENUM.SUCCESS, 100, null, job_id);
                    _send_telegram_best_effort(safe_type, "success", msg, job_id);
                    exit(0);
                }
                transition(job_id, STATE_ENUM.FAIL, 95, reload_detail, job_id);
                _send_telegram_best_effort(safe_type, "fail", reload_detail, job_id);
                exit(1);
            }
            if (safe_type === "update_subscriptions") {
                Log('WORKER', 'INFO', 'Subscription reload phase completed: reload_success=true dataplane_success=true', job_id);
            }
            if (safe_type === "apply_config") {
                if (type(result.data) !== 'object') result.data = {};
                if (type(reload_res.data) === 'object') {
                    for (let k in reload_res.data) {
                        result.data[k] = reload_res.data[k];
                    }
                    if (reload_res.data.apply_branch === "mode_switch" || reload_res.data.mode_switch_applied === true) {
                        result.data.msg = sprintf(
                            "apply_config mode switch completed old_mode=%s new_mode=%s rollback_success=%s",
                            reload_res.data.old_mode || "unknown",
                            reload_res.data.new_mode || "unknown",
                            reload_res.data.rollback_success ? "true" : "false"
                        );
                    }
                }
                StateManager.reset_watchdog_baseline("healthy");
            }
        }

        if (result.ok) {
            if (_is_cron_auto_apply(safe_type, current_job.payload) && type(result.data) === 'object') {
                _log_cron_apply_result(job_id, safe_type, result.data);
            }

            transition(job_id, STATE_ENUM.SUCCESS, 100, null, job_id);
            let dynamic_msg = (type(result.data) === 'object' && result.data.msg) ? result.data.msg : "Task completed";
            let notify_status = "success";
            dynamic_msg = notification_summary(safe_type, "success", result.data, dynamic_msg);
            if (type(result.data) === 'object' && result.data.healthy === false) {
                notify_status = "fail";
                dynamic_msg = notification_summary(safe_type, "fail", result.data, dynamic_msg);
            }
            if (safe_type === "watchdog_report") {
                if (type(result.data) === 'object' && result.data.notify === true) {
                    let tg_res = _send_telegram_best_effort(safe_type, notify_status, dynamic_msg, job_id);
                    if (tg_res && tg_res.ok) {
                        StateManager.record_state({
                            watchdog: {
                                last_notified_state: result.data.next_notified_state || (result.data.healthy ? "healthy" : "broken")
                            }
                        });
                    }
                }
                exit(0);
            }
            _send_telegram_best_effort(safe_type, notify_status, dynamic_msg, job_id);
        } else {
            transition(job_id, STATE_ENUM.FAIL, current_job.progress, result.detail, job_id);
            _send_telegram_best_effort(safe_type, "fail", result.detail, job_id);
        }
    } catch (e) {
        let err_msg = "" + e;
        transition(job_id, STATE_ENUM.FAIL, current_job.progress, "Worker crashed: " + err_msg, job_id);
        _send_telegram_best_effort(current_job.type, "fail", "Worker crashed: " + err_msg, job_id);
    }

    exit(0);
}

if (length(ARGV) > 0) {
    main(ARGV[0]);
}



