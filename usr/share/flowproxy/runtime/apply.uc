/**
 * FlowProxy | runtime/apply.uc
 * Role: apply_config, process reload, dataplane reload, and mode-switch dispatch.
 */

'use strict';

import { ERR } from 'flowproxy.core.error';
import { Fail } from 'flowproxy.core.result';
import { log } from 'flowproxy.core.logger';
import { acquire } from 'flowproxy.core.lock';
import { RuntimeOrchestrator } from 'flowproxy.runtime.runtime';
import {
    begin_lifecycle_epoch,
    clear_lifecycle_protect,
    dispatch_procd_lifecycle,
    dispatch_restart_only_lifecycle,
    wait_lifecycle_ready,
    wait_process_ready
} from 'flowproxy.runtime.lifecycle';
import { HealthCheck } from 'flowproxy.runtime.healthcheck';

function Log(module, level, msg, trace_id) {
    log(trace_id, level, module || 'APPLY', msg);
}

function _bool_field(v, fallback) {
    if (v === true || v === false) return v;
    return !!fallback;
}

function _failure_stage(detail, data) {
    data = (type(data) === 'object') ? data : {};
    if (data.failed_stage) return data.failed_stage;

    let stage = data.error_stage || "";
    if (stage) return stage;

    let d = sprintf("%s", detail || "");
    if (index(d, "process restart") >= 0 || index(d, "restart_process") >= 0) return "restart_process_failed";
    if (index(d, "rollback failed") >= 0) return "rollback_failed";
    return "";
}

function _normalize_failure_data(detail, data) {
    data = (type(data) === 'object') ? data : {};
    let stage = _failure_stage(detail, data);
    let rollback_attempted = _bool_field(data.rollback_attempted, false);
    if (data.rollback_success === true || data.rollback_failed === true || stage === "rollback_failed") {
        rollback_attempted = true;
    }

    let rollback_success = _bool_field(data.rollback_success, false);
    let rollback_failed = _bool_field(data.rollback_failed, rollback_attempted && !rollback_success && stage === "rollback_failed");
    let danger_state = _bool_field(data.danger_state, rollback_failed);
    let manual_required = _bool_field(data.manual_intervention_required, danger_state || rollback_failed);

    data.rollback_attempted = rollback_attempted;
    data.rollback_success = rollback_success;
    data.rollback_failed = rollback_failed;
    data.manual_intervention_required = manual_required;
    data.danger_state = danger_state;
    data.failed_stage = stage;
    data.current_known_mode = data.current_known_mode || data.new_mode || "unknown";
    data.expected_safe_mode = data.expected_safe_mode || data.old_mode || data.restored_mode || "unknown";
    data.detail = data.detail || detail || "";
    return data;
}

function _obs_bool(v) {
    if (v === true) return "true";
    if (v === false) return "false";
    return "unknown";
}

function _obs_str(v) {
    if (v == null) return "unknown";
    return sprintf("%s", v);
}

function _log_rollback_observation(trace_id, log_module, stage, data) {
    data = (type(data) === 'object') ? data : {};
    Log(log_module, 'WARN', sprintf(
        'rollback_observe stage=%s rollback_attempted=%s rollback_success=%s rollback_failed=%s manual_intervention_required=%s danger_state=%s failed_stage=%s old_mode=%s new_mode=%s current_known_mode=%s expected_safe_mode=%s restored_run_json=%s old_process_restarted=%s old_dataplane_setup=%s old_verify_ok=%s rollback_detail=%s',
        stage || "unknown",
        _obs_bool(data.rollback_attempted),
        _obs_bool(data.rollback_success),
        _obs_bool(data.rollback_failed),
        _obs_bool(data.manual_intervention_required),
        _obs_bool(data.danger_state),
        _obs_str(data.failed_stage),
        _obs_str(data.old_mode || data.restored_mode),
        _obs_str(data.new_mode),
        _obs_str(data.current_known_mode),
        _obs_str(data.expected_safe_mode),
        _obs_bool(data.restored_run_json),
        _obs_bool(data.old_process_restarted),
        _obs_bool(data.old_dataplane_setup),
        _obs_bool(data.old_verify_ok),
        _obs_str(data.rollback_detail || data.detail)
    ), trace_id);
}

function _is_old_mode_recovery_stage(data) {
    data = (type(data) === 'object') ? data : {};
    return data.failed_stage === "setup_new_mode_failed" || data.failed_stage === "verify_new_mode_failed";
}

function _record_old_mode_recovery(trace_id, log_module, data, rb_restart, wait_res, health) {
    data = (type(data) === 'object') ? data : {};
    let restart_ok = !!(rb_restart && rb_restart.ok && wait_res && wait_res.ok);
    let verify_ok = !!(restart_ok && health && health.ok);
    let restart_failed = !restart_ok;
    let verify_failed = restart_ok && !verify_ok;

    data.old_process_restarted = restart_ok;
    data.old_restart_failed = restart_failed;
    data.old_verify_ok = verify_ok;
    data.old_verify_failed = verify_failed;
    _log_rollback_observation(trace_id, log_module, "restart_old_process_result", data);

    if (health && type(health) === 'object') {
        data.old_verify_mode = health.mode || (health.dataplane ? health.dataplane.mode : "unknown");
        data.old_verify_failed_items = health.failed || [];
    }
    _log_rollback_observation(trace_id, log_module, "verify_old_mode_result", data);

    if (restart_failed || verify_failed || data.old_setup_failed === true || data.restored_run_json === false) {
        data.rollback_success = false;
        data.rollback_failed = true;
        data.manual_intervention_required = true;
        data.danger_state = true;
        if (data.restored_run_json === false) {
            data.failed_stage = "restore_prev_run_json_failed";
        } else if (data.old_setup_failed === true) {
            data.failed_stage = "old_setup_failed";
        } else if (restart_failed) {
            data.failed_stage = "old_restart_failed";
        } else if (verify_failed) {
            data.failed_stage = "old_verify_failed";
        }
    } else if (data.rollback_attempted === true && data.restored_run_json === true && data.old_dataplane_setup === true && restart_ok && verify_ok) {
        data.rollback_success = true;
        data.rollback_failed = false;
        data.manual_intervention_required = false;
        data.danger_state = false;
    }

    _log_rollback_observation(trace_id, log_module, "rollback_final_state", data);
    return data;
}

function _release_and_return(lock_handle, res) {
    if (lock_handle) lock_handle.release();
    return res;
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

function _dataplane_reload_reason(job_type, payload) {
    if (_is_cron_auto_apply(job_type, payload)) return "cron_auto_apply";
    return "legacy_dataplane_reload";
}

function safe_system_reload(trace_id, job_type, payload, dfa_cb, log_module) {
    let dataplane_reason = _dataplane_reload_reason(job_type, payload);
    let lock_res = acquire(trace_id, "worker");
    if (!lock_res.ok) {
        return lock_res;
    }
    let lock_handle = lock_res.data;

    try {
        let prep_res = RuntimeOrchestrator.run_dataplane_reload(trace_id, job_type, dfa_cb, { phase: "prepare", reason: dataplane_reason, gc_policy: "force" });
        if (!prep_res.ok) {
            if (prep_res.need_restart && RuntimeOrchestrator.is_network_marker_set()) {
                let epoch = begin_lifecycle_epoch(trace_id, "prepare_failure_repair", log_module);
                dispatch_procd_lifecycle(trace_id, epoch, log_module);
                wait_lifecycle_ready(trace_id, epoch, log_module);
            }
            return _release_and_return(lock_handle, prep_res);
        }

        if (!prep_res.data || !prep_res.data.need_restart) {
            return _release_and_return(lock_handle, prep_res);
        }

        let epoch = begin_lifecycle_epoch(trace_id, job_type, log_module);
        let lifecycle_res = dispatch_procd_lifecycle(trace_id, epoch, log_module);
        if (!lifecycle_res.ok) {
            return _release_and_return(lock_handle, Fail(ERR.E_SYSTEM_BUSY, "procd lifecycle dispatch failed: " + lifecycle_res.detail, trace_id));
        }

        let barrier_res = wait_lifecycle_ready(trace_id, epoch, log_module);
        if (!barrier_res.ok) {
            return _release_and_return(lock_handle, Fail(ERR.E_SYSTEM_BUSY, "lifecycle barrier: " + barrier_res.detail, trace_id));
        }

        let verify_res = RuntimeOrchestrator.run_dataplane_reload(trace_id, job_type, dfa_cb, { phase: "verify_only", reason: dataplane_reason, gc_policy: "force" });
        if (!verify_res.ok && (verify_res.need_restart || RuntimeOrchestrator.is_network_marker_set())) {
            let repair_epoch = begin_lifecycle_epoch(trace_id, "verify_failure_repair", log_module);
            dispatch_procd_lifecycle(trace_id, repair_epoch, log_module);
            wait_lifecycle_ready(trace_id, repair_epoch, log_module);
        }
        if (verify_res.ok) clear_lifecycle_protect();
        return _release_and_return(lock_handle, verify_res);
    } catch (e) {
        let fail_res = Fail(ERR.E_SYSTEM_BUSY, "Dataplane reload crashed: " + ("" + e), trace_id);
        fail_res.data = _normalize_failure_data(fail_res.detail, { rollback_success: false });
        return _release_and_return(lock_handle, fail_res);
    }
}

function safe_process_reload(trace_id, job_type, dfa_cb, log_module) {
    let lock_res = acquire(trace_id, "worker");
    if (!lock_res.ok) {
        return lock_res;
    }
    let lock_handle = lock_res.data;

    try {
        let prep_res = RuntimeOrchestrator.run_process_reload(trace_id, job_type, dfa_cb, { phase: "prepare" });
        if (prep_res.data && prep_res.data.backend_mode_switch === true) {
            Log(log_module, 'WARN', sprintf(
                'backend mode switch selected; restart-only branch aborted old_mode=%s new_mode=%s',
                prep_res.data.old_mode || "unknown",
                prep_res.data.new_mode || "unknown"
            ), trace_id);
            return _release_and_return(lock_handle, prep_res);
        }

        if (!prep_res.ok) {
            return _release_and_return(lock_handle, prep_res);
        }

        if (!prep_res.data || !prep_res.data.need_restart) {
            return _release_and_return(lock_handle, prep_res);
        }

        let epoch = begin_lifecycle_epoch(trace_id, job_type + "_restart_only", log_module);
        let lifecycle_res = dispatch_restart_only_lifecycle(trace_id, epoch, log_module);
        if (!lifecycle_res.ok) {
            Log(log_module, 'WARN', 'restart_result=fail restart_process dispatch failed: ' + (lifecycle_res.detail || "unknown"), trace_id);
            let rb_res = RuntimeOrchestrator.run_process_reload(trace_id, job_type, dfa_cb, {
                phase: "rollback",
                bak_path: prep_res.data.bak_path
            });
            let fail_res = Fail(ERR.E_SYSTEM_BUSY, "process restart dispatch failed: " + lifecycle_res.detail, trace_id);
            fail_res.data = _normalize_failure_data(fail_res.detail, {
                config_committed: true,
                runtime_applied: false,
                rollback_attempted: true,
                rollback_success: !!(rb_res && rb_res.ok),
                rollback_failed: !(rb_res && rb_res.ok),
                manual_intervention_required: !(rb_res && rb_res.ok),
                danger_state: !(rb_res && rb_res.ok),
                failed_stage: "restart_process_failed"
            });
            return _release_and_return(lock_handle, fail_res);
        }
        Log(log_module, 'INFO', 'restart_result=success restart_process dispatched', trace_id);

        let barrier_res = wait_process_ready(trace_id, epoch, log_module);
        if (!barrier_res.ok) {
            Log(log_module, 'WARN', 'restart_result=fail restart_process barrier failed: ' + (barrier_res.detail || "unknown"), trace_id);
            let rb_res = RuntimeOrchestrator.run_process_reload(trace_id, job_type, dfa_cb, {
                phase: "rollback",
                bak_path: prep_res.data.bak_path
            });
            if (rb_res && rb_res.ok) {
                let repair_epoch = begin_lifecycle_epoch(trace_id, "restart_only_process_rollback", log_module);
                let rb_restart = dispatch_restart_only_lifecycle(trace_id, repair_epoch, log_module);
                if (rb_restart.ok) {
                    wait_process_ready(trace_id, repair_epoch, log_module);
                    clear_lifecycle_protect();
                }
            }
            let fail_res = Fail(ERR.E_SYSTEM_BUSY, "process restart verify failed: " + barrier_res.detail, trace_id);
            fail_res.data = _normalize_failure_data(fail_res.detail, {
                config_committed: true,
                runtime_applied: false,
                rollback_attempted: true,
                rollback_success: !!(rb_res && rb_res.ok),
                rollback_failed: !(rb_res && rb_res.ok),
                manual_intervention_required: !(rb_res && rb_res.ok),
                danger_state: !(rb_res && rb_res.ok),
                failed_stage: "restart_process_failed"
            });
            return _release_and_return(lock_handle, fail_res);
        }

        let verify_res = RuntimeOrchestrator.run_process_reload(trace_id, job_type, dfa_cb, {
            phase: "verify_only",
            bak_path: prep_res.data.bak_path
        });
        if (verify_res.ok) {
            clear_lifecycle_protect();
            return _release_and_return(lock_handle, verify_res);
        }

        if (verify_res.need_restart) {
            let repair_epoch = begin_lifecycle_epoch(trace_id, "restart_only_run_json_rollback", log_module);
            let rb_restart = dispatch_restart_only_lifecycle(trace_id, repair_epoch, log_module);
            if (rb_restart.ok) {
                wait_process_ready(trace_id, repair_epoch, log_module);
                clear_lifecycle_protect();
            }
        }

        return _release_and_return(lock_handle, verify_res);
    } catch (e) {
        let fail_res = Fail(ERR.E_SYSTEM_BUSY, "Process reload crashed: " + ("" + e), trace_id);
        fail_res.data = _normalize_failure_data(fail_res.detail, { rollback_success: false });
        return _release_and_return(lock_handle, fail_res);
    }
}

function safe_mode_switch_apply(trace_id, job_type, opts, dfa_cb, log_module) {
    opts = (type(opts) === 'object') ? opts : {};
    let lock_res = acquire(trace_id, "worker");
    if (!lock_res.ok) {
        return lock_res;
    }
    let lock_handle = lock_res.data;

    try {
        let prep_res = RuntimeOrchestrator.run_mode_switch_apply(trace_id, job_type, dfa_cb, {
            phase: "prepare",
            reuse_candidate: opts.reuse_candidate === true,
            reuse_checked: opts.reuse_checked === true
        });
        if (!prep_res.ok) {
            if (prep_res.need_restart) {
                let repair_epoch = begin_lifecycle_epoch(trace_id, "mode_switch_prepare_rollback", log_module);
                let rb_restart = dispatch_restart_only_lifecycle(trace_id, repair_epoch, log_module);
                if (rb_restart.ok) {
                    wait_process_ready(trace_id, repair_epoch, log_module);
                    clear_lifecycle_protect();
                }
            }
            return _release_and_return(lock_handle, prep_res);
        }

        let epoch = begin_lifecycle_epoch(trace_id, job_type + "_mode_switch", log_module);
        let lifecycle_res = dispatch_restart_only_lifecycle(trace_id, epoch, log_module);
        if (!lifecycle_res.ok) {
            Log(log_module, 'WARN', 'mode_switch restart_process dispatch failed: ' + (lifecycle_res.detail || "unknown"), trace_id);
            let rb_res = RuntimeOrchestrator.run_mode_switch_apply(trace_id, job_type, dfa_cb, {
                phase: "rollback",
                bak_path: prep_res.data.bak_path,
                old_mode: prep_res.data.old_mode,
                new_mode: prep_res.data.new_mode
            });
            if (rb_res && rb_res.need_restart) {
                let repair_epoch = begin_lifecycle_epoch(trace_id, "mode_switch_dispatch_rollback", log_module);
                let rb_restart = dispatch_restart_only_lifecycle(trace_id, repair_epoch, log_module);
                if (rb_restart.ok) {
                    wait_process_ready(trace_id, repair_epoch, log_module);
                    clear_lifecycle_protect();
                }
            }
            let fail_res = Fail(ERR.E_SYSTEM_BUSY, "mode switch process restart dispatch failed: " + lifecycle_res.detail, trace_id);
            fail_res.data = _normalize_failure_data(fail_res.detail, {
                mode_switch_applied: false,
                old_mode: prep_res.data.old_mode,
                new_mode: prep_res.data.new_mode,
                config_committed: true,
                runtime_applied: false,
                dataplane_touched: true,
                rollback_attempted: true,
                rollback_success: !!(rb_res && rb_res.ok),
                rollback_failed: !(rb_res && rb_res.ok),
                manual_intervention_required: !(rb_res && rb_res.ok),
                danger_state: !(rb_res && rb_res.ok),
                failed_stage: "restart_process_failed"
            });
            return _release_and_return(lock_handle, fail_res);
        }
        Log(log_module, 'INFO', 'mode_switch restart_result=success restart_process dispatched', trace_id);

        let barrier_res = wait_process_ready(trace_id, epoch, log_module);
        if (!barrier_res.ok) {
            Log(log_module, 'WARN', 'mode_switch restart_process barrier failed: ' + (barrier_res.detail || "unknown"), trace_id);
            let rb_res = RuntimeOrchestrator.run_mode_switch_apply(trace_id, job_type, dfa_cb, {
                phase: "rollback",
                bak_path: prep_res.data.bak_path,
                old_mode: prep_res.data.old_mode,
                new_mode: prep_res.data.new_mode
            });
            if (rb_res && rb_res.need_restart) {
                let repair_epoch = begin_lifecycle_epoch(trace_id, "mode_switch_barrier_rollback", log_module);
                let rb_restart = dispatch_restart_only_lifecycle(trace_id, repair_epoch, log_module);
                if (rb_restart.ok) {
                    wait_process_ready(trace_id, repair_epoch, log_module);
                    clear_lifecycle_protect();
                }
            }
            let fail_res = Fail(ERR.E_SYSTEM_BUSY, "mode switch process restart verify failed: " + barrier_res.detail, trace_id);
            fail_res.data = _normalize_failure_data(fail_res.detail, {
                mode_switch_applied: false,
                old_mode: prep_res.data.old_mode,
                new_mode: prep_res.data.new_mode,
                config_committed: true,
                runtime_applied: false,
                dataplane_touched: true,
                rollback_attempted: true,
                rollback_success: !!(rb_res && rb_res.ok),
                rollback_failed: !(rb_res && rb_res.ok),
                manual_intervention_required: !(rb_res && rb_res.ok),
                danger_state: !(rb_res && rb_res.ok),
                failed_stage: "restart_process_failed"
            });
            return _release_and_return(lock_handle, fail_res);
        }

        let verify_res = RuntimeOrchestrator.run_mode_switch_apply(trace_id, job_type, dfa_cb, {
            phase: "verify_only",
            bak_path: prep_res.data.bak_path,
            old_mode: prep_res.data.old_mode,
            new_mode: prep_res.data.new_mode
        });
        if (verify_res.ok) {
            clear_lifecycle_protect();
            return _release_and_return(lock_handle, verify_res);
        }

        if (verify_res.need_restart) {
            let repair_epoch = begin_lifecycle_epoch(trace_id, "mode_switch_run_json_rollback", log_module);
            let rb_restart = dispatch_restart_only_lifecycle(trace_id, repair_epoch, log_module);
            let wait_res = null;
            let old_health = null;
            if (rb_restart.ok) {
                wait_res = wait_process_ready(trace_id, repair_epoch, log_module);
                if (wait_res && wait_res.ok && type(verify_res.data) === 'object' && _is_old_mode_recovery_stage(verify_res.data)) {
                    old_health = HealthCheck.verify({ allow_transient: true });
                }
                clear_lifecycle_protect();
            }
            if (type(verify_res.data) === 'object' && _is_old_mode_recovery_stage(verify_res.data)) {
                verify_res.data = _record_old_mode_recovery(trace_id, log_module, verify_res.data, rb_restart, wait_res, old_health);
            }
        }

        return _release_and_return(lock_handle, verify_res);
    } catch (e) {
        let fail_res = Fail(ERR.E_SYSTEM_BUSY, "Mode switch apply crashed: " + ("" + e), trace_id);
        fail_res.data = _normalize_failure_data(fail_res.detail, { rollback_success: false });
        return _release_and_return(lock_handle, fail_res);
    }
}

function safe_apply_config(trace_id, dfa_cb, log_module) {
    let res = safe_process_reload(trace_id, "apply_config", dfa_cb, log_module);
    if (!(res && type(res.data) === 'object' && res.data.backend_mode_switch === true)) {
        if (res && res.ok && type(res.data) === 'object') {
            res.data.apply_branch = "same_mode";
        }
        return res;
    }

    Log(log_module, 'WARN', sprintf(
        'apply_config backend mode switch lifecycle old_mode=%s new_mode=%s',
        res.data.old_mode || "unknown",
        res.data.new_mode || "unknown"
    ), trace_id);

    let switch_res = safe_mode_switch_apply(trace_id, "apply_config", {
        reuse_candidate: true,
        reuse_checked: true
    }, dfa_cb, log_module);
    if (switch_res && type(switch_res.data) === 'object') {
        switch_res.data.apply_branch = "mode_switch";
        switch_res.data.backend_mode_switch = false;
        switch_res.data.next_action = "";
    }
    return switch_res;
}

export {
    safe_system_reload,
    safe_process_reload,
    safe_mode_switch_apply,
    safe_apply_config
};
