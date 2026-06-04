/**
 * FlowProxy | runtime/rollback.uc
 * Role: shared runtime transaction rollback and backup helpers.
 */

'use strict';

import { PATH, BIN } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { log } from 'flowproxy.core.logger';
import { ExecSafe } from 'flowproxy.core.utils';
import { RuntimeOrchestrator } from 'flowproxy.runtime.runtime';
import {
    begin_lifecycle_epoch,
    clear_lifecycle_protect,
    dispatch_restart_only_lifecycle,
    wait_process_ready
} from 'flowproxy.runtime.lifecycle';

const UCI_BACKUP_DIR = sprintf("%s/backup", PATH.RUNTIME);

function Log(module, level, msg, trace_id) {
    log(trace_id, level, module || 'ROLLBACK', msg);
}

function _rollback_failure(trace_id, detail) {
    let res = Fail(ERR.E_SYSTEM_BUSY, detail, trace_id);
    res.data = {
        rollback_attempted: true,
        rollback_success: false,
        rollback_failed: true,
        manual_intervention_required: true,
        danger_state: true,
        failed_stage: "rollback_failed",
        current_known_mode: "unknown",
        expected_safe_mode: "unknown",
        detail: detail || ""
    };
    return res;
}

function backup_flowproxy_uci(trace_id, log_module) {
    ExecSafe(BIN.MKDIR, ["-p", UCI_BACKUP_DIR], null, trace_id);
    let bak_path = sprintf("%s/flowproxy.uci.%s.bak", UCI_BACKUP_DIR, trace_id);
    let res = ExecSafe(BIN.CP, ["-f", PATH.UCI, bak_path], null, trace_id);
    if (!res.ok) {
        Log(log_module, 'ERROR', 'UCI backup failed: ' + res.detail, trace_id);
        return Fail(ERR.E_SYSTEM_BUSY, "UCI backup failed: " + res.detail, trace_id);
    }
    Log(log_module, 'INFO', 'UCI backup created: ' + bak_path, trace_id);
    return Success({ path: bak_path }, 200, trace_id);
}

function restore_flowproxy_uci(trace_id, bak_path, log_module) {
    Log(log_module, 'WARN', 'UCI rollback attempted: ' + (bak_path || "(none)"), trace_id);
    if (!bak_path) {
        return _rollback_failure(trace_id, "UCI rollback backup path missing");
    }
    let res = ExecSafe(BIN.CP, ["-f", bak_path, PATH.UCI], null, trace_id);
    if (!res.ok) {
        Log(log_module, 'ERROR', 'UCI rollback failed: ' + res.detail, trace_id);
        return _rollback_failure(trace_id, "UCI rollback failed: " + res.detail);
    }
    Log(log_module, 'WARN', 'UCI rollback success', trace_id);
    return Success(true, 200, trace_id);
}

function rollback_run_json_if_needed(trace_id, apply_res, job_type, log_module) {
    let apply_data = (apply_res && type(apply_res.data) === 'object') ? apply_res.data : {};
    if (apply_data.config_committed === true && apply_data.rollback_success !== true) {
        Log(log_module, 'WARN', 'rollback run.json attempted', trace_id);
        let rb_res = RuntimeOrchestrator.run_process_reload(trace_id, job_type, null, {
            phase: "rollback"
        });
        return !!(rb_res && rb_res.ok);
    }
    Log(log_module, 'WARN', 'rollback run.json attempted: already handled or not required', trace_id);
    return !!apply_data.rollback_success || apply_data.config_committed !== true;
}

function restart_process_rollback_if_needed(trace_id, apply_res, label, log_module) {
    let apply_data = (apply_res && type(apply_res.data) === 'object') ? apply_res.data : {};
    let prefix = label ? (label + ' ') : '';
    let reason = label ? (label + "_rollback_restart_only") : "cron_subscription_rollback_restart_only";
    if (apply_data.config_committed === true) {
        Log(log_module, 'WARN', prefix + 'restart_process rollback attempted', trace_id);
        let epoch = begin_lifecycle_epoch(trace_id, reason, log_module);
        let restart_res = dispatch_restart_only_lifecycle(trace_id, epoch, log_module);
        if (restart_res && restart_res.ok) {
            wait_process_ready(trace_id, epoch, log_module);
            clear_lifecycle_protect();
            return true;
        }
        return false;
    }
    Log(log_module, 'WARN', prefix + 'restart_process rollback attempted: not required', trace_id);
    return true;
}

export {
    backup_flowproxy_uci,
    restore_flowproxy_uci,
    rollback_run_json_if_needed,
    restart_process_rollback_if_needed
};
