/**
 * FlowProxy | runtime/lifecycle.uc
 * Role: service lifecycle dispatch and readiness barriers.
 */

'use strict';

import { writefile, unlink } from 'fs';

import { PATH, BIN } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { log } from 'flowproxy.core.logger';
import { ExecSafe } from 'flowproxy.core.utils';
import { HealthCheck, verify_process, lifecycle_grace_reason, lifecycle_error_detail } from 'flowproxy.runtime.healthcheck';

const LIFECYCLE_BARRIER_INTERVAL_SEC = 1;
const LIFECYCLE_PID_TIMEOUT_SEC = 45;
const LIFECYCLE_STABLE_TIMEOUT_SEC = 75;
const LIFECYCLE_STABLE_SAMPLES = 3;
const LIFECYCLE_SETTLE_MIN_SEC = 5;
const LIFECYCLE_SETTLE_TIMEOUT_SEC = 30;
const LIFECYCLE_EPOCH_FILE = sprintf("%s/lifecycle.epoch", PATH.RUNTIME);
const LIFECYCLE_PROTECT_FILE = sprintf("%s/lifecycle.protect", PATH.RUNTIME);

function Log(module, level, msg, trace_id) {
    log(trace_id, level, module || 'LIFECYCLE', msg);
}

function begin_lifecycle_epoch(trace_id, reason, log_module) {
    let epoch = sprintf("%s_%d", trace_id || "job", time());
    writefile(LIFECYCLE_EPOCH_FILE, epoch + "\n");
    writefile(LIFECYCLE_PROTECT_FILE, epoch + "\n");
    Log(log_module, 'INFO', sprintf('Lifecycle epoch prepared: %s (%s)', epoch, reason || "reload"), trace_id);
    return epoch;
}

function clear_lifecycle_protect() {
    unlink(LIFECYCLE_PROTECT_FILE);
}

function dispatch_procd_lifecycle(trace_id, epoch, log_module) {
    Log(log_module, 'INFO', sprintf('Dispatching procd service restart (epoch=%s, sing-box lifecycle owner: init.d)', epoch || "none"), trace_id);

    let ubus_cmd = "ubus call service restart '{\"name\":\"flowproxy\"}'";
    let res = ExecSafe(BIN.SH, ["-c", ubus_cmd], null, trace_id);
    if (res.ok) return res;

    if (index(res.detail || "", "Method not found") >= 0) {
        Log(log_module, 'WARN', 'ubus service.restart unavailable; falling back to init.d restart.', trace_id);
        let fallback_timeout = 120;
        let fallback_start = time();
        Log(log_module, 'INFO', sprintf(
            'fallback init.d restart start timestamp=%d timeout=%ds',
            fallback_start, fallback_timeout
        ), trace_id);
        let fallback_res = ExecSafe(BIN.SH, ["-c", "/etc/init.d/flowproxy restart"], { timeout: fallback_timeout }, trace_id);
        let fallback_duration = time() - fallback_start;
        let fallback_exit = (fallback_res && fallback_res.data && fallback_res.data.exit_code != null) ? fallback_res.data.exit_code : -1;
        Log(log_module, fallback_res.ok ? 'INFO' : 'WARN', sprintf(
            'fallback init.d restart finished duration=%ds timeout=%ds exit_code=%d',
            fallback_duration, fallback_timeout, fallback_exit
        ), trace_id);
        return fallback_res;
    }

    return res;
}

function dispatch_restart_only_lifecycle(trace_id, epoch, log_module) {
    Log(log_module, 'INFO', sprintf('Dispatching process-only restart_process lifecycle (epoch=%s)', epoch || "none"), trace_id);
    let res = ExecSafe(PATH.INIT, ["restart_process"], { timeout: 60 }, trace_id);
    if (!res.ok) {
        Log(log_module, 'WARN', 'restart_process failed: ' + (res.detail || "unknown"), trace_id);
        Log(log_module, 'WARN', sprintf(
            'lifecycle_observe stage=restart_process_result restart_process_ok=false epoch=%s detail=%s',
            epoch || "none",
            res.detail || "unknown"
        ), trace_id);
    } else {
        Log(log_module, 'INFO', sprintf(
            'lifecycle_observe stage=restart_process_result restart_process_ok=true epoch=%s detail=ok',
            epoch || "none"
        ), trace_id);
    }
    return res;
}

function _sleep_barrier(trace_id) {
    ExecSafe(BIN.SH, ["-c", sprintf("sleep %s", LIFECYCLE_BARRIER_INTERVAL_SEC)], null, trace_id);
}

function wait_lifecycle_ready(trace_id, epoch, log_module) {
    Log(log_module, 'INFO', sprintf('Waiting lifecycle barrier stage=pid epoch=%s...', epoch || "none"), trace_id);
    let pid_deadline = time() + LIFECYCLE_PID_TIMEOUT_SEC;

    while (time() < pid_deadline) {
        if (verify_process()) {
            Log(log_module, 'INFO', 'Lifecycle barrier stage=pid observed.', trace_id);
            break;
        }
        _sleep_barrier(trace_id);
    }

    if (!verify_process()) {
        Log(log_module, 'WARN', 'Lifecycle barrier timeout at stage=pid.', trace_id);
        return Fail(ERR.E_SYSTEM_BUSY, lifecycle_error_detail("Lifecycle barrier timeout: real sing-box process not observed"), trace_id);
    }

    Log(log_module, 'INFO', sprintf('Waiting lifecycle barrier stage=settling epoch=%s...', epoch || "none"), trace_id);
    let settle_until = time() + LIFECYCLE_SETTLE_MIN_SEC;
    let settle_deadline = time() + LIFECYCLE_SETTLE_TIMEOUT_SEC;
    while (time() < settle_until || lifecycle_grace_reason()) {
        let grace = lifecycle_grace_reason();
        if (!grace && time() >= settle_until) break;
        _sleep_barrier(trace_id);
        if (time() >= settle_deadline) break;
    }

    Log(log_module, 'INFO', sprintf('Waiting lifecycle barrier stage=stable samples=%d epoch=%s...', LIFECYCLE_STABLE_SAMPLES, epoch || "none"), trace_id);
    let stable_deadline = time() + LIFECYCLE_STABLE_TIMEOUT_SEC;
    let stable_count = 0;
    let last_detail = "";

    while (time() < stable_deadline) {
        let health = HealthCheck.verify({ allow_transient: true });
        if (health.ok && !(health.dataplane && health.dataplane.transient)) {
            stable_count++;
            if (stable_count >= LIFECYCLE_STABLE_SAMPLES) {
                Log(log_module, 'INFO', 'Lifecycle ready: dataplane stable.', trace_id);
                return Success(true, 200, trace_id);
            }
        } else if (health.transient === true || (health.dataplane && health.dataplane.transient)) {
            last_detail = sprintf("transient:%s", health.grace_reason || (health.dataplane.detail || "lifecycle grace"));
            Log(log_module, 'INFO', 'Lifecycle transient observed; stable counter paused: ' + last_detail, trace_id);
        } else {
            stable_count = 0;
            last_detail = (health.dataplane && health.dataplane.detail) ? health.dataplane.detail : join(",", health.failed || []);
        }
        _sleep_barrier(trace_id);
    }

    Log(log_module, 'WARN', 'Lifecycle barrier timeout at stage=stable.', trace_id);
    let detail = "Lifecycle barrier timeout: dataplane not stable" + (last_detail ? (": " + last_detail) : "");
    return Fail(ERR.E_SYSTEM_BUSY, lifecycle_error_detail(detail), trace_id);
}

function wait_process_ready(trace_id, epoch, log_module) {
    Log(log_module, 'INFO', sprintf('Waiting process restart-only barrier epoch=%s...', epoch || "none"), trace_id);
    let pid_deadline = time() + LIFECYCLE_PID_TIMEOUT_SEC;

    while (time() < pid_deadline) {
        if (verify_process()) {
            Log(log_module, 'INFO', 'Restart-only barrier: sing-box process observed.', trace_id);
            ExecSafe(BIN.SH, ["-c", "sleep 2"], null, trace_id);
            return Success(true, 200, trace_id);
        }
        _sleep_barrier(trace_id);
    }

    Log(log_module, 'WARN', 'Restart-only barrier timeout: sing-box process not observed.', trace_id);
    return Fail(ERR.E_SYSTEM_BUSY, lifecycle_error_detail("Restart-only barrier timeout: sing-box process not observed"), trace_id);
}

export {
    begin_lifecycle_epoch,
    clear_lifecycle_protect,
    dispatch_procd_lifecycle,
    dispatch_restart_only_lifecycle,
    wait_lifecycle_ready,
    wait_process_ready
};
