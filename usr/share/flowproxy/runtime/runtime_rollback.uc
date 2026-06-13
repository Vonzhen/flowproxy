/**
 * FlowProxy | runtime/runtime_rollback.uc
 * Role: run.json rollback, rollback observation, and failure data normalization.
 */

'use strict';

import { access, stat, writefile } from 'fs';
import { PATH, BIN } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { ExecSafe } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';
import { allow_call } from 'flowproxy.core.guard';
import { execute_fallback } from 'flowproxy.system.safety';
import {
    artifact_checksum,
    artifact_info,
    preserve_failed_candidate,
    quarantine_candidate
} from 'flowproxy.runtime.runtime_artifacts';

const PATH_NETWORK_MARKER = sprintf("%s/.fp_network_ready", PATH.RUNTIME);
const PATH_APPLY_MARKER = sprintf("%s/apply.marker", PATH.RUNTIME);
const PATH_CANDIDATE_CONFIG = sprintf("%s/sing-box-run.candidate.json", PATH.RUNTIME);
const PATH_PREV_CONFIG = sprintf("%s/sing-box-run.prev.json", PATH.RUNTIME);

const RESTART_REQUEST = {
    action: "request_restart",
    skip_network_setup: true,
    need_restart: true
};

function _reason(opts, fallback) {
    opts = (type(opts) === 'object') ? opts : {};
    return opts.reason || fallback || "unknown";
}

function safe_exec(trace_id, from, to, fn) {
    allow_call(trace_id, from, to);
    return fn();
}

function mark_network_ready(trace_id) {
    writefile(PATH_NETWORK_MARKER, sprintf("%d\n", time()));
    writefile(PATH_APPLY_MARKER, sprintf("%d\n", time()));
}

function _emit_restart_request(trace_id, context) {
    log(trace_id, 'INFO', 'RUNTIME', sprintf(
        '%s: emitting request_restart (lifecycle owned by init.d/procd only)',
        context
    ));
    return Success({
        action: RESTART_REQUEST.action,
        skip_network_setup: RESTART_REQUEST.skip_network_setup,
        need_restart: RESTART_REQUEST.need_restart
    }, 200, trace_id);
}

function _bool_field(v, fallback) {
    if (v === true || v === false) return v;
    return !!fallback;
}

function _tri_bool_field(v, fallback) {
    if (v === true || v === false) return v;
    if (fallback === true || fallback === false) return fallback;
    return null;
}

function failure_stage(detail, data) {
    data = (type(data) === 'object') ? data : {};
    if (data.failed_stage) return data.failed_stage;

    let stage = data.error_stage || "";
    if (stage === "setup_new_failed") return "setup_new_mode_failed";
    if (stage === "verify_new_failed") return "verify_new_mode_failed";
    if (stage === "commit_failed") return "commit_failed";
    if (stage === "rollback_failed") return "rollback_failed";
    if (stage === "restart_process_failed") return "restart_process_failed";
    if (stage === "candidate_check_failed") return "candidate_check_failed";
    if (stage === "candidate_generation_failed") return "candidate_generation_failed";
    if (stage === "teardown_old_failed") return "teardown_old_failed";
    if (stage === "restore_prev_run_json_failed") return "restore_prev_run_json_failed";
    if (stage === "old_setup_failed") return "old_setup_failed";
    if (stage === "old_restart_failed") return "old_restart_failed";
    if (stage === "old_verify_failed") return "old_verify_failed";

    let d = sprintf("%s", detail || "");
    if (index(d, "candidate generation failed") >= 0) return "candidate_generation_failed";
    if (index(d, "candidate check failed") >= 0) return "candidate_check_failed";
    if (index(d, "mode switch candidate check failed") >= 0) return "candidate_check_failed";
    if (index(d, "backup current run.json failed") >= 0) return "commit_failed";
    if (index(d, "commit candidate run.json failed") >= 0) return "commit_failed";
    if (index(d, "Atomic run.json swap failed") >= 0) return "commit_failed";
    if (index(d, "restore previous run.json failed") >= 0) return "restore_prev_run_json_failed";
    if (index(d, "previous run.json backup missing") >= 0) return "restore_prev_run_json_failed";
    if (index(d, "rollback failed") >= 0) return "rollback_failed";
    if (index(d, "process restart") >= 0) return "restart_process_failed";
    if (index(d, "restart-only hard verify failed") >= 0) return "verify_new_mode_failed";
    if (index(d, "mode switch hard verify failed") >= 0) return "verify_new_mode_failed";
    if (index(d, "target setup failed") >= 0) return "setup_new_mode_failed";
    if (index(d, "hard verify failed") >= 0) return "verify_new_mode_failed";
    return stage || "";
}

function _derive_verify_passed(detail, data, stage) {
    if (data.verify_passed === true || data.verify_passed === false) return data.verify_passed;
    if (data.verified === true || data.verified === false) return data.verified;
    if (data.verify_hard_ok === true || data.verify_hard_ok === false) return data.verify_hard_ok;

    let s = sprintf("%s", stage || "");
    let d = sprintf("%s", detail || "");
    if (index(s, "verify") >= 0) return false;
    if (index(d, "verify failed") >= 0 || index(d, "验收失败") >= 0) return false;
    return null;
}

function normalize_failure_data(trace_id, detail, data) {
    data = (type(data) === 'object') ? data : {};
    let stage = failure_stage(detail, data);
    let rollback_attempted = _bool_field(data.rollback_attempted, false);

    if (data.rollback_success === true || data.rollback_failed === true || stage === "rollback_failed") {
        rollback_attempted = true;
    }
    if (index(sprintf("%s", detail || ""), "previous run.json restored") >= 0) {
        rollback_attempted = true;
    }

    let rollback_success = _bool_field(data.rollback_success, false);
    let rollback_failed = rollback_attempted && !rollback_success;
    if (data.rollback_failed === true) rollback_failed = true;
    if (rollback_success === true) rollback_failed = false;
    let danger_state = (data.danger_state === true) || rollback_failed;
    let manual_required = (data.manual_intervention_required === true) || danger_state || rollback_failed;
    let verify_passed = _derive_verify_passed(detail, data, stage);
    let current_mode = data.current_known_mode || data.new_mode || artifact_info(PATH.RUN_JSON).mode || "unknown";
    let expected_mode = data.expected_safe_mode || data.old_mode || data.restored_mode || "unknown";

    data.rollback_attempted = rollback_attempted;
    data.rollback_success = rollback_success;
    data.rollback_failed = rollback_failed;
    data.manual_intervention_required = manual_required;
    data.danger_state = danger_state;
    data.failed_stage = stage;
    data.error_stage = data.error_stage || stage || "";
    data.verify_passed = _tri_bool_field(data.verify_passed, verify_passed);
    data.current_known_mode = current_mode;
    data.expected_safe_mode = expected_mode;
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

function log_rollback_observation(trace_id, stage, data, log_module) {
    data = (type(data) === 'object') ? data : {};
    log(trace_id, 'WARN', log_module || 'RUNTIME', sprintf(
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
    ));
}

function restore_prev_run_json(trace_id, bak_path) {
    let src = bak_path || PATH_PREV_CONFIG;
    if (!access(src)) {
        log(trace_id, 'ERROR', 'RUNTIME', sprintf('rollback_result=fail prev_path=%s detail=missing', src));
        let fail_res = Fail(ERR.E_SYSTEM_BUSY, "previous run.json backup missing: " + src, trace_id);
        fail_res.data = normalize_failure_data(trace_id, fail_res.detail, {
            rollback_attempted: true,
            rollback_success: false,
            rollback_failed: true,
            manual_intervention_required: true,
            danger_state: true,
            failed_stage: "restore_prev_run_json_failed",
            restored_run_json: false,
            old_dataplane_setup: false,
            old_setup_failed: false,
            old_process_restarted: false,
            old_restart_failed: false,
            old_verify_ok: false,
            old_verify_failed: false
        });
        log_rollback_observation(trace_id, "restore_old_run_json_result", fail_res.data);
        return fail_res;
    }

    let res = ExecSafe(BIN.CP, ["-f", src, PATH.RUN_JSON], null, trace_id);
    if (!res.ok) {
        log(trace_id, 'ERROR', 'RUNTIME', sprintf('rollback_result=fail prev_path=%s detail=%s', src, res.detail || "unknown"));
        let fail_res = Fail(ERR.E_SYSTEM_BUSY, "restore previous run.json failed: " + res.detail, trace_id);
        fail_res.data = normalize_failure_data(trace_id, fail_res.detail, {
            rollback_attempted: true,
            rollback_success: false,
            rollback_failed: true,
            manual_intervention_required: true,
            danger_state: true,
            failed_stage: "restore_prev_run_json_failed",
            restored_run_json: false,
            old_dataplane_setup: false,
            old_setup_failed: false,
            old_process_restarted: false,
            old_restart_failed: false,
            old_verify_ok: false,
            old_verify_failed: false
        });
        log_rollback_observation(trace_id, "restore_old_run_json_result", fail_res.data);
        return fail_res;
    }

    log(trace_id, 'WARN', 'RUNTIME', sprintf(
        'rollback run.json success rollback_result=success prev_path=%s prev_checksum=%s commit_path=%s commit_checksum=%s',
        src,
        artifact_checksum(src, trace_id),
        PATH.RUN_JSON,
        artifact_checksum(PATH.RUN_JSON, trace_id)
    ));
    log_rollback_observation(trace_id, "restore_old_run_json_result", {
        rollback_attempted: true,
        restored_run_json: true,
        current_known_mode: artifact_info(PATH.RUN_JSON).mode,
        rollback_detail: "previous run.json restored"
    });
    return Success(true, 200, trace_id);
}

function commit_candidate_run_json(trace_id, bak_path) {
    if (access(PATH.RUN_JSON)) {
        let bak_res = ExecSafe(BIN.CP, ["-f", PATH.RUN_JSON, bak_path], null, trace_id);
        if (!bak_res.ok) {
            let res = Fail(ERR.E_SYSTEM_BUSY, "backup current run.json failed: " + bak_res.detail, trace_id);
            res.data = normalize_failure_data(trace_id, res.detail, {
                rollback_attempted: false,
                rollback_success: false,
                config_committed: false,
                failed_stage: "commit_failed"
            });
            return res;
        }
        log(trace_id, 'INFO', 'RUNTIME', sprintf(
            'prev_path=%s prev_checksum=%s',
            bak_path,
            artifact_checksum(bak_path, trace_id)
        ));
    }

    let swap_res = ExecSafe(BIN.CP, ["-f", PATH_CANDIDATE_CONFIG, PATH.RUN_JSON], null, trace_id);
    if (!swap_res.ok) {
        let rb = access(bak_path) ? restore_prev_run_json(trace_id, bak_path) : null;
        let res = Fail(ERR.E_SYSTEM_BUSY, "commit candidate run.json failed: " + swap_res.detail, trace_id);
        res.data = normalize_failure_data(trace_id, res.detail, {
            config_committed: false,
            rollback_attempted: !!rb,
            rollback_success: rb ? !!rb.ok : false,
            rollback_failed: !!(rb && !rb.ok),
            failed_stage: "commit_failed"
        });
        return res;
    }

    log(trace_id, 'INFO', 'RUNTIME', sprintf(
        'commit run.json path=%s commit_path=%s commit_checksum=%s candidate_path=%s restart_result=requested',
        PATH.RUN_JSON,
        PATH.RUN_JSON,
        artifact_checksum(PATH.RUN_JSON, trace_id),
        PATH_CANDIDATE_CONFIG
    ));
    return Success(true, 200, trace_id);
}

function rollback_commit(trace_id, bak_path, opts) {
    let reason = _reason(opts, "rollback");
    let src = bak_path || PATH_PREV_CONFIG;
    let src_stat = stat(src);

    if (!src || !src_stat || !src_stat.size) {
        let detail = "rollback previous run.json backup missing or empty: " + (src || "(none)");
        log(trace_id, 'ERROR', 'RUNTIME', detail);
        let fail_res = Fail(ERR.E_SYSTEM_BUSY, detail, trace_id);
        fail_res.data = normalize_failure_data(trace_id, detail, {
            rollback_attempted: true,
            rollback_success: false,
            rollback_failed: true,
            manual_intervention_required: true,
            danger_state: true,
            failed_stage: "restore_prev_run_json_failed",
            restored_run_json: false
        });
        log_rollback_observation(trace_id, "restore_old_run_json_result", fail_res.data);
        return fail_res;
    }

    let restore_res = ExecSafe(BIN.CP, ["-f", src, PATH.RUN_JSON], null, trace_id);
    let dst_stat = stat(PATH.RUN_JSON);
    if (!restore_res.ok || !dst_stat || !dst_stat.size) {
        let detail = "restore previous run.json failed: " + (restore_res.ok ? "restored file missing or empty" : restore_res.detail);
        log(trace_id, 'ERROR', 'RUNTIME', detail);
        let fail_res = Fail(ERR.E_SYSTEM_BUSY, detail, trace_id);
        fail_res.data = normalize_failure_data(trace_id, detail, {
            rollback_attempted: true,
            rollback_success: false,
            rollback_failed: true,
            manual_intervention_required: true,
            danger_state: true,
            failed_stage: "restore_prev_run_json_failed",
            restored_run_json: false
        });
        log_rollback_observation(trace_id, "restore_old_run_json_result", fail_res.data);
        return fail_res;
    }

    log_rollback_observation(trace_id, "restore_old_run_json_result", {
        rollback_attempted: true,
        rollback_success: true,
        rollback_failed: false,
        manual_intervention_required: false,
        danger_state: false,
        restored_run_json: true,
        current_known_mode: artifact_info(PATH.RUN_JSON).mode,
        rollback_detail: "previous run.json restored"
    });

    log(trace_id, 'WARN', 'RUNTIME', '[ROLLBACK] rollback_commit delegated cleanup to fallback reason=' + reason);
    safe_exec(trace_id, 'runtime', 'system.safety.fallback', () => execute_fallback(trace_id, { reason: "fallback" }));

    quarantine_candidate(trace_id);

    mark_network_ready(trace_id);
    let restart_res = _emit_restart_request(trace_id, 'rollback_commit');
    if (restart_res && restart_res.ok) {
        restart_res.data = (type(restart_res.data) === 'object') ? restart_res.data : {};
        restart_res.data.restored_run_json = true;
        restart_res.data.rollback_attempted = true;
        restart_res.data.rollback_success = true;
        restart_res.data.rollback_failed = false;
        restart_res.data.danger_state = false;
        restart_res.data.manual_intervention_required = false;
        restart_res.data.verify_passed = null;
    }
    return restart_res;
}

export {
    failure_stage,
    normalize_failure_data,
    log_rollback_observation,
    restore_prev_run_json,
    commit_candidate_run_json,
    rollback_commit
};
