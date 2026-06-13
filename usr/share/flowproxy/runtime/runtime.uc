/**
 * FlowProxy | runtime/runtime.uc | v1.5 (Orchestrator-Only Edition)
 * 职责：数据面事务编排（generate / check / network.setup / verify）。
 * 边界：禁止 shell stop/restart；进程生命周期仅 emit request_restart，由 init.d/procd 执行。
 */

'use strict';

/**
 * 0. Imports / Constants
 */

import { writefile, unlink, access, readfile, stat } from 'fs';
import { PATH, BIN } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { ExecSafe } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';
import { allow_call } from 'flowproxy.core.guard';
import { setup, teardown } from 'flowproxy.system.network';
import { inject_bypass, execute_fallback } from 'flowproxy.system.safety';
import { check, verify_after_reload } from 'flowproxy.runtime.launcher';
import { verify_process } from 'flowproxy.runtime.healthcheck';
import {
    safe_artifact_id as artifacts_safe_artifact_id,
    shell_path as artifacts_shell_path,
    artifact_checksum as artifacts_artifact_checksum,
    artifact_info as artifacts_artifact_info,
    log_artifact as artifacts_log_artifact,
    preserve_failed_candidate as artifacts_preserve_failed_candidate,
    quarantine_candidate as artifacts_quarantine_candidate
} from 'flowproxy.runtime.runtime_artifacts';
import {
    load_json_config as verify_load_json_config,
    find_inbound as verify_find_inbound,
    run_json_mode as verify_run_json_mode,
    core_listener_inbound as verify_core_listener_inbound,
    core_listener_port as verify_core_listener_port,
    verify_listen_port as verify_verify_listen_port,
    verify_tun_up as verify_verify_tun_up,
    verify_proxy_curl as verify_verify_proxy_curl,
    verify_restart_only_runtime as verify_verify_restart_only_runtime
} from 'flowproxy.runtime.runtime_verify';
import {
    failure_stage as rollback_failure_stage,
    normalize_failure_data as rollback_normalize_failure_data,
    log_rollback_observation as rollback_log_rollback_observation,
    restore_prev_run_json as rollback_restore_prev_run_json,
    commit_candidate_run_json as rollback_commit_candidate_run_json,
    rollback_commit as rollback_runtime_commit
} from 'flowproxy.runtime.runtime_rollback';

const PATH_NETWORK_MARKER = sprintf("%s/.fp_network_ready", PATH.RUNTIME);
const PATH_APPLY_MARKER = sprintf("%s/apply.marker", PATH.RUNTIME);
const PATH_CANDIDATE_CONFIG = sprintf("%s/sing-box-run.candidate.json", PATH.RUNTIME);
const PATH_PREV_CONFIG = sprintf("%s/sing-box-run.prev.json", PATH.RUNTIME);
const PATH_FAILED_CONFIG = sprintf("%s/sing-box-run.failed.json", PATH.RUNTIME);
const PATH_FAILED_CONFIG_DIR = sprintf("%s/failed", PATH.RUNTIME);

const RESTART_REQUEST = {
    action: "request_restart",
    skip_network_setup: true,
    need_restart: true
};

/**
 * 1. Common Helpers
 */

function safe_exec(trace_id, from, to, fn) {
    allow_call(trace_id, from, to);
    return fn();
}

function _reason(opts, fallback) {
    opts = (type(opts) === 'object') ? opts : {};
    return opts.reason || fallback || "unknown";
}

function _gc_policy(opts, fallback) {
    opts = (type(opts) === 'object') ? opts : {};
    return opts.gc_policy || fallback || "auto";
}

function _dfa_emit(dfa_cb, state, progress, err) {
    if (type(dfa_cb) === 'function') {
        dfa_cb(state, progress, err);
    }
}

/**
 * 2. Marker Helpers
 */

function mark_network_ready(trace_id) {
    writefile(PATH_NETWORK_MARKER, sprintf("%d\n", time()));
    writefile(PATH_APPLY_MARKER, sprintf("%d\n", time()));
}

function clear_network_marker(trace_id) {
    unlink(PATH_NETWORK_MARKER);
}

function is_network_marker_set() {
    return access(PATH_NETWORK_MARKER);
}

/**
 * 3. Artifact Helpers
 */

function _safe_artifact_id(trace_id) {
    return artifacts_safe_artifact_id(trace_id);
}

function _shell_path(path) {
    return artifacts_shell_path(path);
}

function _artifact_checksum(path, trace_id) {
    return artifacts_artifact_checksum(path, trace_id);
}

function _artifact_info(path) {
    return artifacts_artifact_info(path);
}

function _bool_field(v, fallback) {
    if (v === true || v === false) return v;
    return !!fallback;
}

function _failure_stage(detail, data) {
    return rollback_failure_stage(detail, data);
}

function _normalize_failure_data(trace_id, detail, data) {
    return rollback_normalize_failure_data(trace_id, detail, data);
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

function _log_rollback_observation(trace_id, stage, data) {
    return rollback_log_rollback_observation(trace_id, stage, data);
}

function _log_artifact(trace_id, label, path) {
    return artifacts_log_artifact(trace_id, label, path);
}

function _preserve_failed_candidate(trace_id, reason) {
    return artifacts_preserve_failed_candidate(trace_id, reason);
}

function _quarantine_candidate(trace_id) {
    return artifacts_quarantine_candidate(trace_id);
}

/**
 * Restore the previous committed run.json artifact.
 */
function _restore_prev_run_json(trace_id, bak_path) {
    return rollback_restore_prev_run_json(trace_id, bak_path);
}

function _commit_candidate_run_json(trace_id, bak_path) {
    return rollback_commit_candidate_run_json(trace_id, bak_path);
}

/**
 * 4. Config / Runtime Inspect Helpers
 */

function _load_json_config(path) {
    return verify_load_json_config(path);
}

function _find_inbound(cfg, inbound_type, tag) {
    return verify_find_inbound(cfg, inbound_type, tag);
}

function _run_json_mode(cfg) {
    return verify_run_json_mode(cfg);
}

function _core_listener_inbound(cfg) {
    return verify_core_listener_inbound(cfg);
}

function _core_listener_port(cfg) {
    return verify_core_listener_port(cfg);
}

/**
 * 5. Runtime Verify Helpers
 */

function _verify_listen_port(port) {
    return verify_verify_listen_port(port);
}

function _verify_tun_up(tun_in) {
    return verify_verify_tun_up(tun_in);
}

function _verify_proxy_curl(trace_id, port) {
    return verify_verify_proxy_curl(trace_id, port);
}

function _verify_restart_only_runtime(trace_id) {
    return verify_verify_restart_only_runtime(trace_id);
}

/**
 * 6. Network Apply / Rollback Helpers
 */

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

function apply_commit(trace_id, opts) {
    let reason = _reason(opts, "legacy_dataplane_reload");
    let gc_policy = _gc_policy(opts, "force");
    let setup_res = safe_exec(trace_id, 'runtime', 'system.network.setup', () => setup(trace_id, { reason: reason, gc_policy: gc_policy }));
    if (!setup_res || !setup_res.ok) {
        return Fail(ERR.E_SYSTEM_BUSY, "network.setup failed: " + (setup_res ? setup_res.detail : "unknown"), trace_id);
    }

    mark_network_ready(trace_id);
    return _emit_restart_request(trace_id, 'apply_commit');
}

/*
 * rollback_commit restores the previous run.json before physical fallback and
 * restart request. If the backup cannot be restored, it returns danger_state.
 */
/**
 * 事务回滚：teardown + fallback + 恢复配置 + 重载请求（不触达 init.d/procd）
 */
function rollback_commit(trace_id, bak_path, opts) {
    return rollback_runtime_commit(trace_id, bak_path, opts);
}

/**
 * 冷启动 / init.d：仅 network.setup（generate 由 init.d 或 validating 阶段完成）
 */
function setup_network_only(trace_id, opts) {
    let reason = _reason(opts, "setup_network_only");
    let gc_policy = _gc_policy(opts, "auto");
    let setup_res = safe_exec(trace_id, 'runtime', 'system.network.setup', () => setup(trace_id, { reason: reason, gc_policy: gc_policy }));
    if (!setup_res || !setup_res.ok) {
        return Fail(ERR.E_SYSTEM_BUSY, "network.setup failed: " + (setup_res ? setup_res.detail : "unknown"), trace_id);
    }
    return Success(true, 200, trace_id);
}

function teardown_network_only(trace_id, opts) {
    let reason = _reason(opts, "teardown_network_only");
    opts = (type(opts) === 'object') ? opts : {};
    let mode = opts.mode || "auto";
    let no_run_json_policy = opts.no_run_json_policy || "teardown_both";
    let teardown_res = safe_exec(trace_id, 'runtime', 'system.network.teardown', () => teardown(trace_id, {
        reason: reason,
        mode: mode,
        no_run_json_policy: no_run_json_policy
    }));
    clear_network_marker(trace_id);
    if (!teardown_res || !teardown_res.ok) {
        return Fail(ERR.E_SYSTEM_BUSY, "network.teardown failed: " + (teardown_res ? teardown_res.detail : "unknown"), trace_id);
    }
    return Success(true, 200, trace_id);
}

/**
 * 7. Transaction Failure Helpers
 */

function _is_business_reload_job(job_type) {
    return job_type === 'update_assets' || job_type === 'update_subscriptions' || job_type === 'rebuild_groups';
}

function _fail_dataplane(trace_id, dfa_cb, bak_path, progress_rb, progress_fail, detail, do_network_rollback, data) {
    let rb = null;
    if (do_network_rollback && bak_path) {
        rb = rollback_commit(trace_id, bak_path, { reason: "rollback" });
    }
    _dfa_emit(dfa_cb, "rollback", progress_rb, detail);
    _dfa_emit(dfa_cb, "fail", progress_fail, detail);
    let fail_res = Fail(ERR.E_SYSTEM_BUSY, detail, trace_id);
    let failure_data = {
        rollback_attempted: !!(do_network_rollback && bak_path),
        rollback_success: !!(rb && rb.ok),
        rollback_failed: !!(do_network_rollback && bak_path && (!rb || !rb.ok)),
        manual_intervention_required: !!(do_network_rollback && bak_path && (!rb || !rb.ok)),
        danger_state: !!(do_network_rollback && bak_path && (!rb || !rb.ok)),
        runtime_applied: false
    };
    if (type(data) === 'object') {
        for (let k in data) failure_data[k] = data[k];
    }
    fail_res.data = _normalize_failure_data(trace_id, detail, failure_data);
    if (do_network_rollback && is_network_marker_set()) {
        fail_res.need_restart = true;
    }
    return fail_res;
}

function _fail_process_reload(trace_id, dfa_cb, progress, detail, data) {
    _dfa_emit(dfa_cb, "fail", progress, detail);
    let fail_res = Fail(ERR.E_SYSTEM_BUSY, detail, trace_id);
    fail_res.data = _normalize_failure_data(trace_id, detail, data || {
        config_committed: false,
        runtime_applied: false,
        rollback_success: false
    });
    return fail_res;
}

/**
 * 8. Transaction Verify Phases
 */

function _run_verify_phase(trace_id, job_type, dfa_cb, bak_path) {
    _dfa_emit(dfa_cb, "committing", 85, null);
    log(trace_id, 'INFO', 'RUNTIME', '[verify_only] dataplane_verify after lifecycle');

    let dp = verify_after_reload(trace_id, {
        allow_transient: true,
        min_settle_sec: 8,
        timeout_sec: 75,
        stable_samples: 2
    });
    log(trace_id, 'INFO', 'RUNTIME', sprintf(
        "dataplane_verify ok=%s error=%s detail=%s",
        dp.ok, dp.error || "", dp.detail || ""
    ));

    if (!dp.ok) {
        let verify_detail = sprintf("%s: %s", dp.error || "dataplane_incomplete", dp.detail || "unknown");
        return _fail_dataplane(trace_id, dfa_cb, bak_path, 90, 95, "数据面验收失败: " + verify_detail, true);
    }

    clear_network_marker(trace_id);
    log(trace_id, 'INFO', 'RUNTIME', 'Dataplane transaction complete.');
    return Success({ verified: true, verify_passed: true }, 200, trace_id);
}

function _run_process_verify_phase(trace_id, job_type, dfa_cb, bak_path) {
    _dfa_emit(dfa_cb, "committing", 85, null);
    log(trace_id, 'INFO', 'RUNTIME', '[restart_only:verify] mode-aware hard/soft verify');

    let core = _verify_restart_only_runtime(trace_id);
    if (core.hard_ok) {
        if (length(core.soft_warnings || []) > 0) {
            log(trace_id, 'WARN', 'RUNTIME', 'verify_result=success restart-only verify soft warning; runtime kept');
        } else {
            log(trace_id, 'INFO', 'RUNTIME', 'verify_result=success restart-only hard verify success');
        }
        return Success({
            verified: true,
            config_committed: true,
            runtime_applied: true,
            rollback_success: false,
            rollback_failed: false,
            danger_state: false,
            manual_intervention_required: false,
            verify_passed: true,
            verify_hard_ok: true,
            curl_ok: core.curl_ok,
            soft_warnings: core.soft_warnings || [],
            core_proxy: core
        }, 200, trace_id);
    }

    log(trace_id, 'WARN', 'RUNTIME', 'verify_result=fail restart-only hard verify failed; preserving failed candidate and restoring previous run.json');
    let failed_candidate = _preserve_failed_candidate(trace_id, "restart_only_hard_verify_failed");
    let rb = _restore_prev_run_json(trace_id, bak_path || PATH_PREV_CONFIG);
    if (!rb.ok) {
        log(trace_id, 'ERROR', 'RUNTIME', 'rollback run.json failed: ' + rb.detail);
        return _fail_process_reload(trace_id, dfa_cb, 95, "restart-only hard verify failed and rollback failed: " + rb.detail, {
            config_committed: true,
            runtime_applied: false,
            rollback_success: false,
            verify_passed: false,
            verify_hard_ok: false,
            curl_ok: core.curl_ok,
            soft_warnings: core.soft_warnings || [],
            core_proxy: core,
            failed_candidate: failed_candidate || ""
        });
    }

    let fail_res = _fail_process_reload(trace_id, dfa_cb, 95, "restart-only hard verify failed; previous run.json restored", {
        config_committed: true,
        runtime_applied: false,
        rollback_success: true,
        verify_passed: false,
        verify_hard_ok: false,
        curl_ok: core.curl_ok,
        soft_warnings: core.soft_warnings || [],
        core_proxy: core,
        failed_candidate: failed_candidate || ""
    });
    fail_res.need_restart = true;
    return fail_res;
}

/**
 * 9. Mode Switch Helpers
 */

function _is_switchable_mode(mode) {
    return mode === "tun" || mode === "redirect_tproxy";
}

function _detect_mode_switch(trace_id) {
    let old_info = _artifact_info(PATH.RUN_JSON);
    let new_info = _artifact_info(PATH_CANDIDATE_CONFIG);
    let old_mode = old_info.mode || "unknown";
    let new_mode = new_info.mode || "unknown";

    if (_is_switchable_mode(old_mode) && _is_switchable_mode(new_mode) && old_mode !== new_mode) {
        log(trace_id, 'WARN', 'RUNTIME', sprintf(
            'mode_switch_detected old_mode=%s new_mode=%s candidate_path=%s',
            old_mode,
            new_mode,
            PATH_CANDIDATE_CONFIG
        ));
        return {
            required: true,
            old_mode: old_mode,
            new_mode: new_mode
        };
    }

    return {
        required: false,
        old_mode: old_mode,
        new_mode: new_mode
    };
}

function _setup_mode(trace_id, mode, reason) {
    if (!_is_switchable_mode(mode)) {
        return Fail(ERR.E_SYSTEM_BUSY, "unsupported setup mode: " + (mode || "unknown"), trace_id);
    }
    return safe_exec(trace_id, 'runtime', 'system.network.setup', () => setup(trace_id, {
        reason: reason || "mode_switch",
        mode: mode
    }));
}

function _teardown_mode(trace_id, mode, reason) {
    if (!_is_switchable_mode(mode)) {
        return Fail(ERR.E_SYSTEM_BUSY, "unsupported teardown mode: " + (mode || "unknown"), trace_id);
    }
    return safe_exec(trace_id, 'runtime', 'system.network.teardown', () => teardown(trace_id, {
        reason: reason || "mode_switch",
        mode: mode
    }));
}

function _log_mode_switch_stage(trace_id, stage, detail) {
    log(trace_id, 'WARN', 'RUNTIME', sprintf(
        'mode_switch stage=%s%s',
        stage || "unknown",
        detail ? (" " + detail) : ""
    ));
}

function _run_mode_switch_rollback(trace_id, bak_path, old_mode, reason, cleanup_mode) {
    _log_rollback_observation(trace_id, "mode_switch_rollback_begin", {
        rollback_attempted: true,
        old_mode: old_mode || "unknown",
        new_mode: cleanup_mode || "unknown",
        current_known_mode: cleanup_mode || "unknown",
        expected_safe_mode: old_mode || "unknown",
        rollback_detail: reason || "mode_switch_rollback"
    });
    _log_mode_switch_stage(trace_id, "rollback_restore_prev", sprintf(
        "old_mode=%s cleanup_mode=%s reason=%s",
        old_mode || "unknown",
        cleanup_mode || "unknown",
        reason || "unknown"
    ));
    _preserve_failed_candidate(trace_id, reason || "mode_switch_rollback");
    let rb = _restore_prev_run_json(trace_id, bak_path || PATH_PREV_CONFIG);
    if (!rb.ok) {
        _log_rollback_observation(trace_id, "rollback_runtime_state", rb.data);
        return rb;
    }
    let restored_run_json = true;

    let cleanup = cleanup_mode || old_mode;
    if (_is_switchable_mode(cleanup)) {
        _log_mode_switch_stage(trace_id, "rollback_teardown_new", "mode=" + cleanup);
        let teardown_res = _teardown_mode(trace_id, cleanup, "rollback");
        _log_rollback_observation(trace_id, "teardown_new_result", {
            rollback_attempted: true,
            old_mode: old_mode || "unknown",
            new_mode: cleanup || "unknown",
            current_known_mode: cleanup || "unknown",
            expected_safe_mode: old_mode || "unknown",
            rollback_detail: teardown_res && teardown_res.ok ? "teardown new mode success" : (teardown_res ? teardown_res.detail : "teardown new mode result unknown")
        });
    }

    if (_is_switchable_mode(old_mode)) {
        _log_mode_switch_stage(trace_id, "rollback_setup_old", "mode=" + old_mode);
        let setup_res = _setup_mode(trace_id, old_mode, "rollback");
        if (!setup_res || !setup_res.ok) {
            let fail_res = Fail(ERR.E_SYSTEM_BUSY, "rollback network.setup failed: " + (setup_res ? setup_res.detail : "unknown"), trace_id);
            fail_res.data = _normalize_failure_data(trace_id, fail_res.detail, {
                rollback_attempted: true,
                rollback_success: false,
                rollback_failed: true,
                manual_intervention_required: true,
                danger_state: true,
                failed_stage: "old_setup_failed",
                expected_safe_mode: old_mode || "unknown",
                restored_mode: old_mode || "unknown",
                restored_run_json: restored_run_json,
                old_dataplane_setup: false,
                old_setup_failed: true,
                old_process_restarted: false,
                old_restart_failed: false,
                old_verify_ok: false,
                old_verify_failed: false
            });
            _log_rollback_observation(trace_id, "setup_old_dataplane_result", fail_res.data);
            _log_rollback_observation(trace_id, "rollback_runtime_state", fail_res.data);
            return fail_res;
        }
        _log_rollback_observation(trace_id, "setup_old_dataplane_result", {
            rollback_attempted: true,
            old_mode: old_mode || "unknown",
            current_known_mode: old_mode || "unknown",
            expected_safe_mode: old_mode || "unknown",
            restored_run_json: restored_run_json,
            old_dataplane_setup: true,
            rollback_detail: "old dataplane setup success"
        });
    }
    clear_network_marker(trace_id);
    _log_mode_switch_stage(trace_id, "rollback_success", "old_mode=" + (old_mode || "unknown"));
    let data = {
        rollback_attempted: true,
        rollback_success: true,
        rollback_failed: false,
        manual_intervention_required: false,
        danger_state: false,
        restored_mode: old_mode || "unknown",
        restored_run_json: restored_run_json,
        old_dataplane_setup: _is_switchable_mode(old_mode),
        old_process_restarted: false,
        old_verify_ok: false,
        current_known_mode: old_mode || "unknown",
        expected_safe_mode: old_mode || "unknown"
    };
    _log_rollback_observation(trace_id, "rollback_runtime_state", data);
    return Success(data, 200, trace_id);
}

function _run_mode_switch_verify_phase(trace_id, dfa_cb, opts) {
    opts = (type(opts) === 'object') ? opts : {};
    let old_mode = opts.old_mode || "unknown";
    let new_mode = opts.new_mode || "unknown";
    let bak_path = opts.bak_path || PATH_PREV_CONFIG;

    _dfa_emit(dfa_cb, "committing", 85, null);
    log(trace_id, 'INFO', 'RUNTIME', sprintf('[mode_switch:verify] old_mode=%s new_mode=%s', old_mode, new_mode));

    _log_mode_switch_stage(trace_id, "setup_new", sprintf("old_mode=%s new_mode=%s", old_mode, new_mode));
    log(trace_id, 'INFO', 'RUNTIME', '[mode_switch:verify] setting up target dataplane mode=' + new_mode);
    let setup_res = _setup_mode(trace_id, new_mode, "mode_switch");
    if (!setup_res || !setup_res.ok) {
        _log_mode_switch_stage(trace_id, "setup_new_failed", sprintf("old_mode=%s new_mode=%s", old_mode, new_mode));
        log(trace_id, 'WARN', 'RUNTIME', 'mode_switch target setup failed; restoring previous run.json');
        let rb = _run_mode_switch_rollback(trace_id, bak_path, old_mode, "mode_switch_target_setup_failed", new_mode);
        let rb_data = (rb && type(rb.data) === 'object') ? rb.data : {};
        let fail_res = _fail_process_reload(trace_id, dfa_cb, 95, "mode switch target setup failed: " + (setup_res ? setup_res.detail : "unknown"), {
            mode_switch_applied: false,
            old_mode: old_mode,
            new_mode: new_mode,
            config_committed: true,
            runtime_applied: false,
            dataplane_touched: true,
            verify_passed: false,
            rollback_attempted: true,
            rollback_success: !!(rb && rb.ok),
            rollback_failed: !!(rb && !rb.ok),
            manual_intervention_required: !!(rb && !rb.ok),
            danger_state: !!(rb && !rb.ok),
            restored_mode: rb_data.restored_mode || old_mode,
            restored_run_json: rb_data.restored_run_json === true,
            old_dataplane_setup: rb_data.old_dataplane_setup === true,
            old_setup_failed: rb_data.old_setup_failed === true,
            old_process_restarted: false,
            old_verify_ok: false,
            verify_hard_ok: false,
            error_stage: "setup_new_failed"
        });
        fail_res.need_restart = true;
        return fail_res;
    }

    mark_network_ready(trace_id);

    _log_mode_switch_stage(trace_id, "verify_new", sprintf("old_mode=%s new_mode=%s", old_mode, new_mode));
    let core = _verify_restart_only_runtime(trace_id);
    if (!core.hard_ok) {
        _log_mode_switch_stage(trace_id, "verify_new_failed", sprintf("old_mode=%s new_mode=%s", old_mode, new_mode));
        log(trace_id, 'WARN', 'RUNTIME', 'mode_switch hard verify failed; restoring previous run.json');
        let rb = _run_mode_switch_rollback(trace_id, bak_path, old_mode, "mode_switch_hard_verify_failed", new_mode);
        let rb_data = (rb && type(rb.data) === 'object') ? rb.data : {};
        let fail_res = _fail_process_reload(trace_id, dfa_cb, 95, "mode switch hard verify failed; previous run.json restored", {
            mode_switch_applied: false,
            old_mode: old_mode,
            new_mode: new_mode,
            config_committed: true,
            runtime_applied: false,
            dataplane_touched: true,
            verify_passed: false,
            rollback_attempted: true,
            rollback_success: !!(rb && rb.ok),
            rollback_failed: !!(rb && !rb.ok),
            manual_intervention_required: !!(rb && !rb.ok),
            danger_state: !!(rb && !rb.ok),
            restored_mode: rb_data.restored_mode || old_mode,
            restored_run_json: rb_data.restored_run_json === true,
            old_dataplane_setup: rb_data.old_dataplane_setup === true,
            old_setup_failed: rb_data.old_setup_failed === true,
            old_process_restarted: false,
            old_verify_ok: false,
            verify_hard_ok: false,
            curl_ok: core.curl_ok,
            soft_warnings: core.soft_warnings || [],
            core_proxy: core,
            error_stage: "verify_new_failed"
        });
        fail_res.need_restart = true;
        return fail_res;
    }

    if (length(core.soft_warnings || []) > 0) {
        log(trace_id, 'WARN', 'RUNTIME', 'mode_switch verify soft warning; runtime kept');
    }
    _log_mode_switch_stage(trace_id, "success", sprintf("old_mode=%s new_mode=%s", old_mode, new_mode));
    log(trace_id, 'INFO', 'RUNTIME', sprintf(
        'mode_switch_apply success old_mode=%s new_mode=%s setup_after_restart=%s',
        old_mode,
        new_mode,
        "true"
    ));
    return Success({
        mode_switch_applied: true,
        old_mode: old_mode,
        new_mode: new_mode,
        config_committed: true,
        runtime_applied: true,
        dataplane_touched: true,
        rollback_success: false,
        rollback_failed: false,
        danger_state: false,
        manual_intervention_required: false,
        verify_passed: true,
        verify_hard_ok: true,
        curl_ok: core.curl_ok,
        soft_warnings: core.soft_warnings || [],
        setup_after_restart: true,
        mode_switch: true,
        core_proxy: core
    }, 200, trace_id);
}

/**
 * 10. Public Transaction Entries
 */

function run_process_reload(trace_id, job_type, dfa_cb, opts) {
    opts = opts || {};
    let phase = opts.phase || "prepare";
    let bak_path = opts.bak_path || PATH_PREV_CONFIG;

    if (phase === "verify_only") {
        return _run_process_verify_phase(trace_id, job_type, dfa_cb, bak_path);
    }
    if (phase === "rollback") {
        _preserve_failed_candidate(trace_id, "explicit_process_rollback");
        return _restore_prev_run_json(trace_id, bak_path);
    }

    let gateway_script = sprintf("%s/runtime/generate.uc", PATH.BASE);

    _dfa_emit(dfa_cb, "validating", 40, null);
    log(trace_id, 'INFO', 'RUNTIME', '[restart_only:prepare] generate + sing-box check');

    ExecSafe(BIN.RM, ["-f", PATH_CANDIDATE_CONFIG], null, trace_id);

    let gen_res = ExecSafe(BIN.UCODE, [gateway_script, PATH_CANDIDATE_CONFIG], null, trace_id);
    if (!gen_res.ok) {
        return _fail_process_reload(trace_id, dfa_cb, 55, "candidate generation failed: " + gen_res.detail, {
            config_committed: false,
            runtime_applied: false,
            rollback_success: false
        });
    }
    _log_artifact(trace_id, 'candidate', PATH_CANDIDATE_CONFIG);

    let check_res = check(PATH_CANDIDATE_CONFIG, { caller: 'runtime.manager' }, trace_id);
    if (!check_res.ok) {
        let failed_path = _quarantine_candidate(trace_id);
        log(trace_id, 'WARN', 'RUNTIME', 'check_result=fail candidate check failed; bad candidate quarantined at: ' + (failed_path || "(none)"));
        return _fail_process_reload(trace_id, dfa_cb, 60, "candidate check failed: " + check_res.detail, {
            config_committed: false,
            runtime_applied: false,
            rollback_success: false,
            failed_artifact: failed_path || ""
        });
    }
    log(trace_id, 'INFO', 'RUNTIME', sprintf(
        'check_result=success candidate_path=%s candidate_checksum=%s',
        PATH_CANDIDATE_CONFIG,
        _artifact_checksum(PATH_CANDIDATE_CONFIG, trace_id)
    ));

    let mode_switch = _detect_mode_switch(trace_id);
    if (mode_switch.required) {
        log(trace_id, 'WARN', 'RUNTIME', sprintf(
            'action=backend_mode_switch run_mode=%s candidate_mode=%s',
            mode_switch.old_mode || "unknown",
            mode_switch.new_mode || "unknown"
        ));
        let res = Fail(ERR.E_SYSTEM_BUSY, "mode switch apply required", trace_id);
        res.data = {
            backend_mode_switch: true,
            old_mode: mode_switch.old_mode,
            new_mode: mode_switch.new_mode,
            next_action: "backend_mode_switch_lifecycle",
            candidate_path: PATH_CANDIDATE_CONFIG,
            runtime_applied: false,
            config_committed: false,
            dataplane_touched: false,
            verify_passed: null,
            need_restart: false
        };
        return res;
    }
    log(trace_id, 'INFO', 'RUNTIME', sprintf(
        'action=commit run_mode=%s candidate_mode=%s',
        mode_switch.old_mode || "unknown",
        mode_switch.new_mode || "unknown"
    ));

    if (access(PATH.RUN_JSON)) {
        let bak_res = ExecSafe(BIN.CP, ["-f", PATH.RUN_JSON, bak_path], null, trace_id);
        if (!bak_res.ok) {
            return _fail_process_reload(trace_id, dfa_cb, 65, "backup current run.json failed: " + bak_res.detail, {
                config_committed: false,
                runtime_applied: false,
                rollback_success: false
            });
        }
        log(trace_id, 'INFO', 'RUNTIME', sprintf(
            'prev_path=%s prev_checksum=%s',
            bak_path,
            _artifact_checksum(bak_path, trace_id)
        ));
    }

    let swap_res = ExecSafe(BIN.CP, ["-f", PATH_CANDIDATE_CONFIG, PATH.RUN_JSON], null, trace_id);
    if (!swap_res.ok) {
        let rb = access(bak_path) ? _restore_prev_run_json(trace_id, bak_path) : null;
        return _fail_process_reload(trace_id, dfa_cb, 70, "commit candidate run.json failed: " + swap_res.detail, {
            config_committed: false,
            runtime_applied: false,
            rollback_success: rb ? !!rb.ok : false
        });
    }

    _dfa_emit(dfa_cb, "committing", 80, null);
    log(trace_id, 'INFO', 'RUNTIME', sprintf(
        'commit run.json path=%s commit_path=%s commit_checksum=%s candidate_path=%s restart_result=requested',
        PATH.RUN_JSON,
        PATH.RUN_JSON,
        _artifact_checksum(PATH.RUN_JSON, trace_id),
        PATH_CANDIDATE_CONFIG
    ));
    log(trace_id, 'INFO', 'RUNTIME', '[restart_only:prepare] run.json committed; request process restart only');

    return Success({
        need_restart: true,
        action: RESTART_REQUEST.action,
        skip_network_setup: true,
        next_phase: "verify_only",
        bak_path: bak_path,
        config_committed: true,
        runtime_applied: false,
        verify_passed: null,
        rollback_success: false
    }, 200, trace_id);
}

function run_dataplane_reload(trace_id, job_type, dfa_cb, opts) {
    opts = opts || {};
    let phase = opts.phase || "prepare";
    let reason = _reason(opts, "legacy_dataplane_reload");
    let bak_path = PATH_PREV_CONFIG;

    if (phase === "verify_only") {
        return _run_verify_phase(trace_id, job_type, dfa_cb, bak_path);
    }

    let gateway_script = sprintf("%s/runtime/generate.uc", PATH.BASE);

    _dfa_emit(dfa_cb, "validating", 40, null);
    log(trace_id, 'INFO', 'RUNTIME', '[validating] generate + sing-box check');

    ExecSafe(BIN.RM, ["-f", PATH_CANDIDATE_CONFIG], null, trace_id);

    let gen_res = ExecSafe(BIN.UCODE, [gateway_script, PATH_CANDIDATE_CONFIG], null, trace_id);
    if (!gen_res.ok) {
        return _fail_dataplane(trace_id, dfa_cb, null, 50, 55, "配置生成失败: " + gen_res.detail, false, {
            failed_stage: "candidate_generation_failed",
            failed_artifact: "",
            detail: "配置生成失败: " + gen_res.detail
        });
    }
    _log_artifact(trace_id, 'candidate', PATH_CANDIDATE_CONFIG);

    let check_res = check(PATH_CANDIDATE_CONFIG, { caller: 'runtime.manager' }, trace_id);
    if (!check_res.ok) {
        let failed_path = _quarantine_candidate(trace_id);
        log(trace_id, 'WARN', 'RUNTIME', 'check_result=fail candidate check failed; bad candidate quarantined at: ' + (failed_path || "(none)"));
        check_res.detail = check_res.detail + (failed_path ? (" | failed_artifact=" + failed_path) : "");
        if (_is_business_reload_job(job_type)) {
            log(trace_id, 'WARN', 'RUNTIME', 'business rollback recommended; returning failure data to caller.');
        }
        return _fail_dataplane(trace_id, dfa_cb, null, 55, 60, "安全预检拦截: " + check_res.detail, false, {
            failed_stage: "candidate_check_failed",
            failed_artifact: failed_path || "",
            business_rollback_recommended: _is_business_reload_job(job_type),
            detail: "安全预检拦截: " + check_res.detail
        });
    }
    log(trace_id, 'INFO', 'RUNTIME', sprintf(
        'check_result=success candidate_path=%s candidate_checksum=%s',
        PATH_CANDIDATE_CONFIG,
        _artifact_checksum(PATH_CANDIDATE_CONFIG, trace_id)
    ));

    if (access(PATH.RUN_JSON)) {
        let bak_res = ExecSafe(BIN.CP, ["-f", PATH.RUN_JSON, bak_path], null, trace_id);
        if (bak_res.ok) {
            log(trace_id, 'INFO', 'RUNTIME', sprintf(
                'prev_path=%s prev_checksum=%s',
                bak_path,
                _artifact_checksum(bak_path, trace_id)
            ));
        }
    }

    let swap_res = ExecSafe(BIN.CP, ["-f", PATH_CANDIDATE_CONFIG, PATH.RUN_JSON], null, trace_id);
    if (!swap_res.ok) {
        return _fail_dataplane(trace_id, dfa_cb, bak_path, 60, 65, "Atomic run.json swap failed: " + swap_res.detail, false);
    }
    log(trace_id, 'INFO', 'RUNTIME', sprintf(
        'commit run.json path=%s commit_path=%s commit_checksum=%s candidate_path=%s restart_result=requested',
        PATH.RUN_JSON,
        PATH.RUN_JSON,
        _artifact_checksum(PATH.RUN_JSON, trace_id),
        PATH_CANDIDATE_CONFIG
    ));

    _dfa_emit(dfa_cb, "committing", 75, null);
    log(trace_id, 'INFO', 'RUNTIME', '[committing] apply_commit (orchestrator only)');

    let commit_res = apply_commit(trace_id, { reason: reason });
    if (!commit_res.ok) {
        return _fail_dataplane(trace_id, dfa_cb, bak_path, 85, 88, "提交失败: " + commit_res.detail, true);
    }

    _dfa_emit(dfa_cb, "committing", 80, null);
    return Success({
        need_restart: true,
        action: RESTART_REQUEST.action,
        skip_network_setup: RESTART_REQUEST.skip_network_setup,
        next_phase: "verify_only",
        bak_path: bak_path
    }, 200, trace_id);
}

function run_mode_switch_apply(trace_id, job_type, dfa_cb, opts) {
    opts = (type(opts) === 'object') ? opts : {};
    let phase = opts.phase || "prepare";
    let bak_path = opts.bak_path || PATH_PREV_CONFIG;

    if (phase === "verify_only") {
        return _run_mode_switch_verify_phase(trace_id, dfa_cb, opts);
    }
    if (phase === "rollback") {
        let rb = _run_mode_switch_rollback(trace_id, bak_path, opts.old_mode || "unknown", "mode_switch_explicit_rollback", opts.new_mode);
        if (!rb.ok) return rb;
        rb.need_restart = true;
        return rb;
    }

    let gateway_script = sprintf("%s/runtime/generate.uc", PATH.BASE);
    let reuse_candidate = opts.reuse_candidate === true && access(PATH_CANDIDATE_CONFIG);
    let reuse_checked = opts.reuse_checked === true && reuse_candidate;
    _dfa_emit(dfa_cb, "validating", 40, null);
    _log_mode_switch_stage(trace_id, reuse_candidate ? "reuse_candidate" : "generate_candidate", sprintf(
        "reuse_checked=%s candidate_path=%s",
        reuse_checked ? "true" : "false",
        PATH_CANDIDATE_CONFIG
    ));
    log(trace_id, 'INFO', 'RUNTIME', reuse_candidate
        ? (reuse_checked ? '[mode_switch:prepare] reuse checked candidate' : '[mode_switch:prepare] reuse existing candidate + sing-box check')
        : '[mode_switch:prepare] generate + sing-box check');

    if (!reuse_candidate) {
        ExecSafe(BIN.RM, ["-f", PATH_CANDIDATE_CONFIG], null, trace_id);
        let gen_res = ExecSafe(BIN.UCODE, [gateway_script, PATH_CANDIDATE_CONFIG], null, trace_id);
        if (!gen_res.ok) {
            return _fail_process_reload(trace_id, dfa_cb, 55, "mode switch candidate generation failed: " + gen_res.detail, {
                mode_switch_applied: false,
                config_committed: false,
                runtime_applied: false,
                dataplane_touched: false,
                verify_passed: null,
                rollback_success: false
            });
        }
    }
    _log_artifact(trace_id, 'candidate', PATH_CANDIDATE_CONFIG);

    _log_mode_switch_stage(trace_id, "check_candidate", sprintf(
        "result=%s candidate_path=%s",
        reuse_checked ? "reused" : "pending",
        PATH_CANDIDATE_CONFIG
    ));
    if (!reuse_checked) {
        let check_res = check(PATH_CANDIDATE_CONFIG, { caller: 'runtime.manager' }, trace_id);
        if (!check_res.ok) {
            let failed_path = _quarantine_candidate(trace_id);
            log(trace_id, 'WARN', 'RUNTIME', 'mode_switch check_result=fail candidate check failed; bad candidate quarantined at: ' + (failed_path || "(none)"));
            return _fail_process_reload(trace_id, dfa_cb, 60, "mode switch candidate check failed: " + check_res.detail, {
                mode_switch_applied: false,
                config_committed: false,
                runtime_applied: false,
                dataplane_touched: false,
                verify_passed: null,
                rollback_success: false,
                failed_artifact: failed_path || ""
            });
        }
    }
    _log_mode_switch_stage(trace_id, "check_candidate_ok", sprintf(
        "result=%s candidate_checksum=%s",
        reuse_checked ? "reused" : "success",
        _artifact_checksum(PATH_CANDIDATE_CONFIG, trace_id)
    ));
    log(trace_id, 'INFO', 'RUNTIME', sprintf(
        'check_result=%s candidate_path=%s candidate_checksum=%s',
        reuse_checked ? "reused" : "success",
        PATH_CANDIDATE_CONFIG,
        _artifact_checksum(PATH_CANDIDATE_CONFIG, trace_id)
    ));

    let mode_switch = _detect_mode_switch(trace_id);
    _log_mode_switch_stage(trace_id, "detect_modes", sprintf(
        "required=%s old_mode=%s new_mode=%s",
        mode_switch.required ? "true" : "false",
        mode_switch.old_mode || "unknown",
        mode_switch.new_mode || "unknown"
    ));
    if (!mode_switch.required) {
        return _fail_process_reload(trace_id, dfa_cb, 65, sprintf(
            "mode switch not required old_mode=%s new_mode=%s",
            mode_switch.old_mode || "unknown",
            mode_switch.new_mode || "unknown"
        ), {
            mode_switch_applied: false,
            backend_mode_switch: false,
            old_mode: mode_switch.old_mode || "unknown",
            new_mode: mode_switch.new_mode || "unknown",
            config_committed: false,
            runtime_applied: false,
            dataplane_touched: false,
            verify_passed: null,
            rollback_success: false
        });
    }

    _log_mode_switch_stage(trace_id, "teardown_old", sprintf(
        "old_mode=%s new_mode=%s",
        mode_switch.old_mode,
        mode_switch.new_mode
    ));
    log(trace_id, 'INFO', 'RUNTIME', sprintf(
        '[mode_switch:prepare] teardown old dataplane old_mode=%s new_mode=%s',
        mode_switch.old_mode,
        mode_switch.new_mode
    ));
    let teardown_res = _teardown_mode(trace_id, mode_switch.old_mode, "mode_switch");
    if (!teardown_res || !teardown_res.ok) {
        _log_mode_switch_stage(trace_id, "teardown_old_failed", sprintf(
            "old_mode=%s new_mode=%s",
            mode_switch.old_mode,
            mode_switch.new_mode
        ));
        let setup_old = _setup_mode(trace_id, mode_switch.old_mode, "mode_switch_teardown_failed");
        let fail_res = _fail_process_reload(trace_id, dfa_cb, 75, "mode switch teardown failed: " + (teardown_res ? teardown_res.detail : "unknown"), {
            mode_switch_applied: false,
            old_mode: mode_switch.old_mode,
            new_mode: mode_switch.new_mode,
            config_committed: false,
            runtime_applied: false,
            dataplane_touched: true,
            verify_passed: null,
            rollback_attempted: true,
            rollback_success: !!(setup_old && setup_old.ok),
            rollback_failed: !(setup_old && setup_old.ok),
            manual_intervention_required: !(setup_old && setup_old.ok),
            danger_state: !(setup_old && setup_old.ok),
            error_stage: "teardown_old_failed"
        });
        return fail_res;
    }
    clear_network_marker(trace_id);

    _log_mode_switch_stage(trace_id, "commit_candidate", sprintf(
        "old_mode=%s new_mode=%s",
        mode_switch.old_mode,
        mode_switch.new_mode
    ));
    let commit_res = _commit_candidate_run_json(trace_id, bak_path);
    if (!commit_res.ok) {
        _log_mode_switch_stage(trace_id, "commit_candidate_failed", sprintf(
            "old_mode=%s new_mode=%s",
            mode_switch.old_mode,
            mode_switch.new_mode
        ));
        let setup_old = _setup_mode(trace_id, mode_switch.old_mode, "mode_switch_commit_failed");
        return _fail_process_reload(trace_id, dfa_cb, 70, commit_res.detail || "mode switch commit failed", {
            mode_switch_applied: false,
            old_mode: mode_switch.old_mode,
            new_mode: mode_switch.new_mode,
            config_committed: false,
            runtime_applied: false,
            dataplane_touched: true,
            verify_passed: null,
            rollback_attempted: true,
            rollback_success: !!(setup_old && setup_old.ok),
            rollback_failed: !(setup_old && setup_old.ok),
            manual_intervention_required: !(setup_old && setup_old.ok),
            danger_state: !(setup_old && setup_old.ok),
            error_stage: "commit_failed"
        });
    }

    _dfa_emit(dfa_cb, "committing", 80, null);
    _log_mode_switch_stage(trace_id, "restart_process", sprintf(
        "old_mode=%s new_mode=%s",
        mode_switch.old_mode,
        mode_switch.new_mode
    ));
    log(trace_id, 'INFO', 'RUNTIME', sprintf(
        '[mode_switch:prepare] committed; request process restart old_mode=%s new_mode=%s',
        mode_switch.old_mode,
        mode_switch.new_mode
    ));
    return Success({
        need_restart: true,
        action: RESTART_REQUEST.action,
        skip_network_setup: true,
        next_phase: "verify_only",
        bak_path: bak_path,
        mode_switch_apply: true,
        old_mode: mode_switch.old_mode,
        new_mode: mode_switch.new_mode,
        candidate_path: PATH_CANDIDATE_CONFIG,
        candidate_checksum: _artifact_checksum(PATH_CANDIDATE_CONFIG, trace_id),
        prev_run_json: bak_path,
        prev_run_json_checksum: _artifact_checksum(bak_path, trace_id),
        config_committed: true,
        runtime_applied: false,
        verify_passed: null,
        dataplane_touched: true
    }, 200, trace_id);
}

/**
 * 11. RuntimeOrchestrator Export
 */

const RuntimeOrchestrator = {
    run_process_reload: run_process_reload,
    run_mode_switch_apply: run_mode_switch_apply,
    run_dataplane_reload: run_dataplane_reload,
    setup_network_only: setup_network_only,
    teardown_network_only: teardown_network_only,
    mark_network_ready: mark_network_ready,
    clear_network_marker: clear_network_marker,
    is_network_marker_set: is_network_marker_set,
    rollback_commit: rollback_commit
};

export { RuntimeOrchestrator, PATH_NETWORK_MARKER };
