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
import { task_rollback_assets } from 'flowproxy.modules.assets';

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
    let raw = trace_id || sprintf("%d", time());
    let out = "";
    for (let i = 0; i < length(raw); i++) {
        let c = substr(raw, i, 1);
        if ((c >= "a" && c <= "z") || (c >= "A" && c <= "Z") || (c >= "0" && c <= "9") || c === "_" || c === "-") {
            out += c;
        } else {
            out += "_";
        }
    }
    return out || sprintf("%d", time());
}

function _shell_path(path) {
    let out = "'";
    let s = sprintf("%s", path || "");
    for (let i = 0; i < length(s); i++) {
        let c = substr(s, i, 1);
        if (c === "'") out += "'\\''";
        else out += c;
    }
    return out + "'";
}

function _artifact_checksum(path, trace_id) {
    if (!path || !access(path)) return "missing";
    let res = ExecSafe(BIN.SH, ["-c", sprintf("sha256sum %s 2>/dev/null | awk '{print $1}'", _shell_path(path))], null, trace_id);
    if (res.ok && res.data && trim(res.data.stdout || "")) return trim(res.data.stdout || "");
    res = ExecSafe(BIN.SH, ["-c", sprintf("wc -c %s 2>/dev/null | awk '{print \"bytes:\"$1}'", _shell_path(path))], null, trace_id);
    if (res.ok && res.data && trim(res.data.stdout || "")) return trim(res.data.stdout || "");
    return "unknown";
}

function _artifact_info(path) {
    let info = { mode: "unknown", inbounds: "" };
    if (!path || !access(path)) return info;
    let raw = readfile(path);
    if (!raw) return info;
    try {
        let cfg = json(raw);
        let inbounds = (cfg && type(cfg.inbounds) === 'array') ? cfg.inbounds : [];
        let parts = [];
        let has_tun = false;
        let has_tproxy = false;
        let has_redirect = false;
        for (let i = 0; i < length(inbounds); i++) {
            let inb = inbounds[i];
            if (!inb || type(inb) !== 'object') continue;
            let t = inb.type || "-";
            let tag = inb.tag || "-";
            push(parts, sprintf("%s:%s", tag, t));
            if (t === "tun") has_tun = true;
            else if (t === "tproxy") has_tproxy = true;
            else if (t === "redirect") has_redirect = true;
        }
        if (has_tun) info.mode = "tun";
        else if (has_tproxy || has_redirect) info.mode = "redirect_tproxy";
        else info.mode = "none";
        info.inbounds = join(",", parts);
    } catch (e) {
        info.mode = "parse_error";
        info.inbounds = "parse_error";
    }
    return info;
}

function _bool_field(v, fallback) {
    if (v === true || v === false) return v;
    return !!fallback;
}

function _failure_stage(detail, data) {
    data = (type(data) === 'object') ? data : {};
    if (data.failed_stage) return data.failed_stage;

    let stage = data.error_stage || "";
    if (stage === "setup_new_failed") return "setup_new_mode_failed";
    if (stage === "verify_new_failed") return "verify_new_mode_failed";
    if (stage === "commit_failed") return "commit_failed";
    if (stage === "rollback_failed") return "rollback_failed";
    if (stage === "restart_process_failed") return "restart_process_failed";
    if (stage === "candidate_check_failed") return "candidate_check_failed";

    let d = sprintf("%s", detail || "");
    if (index(d, "candidate check failed") >= 0) return "candidate_check_failed";
    if (index(d, "commit candidate run.json failed") >= 0) return "commit_failed";
    if (index(d, "Atomic run.json swap failed") >= 0) return "commit_failed";
    if (index(d, "rollback failed") >= 0) return "rollback_failed";
    if (index(d, "process restart") >= 0) return "restart_process_failed";
    if (index(d, "target setup failed") >= 0) return "setup_new_mode_failed";
    if (index(d, "hard verify failed") >= 0) return "verify_new_mode_failed";
    return stage || "";
}

function _normalize_failure_data(trace_id, detail, data) {
    data = (type(data) === 'object') ? data : {};
    let stage = _failure_stage(detail, data);
    let rollback_attempted = _bool_field(data.rollback_attempted, false);

    if (data.rollback_success === true || data.rollback_failed === true || stage === "rollback_failed") {
        rollback_attempted = true;
    }
    if (index(sprintf("%s", detail || ""), "previous run.json restored") >= 0) {
        rollback_attempted = true;
    }

    let rollback_success = _bool_field(data.rollback_success, false);
    let rollback_failed = _bool_field(data.rollback_failed, rollback_attempted && !rollback_success && stage === "rollback_failed");
    let danger_state = _bool_field(data.danger_state, rollback_failed);
    let manual_required = _bool_field(data.manual_intervention_required, danger_state || rollback_failed);
    let current_mode = data.current_known_mode || data.new_mode || _artifact_info(PATH.RUN_JSON).mode || "unknown";
    let expected_mode = data.expected_safe_mode || data.old_mode || data.restored_mode || "unknown";

    data.rollback_attempted = rollback_attempted;
    data.rollback_success = rollback_success;
    data.rollback_failed = rollback_failed;
    data.manual_intervention_required = manual_required;
    data.danger_state = danger_state;
    data.failed_stage = stage;
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

function _log_rollback_observation(trace_id, stage, data) {
    data = (type(data) === 'object') ? data : {};
    log(trace_id, 'WARN', 'RUNTIME', sprintf(
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

function _log_artifact(trace_id, label, path) {
    let info = _artifact_info(path);
    log(trace_id, 'INFO', 'RUNTIME', sprintf(
        '%s_path=%s %s_mode=%s %s_checksum=%s %s_inbounds=[%s]',
        label,
        path || "(none)",
        label,
        info.mode,
        label,
        _artifact_checksum(path, trace_id),
        label,
        info.inbounds
    ));
}

function _preserve_failed_candidate(trace_id, reason) {
    if (!access(PATH_CANDIDATE_CONFIG)) return null;
    let cp_res = ExecSafe(BIN.CP, ["-f", PATH_CANDIDATE_CONFIG, PATH_FAILED_CONFIG], null, trace_id);
    if (!cp_res.ok) {
        log(trace_id, 'WARN', 'RUNTIME', 'failed_candidate copy failed: ' + cp_res.detail);
        return PATH_CANDIDATE_CONFIG;
    }
    log(trace_id, 'WARN', 'RUNTIME', sprintf(
        'failed_candidate_path=%s reason=%s failed_candidate_checksum=%s',
        PATH_FAILED_CONFIG,
        reason || "unknown",
        _artifact_checksum(PATH_FAILED_CONFIG, trace_id)
    ));
    _log_artifact(trace_id, 'failed_candidate', PATH_FAILED_CONFIG);
    return PATH_FAILED_CONFIG;
}

function _quarantine_candidate(trace_id) {
    if (!access(PATH_CANDIDATE_CONFIG)) return null;

    ExecSafe(BIN.MKDIR, ["-p", PATH_FAILED_CONFIG_DIR], null, trace_id);
    let failed_path = sprintf("%s/sing-box-run.%s.json", PATH_FAILED_CONFIG_DIR, _safe_artifact_id(trace_id));
    let cp_res = ExecSafe(BIN.CP, ["-f", PATH_CANDIDATE_CONFIG, failed_path], null, trace_id);
    _preserve_failed_candidate(trace_id, "candidate_check_failed");
    if (!cp_res.ok) {
        log(trace_id, 'WARN', 'RUNTIME', 'Failed to quarantine bad candidate: ' + cp_res.detail);
        return PATH_CANDIDATE_CONFIG;
    }
    return failed_path;
}

/**
 * Restore the previous committed run.json artifact.
 */
function _restore_prev_run_json(trace_id, bak_path) {
    let src = bak_path || PATH_PREV_CONFIG;
    if (!access(src)) {
        log(trace_id, 'ERROR', 'RUNTIME', sprintf('rollback_result=fail prev_path=%s detail=missing', src));
        let fail_res = Fail(ERR.E_SYSTEM_BUSY, "previous run.json backup missing: " + src, trace_id);
        fail_res.data = _normalize_failure_data(trace_id, fail_res.detail, {
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
        _log_rollback_observation(trace_id, "restore_old_run_json_result", fail_res.data);
        return fail_res;
    }

    let res = ExecSafe(BIN.CP, ["-f", src, PATH.RUN_JSON], null, trace_id);
    if (!res.ok) {
        log(trace_id, 'ERROR', 'RUNTIME', sprintf('rollback_result=fail prev_path=%s detail=%s', src, res.detail || "unknown"));
        let fail_res = Fail(ERR.E_SYSTEM_BUSY, "restore previous run.json failed: " + res.detail, trace_id);
        fail_res.data = _normalize_failure_data(trace_id, fail_res.detail, {
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
        _log_rollback_observation(trace_id, "restore_old_run_json_result", fail_res.data);
        return fail_res;
    }

    log(trace_id, 'WARN', 'RUNTIME', sprintf(
        'rollback run.json success rollback_result=success prev_path=%s prev_checksum=%s commit_path=%s commit_checksum=%s',
        src,
        _artifact_checksum(src, trace_id),
        PATH.RUN_JSON,
        _artifact_checksum(PATH.RUN_JSON, trace_id)
    ));
    _log_rollback_observation(trace_id, "restore_old_run_json_result", {
        rollback_attempted: true,
        restored_run_json: true,
        current_known_mode: _artifact_info(PATH.RUN_JSON).mode,
        rollback_detail: "previous run.json restored"
    });
    return Success(true, 200, trace_id);
}

function _commit_candidate_run_json(trace_id, bak_path) {
    if (access(PATH.RUN_JSON)) {
        let bak_res = ExecSafe(BIN.CP, ["-f", PATH.RUN_JSON, bak_path], null, trace_id);
        if (!bak_res.ok) {
            let fail_res = Fail(ERR.E_SYSTEM_BUSY, "backup current run.json failed: " + bak_res.detail, trace_id);
            fail_res.data = _normalize_failure_data(trace_id, fail_res.detail, {
                config_committed: false,
                rollback_attempted: false,
                rollback_success: false,
                failed_stage: "commit_failed"
            });
            return fail_res;
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
        let res = Fail(ERR.E_SYSTEM_BUSY, "commit candidate run.json failed: " + swap_res.detail, trace_id);
        res.data = _normalize_failure_data(trace_id, res.detail, {
            config_committed: false,
            rollback_attempted: !!rb,
            rollback_success: rb ? !!rb.ok : false,
            rollback_failed: !!(rb && !rb.ok),
            manual_intervention_required: !!(rb && !rb.ok),
            danger_state: !!(rb && !rb.ok)
        });
        return res;
    }

    log(trace_id, 'INFO', 'RUNTIME', sprintf(
        'commit run.json path=%s commit_path=%s commit_checksum=%s candidate_path=%s restart_result=requested',
        PATH.RUN_JSON,
        PATH.RUN_JSON,
        _artifact_checksum(PATH.RUN_JSON, trace_id),
        PATH_CANDIDATE_CONFIG
    ));
    return Success(true, 200, trace_id);
}

/**
 * 4. Config / Runtime Inspect Helpers
 */

function _load_json_config(path) {
    if (!path || !access(path)) return { ok: false, cfg: null, detail: "run.json missing" };
    let raw = readfile(path);
    if (!raw || length(raw) === 0) return { ok: false, cfg: null, detail: "run.json empty" };
    try {
        return { ok: true, cfg: json(raw), detail: "" };
    } catch (e) {
        return { ok: false, cfg: null, detail: "run.json parse failed: " + ("" + e) };
    }
}

function _find_inbound(cfg, inbound_type, tag) {
    let inbounds = (cfg && type(cfg.inbounds) === 'array') ? cfg.inbounds : [];
    for (let i = 0; i < length(inbounds); i++) {
        let inb = inbounds[i];
        if (!inb || type(inb) !== 'object') continue;
        if ((inbound_type && inb.type === inbound_type) || (tag && inb.tag === tag)) return inb;
    }
    return null;
}

function _run_json_mode(cfg) {
    let inbounds = (cfg && type(cfg.inbounds) === 'array') ? cfg.inbounds : [];
    let has_tun = false;
    let has_redirect = false;
    let has_tproxy = false;
    let has_mixed = false;
    let has_socks = false;

    for (let i = 0; i < length(inbounds); i++) {
        let inb = inbounds[i];
        if (!inb || type(inb) !== 'object') continue;
        if (inb.type === "tun") has_tun = true;
        else if (inb.type === "redirect") has_redirect = true;
        else if (inb.type === "tproxy") has_tproxy = true;
        else if (inb.type === "mixed") has_mixed = true;
        else if (inb.type === "socks") has_socks = true;
    }

    if (has_tun) return "tun";
    if (has_redirect || has_tproxy) return "redirect_tproxy";
    if (has_mixed || has_socks) return "mixed";
    return "unknown";
}

function _core_listener_inbound(cfg) {
    let mixed = _find_inbound(cfg, "mixed", "mixed-in");
    if (mixed) return mixed;
    let socks = _find_inbound(cfg, "socks", "socks-in");
    if (socks) return socks;
    return null;
}

function _core_listener_port(cfg) {
    let listener = _core_listener_inbound(cfg);
    if (listener && listener.listen_port) return int(listener.listen_port);
    return 0;
}

/**
 * 5. Runtime Verify Helpers
 */

function _verify_listen_port(port) {
    if (!port || int(port) <= 0) return false;
    let safe_port = sprintf("%d", int(port));
    let grep_expr = sprintf("(^|[.:])%s[[:space:]]", safe_port);
    let cmd = sprintf(
        "(%s -lnt 2>/dev/null || ss -lnt 2>/dev/null) | grep -Eq %s",
        _shell_path(BIN.NETSTAT),
        _shell_path(grep_expr)
    );
    let res = ExecSafe(BIN.SH, ["-c", cmd], null, null);
    return res.ok;
}

function _verify_tun_up(tun_in) {
    if (!tun_in) return { ok: false, detail: "tun-in inbound missing" };
    let iface = tun_in.interface_name || "singtun0";
    let cmd = sprintf(
        "ip link show dev %s 2>/dev/null | grep -q 'state UP' || ip link show dev %s 2>/dev/null | grep -q 'UP'",
        _shell_path(iface),
        _shell_path(iface)
    );
    let res = ExecSafe(BIN.SH, ["-c", cmd], null, null);
    if (res.ok) return { ok: true, detail: "", iface: iface };
    return { ok: false, detail: sprintf("%s missing or not UP", iface), iface: iface };
}

function _verify_proxy_curl(trace_id, port) {
    if (!access(BIN.CURL) || !port || int(port) <= 0) {
        return { ok: true, warning: "", code: "" };
    }

    let proxy_url = sprintf("socks5h://127.0.0.1:%d", int(port));
    let curl_res = ExecSafe(BIN.CURL, [
        "-sS",
        "-x", proxy_url,
        "https://www.google.com/generate_204",
        "--connect-timeout", "8",
        "--max-time", "12",
        "-k",
        "-o", "/dev/null",
        "-w", "%{http_code}"
    ], { timeout: 15 }, trace_id);

    let code = (curl_res.ok && curl_res.data) ? trim(curl_res.data.stdout || "") : "";
    if (curl_res.ok && code === "204") {
        return { ok: true, warning: "", code: code };
    }

    return {
        ok: false,
        warning: sprintf("proxy curl failed: http_code=%s detail=%s", code || "-", curl_res.detail || "unknown"),
        code: code
    };
}

function _verify_restart_only_runtime(trace_id) {
    let cfg_info = _load_json_config(PATH.RUN_JSON);
    let cfg = cfg_info.cfg;
    let mode = cfg_info.ok ? _run_json_mode(cfg) : "unknown";
    let hard_errors = [];
    let soft_warnings = [];

    let process_ok = verify_process();
    if (!process_ok) push(hard_errors, "sing-box process not running");

    let run_json_ok = !!cfg_info.ok;
    if (!run_json_ok) push(hard_errors, cfg_info.detail || "run.json invalid");

    let listener = run_json_ok ? _core_listener_inbound(cfg) : null;
    let port = run_json_ok ? _core_listener_port(cfg) : 0;
    let listener_ok = !!listener;
    if (!listener_ok) push(hard_errors, "core listener inbound missing");

    let port_ok = listener_ok && _verify_listen_port(port);
    if (!port_ok) push(hard_errors, sprintf("core listener port %d not listening", port || 0));

    let tun_ok = true;
    if (run_json_ok && mode === "tun") {
        let tun_in = _find_inbound(cfg, "tun", "tun-in");
        if (!tun_in) {
            tun_ok = false;
            push(hard_errors, "run.json mode=tun but tun-in inbound missing");
        } else {
            let tun_chk = _verify_tun_up(tun_in);
            tun_ok = !!tun_chk.ok;
            if (!tun_ok) push(hard_errors, tun_chk.detail || "tun interface missing");
        }
    } else if (run_json_ok && mode === "redirect_tproxy") {
        if (!_find_inbound(cfg, "redirect", "redirect-in")) push(hard_errors, "redirect inbound missing");
        if (!_find_inbound(cfg, "tproxy", "tproxy-in")) push(hard_errors, "tproxy inbound missing");
    } else if (run_json_ok && mode === "unknown") {
        push(hard_errors, "run.json mode unknown");
    }

    let curl_ok = true;
    if (port_ok) {
        let curl_res = _verify_proxy_curl(trace_id, port);
        curl_ok = !!curl_res.ok;
        if (!curl_ok) push(soft_warnings, curl_res.warning || "proxy curl failed");
    }

    let hard_ok = length(hard_errors) === 0;
    let soft_msg = length(soft_warnings) > 0 ? join(" | ", soft_warnings) : "";
    if (hard_ok && length(soft_warnings) > 0) {
        log(trace_id, 'WARN', 'RESTART_VERIFY', sprintf(
            'mode=%s hard_ok=true curl_ok=%s soft_warning=%s',
            mode,
            curl_ok ? "true" : "false",
            soft_msg
        ));
    } else {
        log(trace_id, hard_ok ? 'INFO' : 'WARN', 'RESTART_VERIFY', sprintf(
            'mode=%s hard_ok=%s curl_ok=%s error=%s',
            mode,
            hard_ok ? "true" : "false",
            curl_ok ? "true" : "false",
            hard_ok ? "" : join(" | ", hard_errors)
        ));
    }

    return {
        ok: hard_ok,
        hard_ok: hard_ok,
        error: hard_ok ? "" : "restart_only_hard_verify_failed",
        detail: hard_ok ? soft_msg : join(" | ", hard_errors),
        mode: mode,
        process_ok: process_ok,
        run_json_ok: run_json_ok,
        listener_ok: listener_ok,
        port_ok: port_ok,
        port: port,
        tun_ok: tun_ok,
        curl_ok: curl_ok,
        soft_warnings: soft_warnings,
        stage: "restart_only_verify"
    };
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
    let reason = _reason(opts, "rollback");
    let src = bak_path || PATH_PREV_CONFIG;
    let src_stat = stat(src);

    if (!src || !src_stat || !src_stat.size) {
        let detail = "rollback previous run.json backup missing or empty: " + (src || "(none)");
        log(trace_id, 'ERROR', 'RUNTIME', detail);
        let fail_res = Fail(ERR.E_SYSTEM_BUSY, detail, trace_id);
        fail_res.data = _normalize_failure_data(trace_id, detail, {
            rollback_attempted: true,
            rollback_success: false,
            rollback_failed: true,
            manual_intervention_required: true,
            danger_state: true,
            failed_stage: "restore_prev_run_json_failed",
            restored_run_json: false
        });
        _log_rollback_observation(trace_id, "restore_old_run_json_result", fail_res.data);
        return fail_res;
    }

    let restore_res = ExecSafe(BIN.CP, ["-f", src, PATH.RUN_JSON], null, trace_id);
    let dst_stat = stat(PATH.RUN_JSON);
    if (!restore_res.ok || !dst_stat || !dst_stat.size) {
        let detail = "restore previous run.json failed: " + (restore_res.ok ? "restored file missing or empty" : restore_res.detail);
        log(trace_id, 'ERROR', 'RUNTIME', detail);
        let fail_res = Fail(ERR.E_SYSTEM_BUSY, detail, trace_id);
        fail_res.data = _normalize_failure_data(trace_id, detail, {
            rollback_attempted: true,
            rollback_success: false,
            rollback_failed: true,
            manual_intervention_required: true,
            danger_state: true,
            failed_stage: "restore_prev_run_json_failed",
            restored_run_json: false
        });
        _log_rollback_observation(trace_id, "restore_old_run_json_result", fail_res.data);
        return fail_res;
    }

    _log_rollback_observation(trace_id, "restore_old_run_json_result", {
        rollback_attempted: true,
        rollback_success: true,
        rollback_failed: false,
        manual_intervention_required: false,
        danger_state: false,
        restored_run_json: true,
        current_known_mode: _artifact_info(PATH.RUN_JSON).mode,
        rollback_detail: "previous run.json restored"
    });

    /* Physical cleanup is owned by execute_fallback; avoid double teardown/GC. */
    log(trace_id, 'WARN', 'RUNTIME', '[ROLLBACK] rollback_commit delegated cleanup to fallback reason=' + reason);
    safe_exec(trace_id, 'runtime', 'system.safety.fallback', () => execute_fallback(trace_id, { reason: "fallback" }));

    _quarantine_candidate(trace_id);

    mark_network_ready(trace_id);
    let restart_res = _emit_restart_request(trace_id, 'rollback_commit');
    if (restart_res && restart_res.ok) {
        restart_res.data = (type(restart_res.data) === 'object') ? restart_res.data : {};
        restart_res.data.restored_run_json = true;
    }
    return restart_res;
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

function _fail_dataplane(trace_id, dfa_cb, bak_path, progress_rb, progress_fail, detail, do_network_rollback) {
    let rb = null;
    if (do_network_rollback && bak_path) {
        rb = rollback_commit(trace_id, bak_path, { reason: "rollback" });
    }
    _dfa_emit(dfa_cb, "rollback", progress_rb, detail);
    _dfa_emit(dfa_cb, "fail", progress_fail, detail);
    let fail_res = Fail(ERR.E_SYSTEM_BUSY, detail, trace_id);
    fail_res.data = _normalize_failure_data(trace_id, detail, {
        rollback_attempted: !!(do_network_rollback && bak_path),
        rollback_success: !!(rb && rb.ok),
        rollback_failed: !!(do_network_rollback && bak_path && (!rb || !rb.ok)),
        manual_intervention_required: !!(do_network_rollback && bak_path && (!rb || !rb.ok)),
        danger_state: !!(do_network_rollback && bak_path && (!rb || !rb.ok))
    });
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
    return Success({ verified: true }, 200, trace_id);
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
        return _fail_dataplane(trace_id, dfa_cb, null, 50, 55, "配置生成失败: " + gen_res.detail, false);
    }
    _log_artifact(trace_id, 'candidate', PATH_CANDIDATE_CONFIG);

    let check_res = check(PATH_CANDIDATE_CONFIG, { caller: 'runtime.manager' }, trace_id);
    if (!check_res.ok) {
        let failed_path = _quarantine_candidate(trace_id);
        log(trace_id, 'WARN', 'RUNTIME', 'check_result=fail candidate check failed; bad candidate quarantined at: ' + (failed_path || "(none)"));
        check_res.detail = check_res.detail + (failed_path ? (" | failed_artifact=" + failed_path) : "");

        if (job_type === 'update_assets' || job_type === 'update_subscriptions' || job_type === 'rebuild_groups') {
            log(trace_id, 'WARN', 'RUNTIME', 'Asset corruption detected. Initiating emergency asset rollback.');
            task_rollback_assets(trace_id, {});
        }
        return _fail_dataplane(trace_id, dfa_cb, null, 55, 60, "安全预检拦截: " + check_res.detail, false);
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
