/**
 * FlowProxy | runtime/control.uc | v1.0
 * Runtime 官方 CLI：仅供 init.d 生命周期调用，身份 runtime.manager，禁止 shell 直 import system.*
 * 用法: ucode control.uc <setup-network|teardown-network> [trace_id]
 */

'use strict';

push(REQUIRE_SEARCH_PATH, "/usr/share/ucode/*.uc");
push(REQUIRE_SEARCH_PATH, "/usr/share/ucode/*/init.uc");

import { access } from 'fs';
import { PATH, BIN } from 'flowproxy.core.constants';
import { init as gen_trace_id } from 'flowproxy.core.trace';
import { log } from 'flowproxy.core.logger';
import { acquire } from 'flowproxy.core.lock';
import { ExecSafe } from 'flowproxy.core.utils';
import { check } from 'flowproxy.runtime.launcher';
import { dataplane_verify } from 'flowproxy.runtime.healthcheck';
import { RuntimeOrchestrator } from 'flowproxy.runtime.runtime';

const PATH_APPLY_MARKER = sprintf("%s/apply.marker", PATH.RUNTIME);
const PATH_CANDIDATE_CONFIG = sprintf("%s/sing-box-run.candidate.json", PATH.RUNTIME);
const PATH_FAILED_CONFIG_DIR = sprintf("%s/failed", PATH.RUNTIME);

function _safe_artifact_id(trace_id) {
    let raw = trace_id || sprintf("%d", time());
    let out = "";
    for (let i = 0; i < length(raw); i++) {
        let c = substr(raw, i, 1);
        if ((c >= "a" && c <= "z") || (c >= "A" && c <= "Z") || (c >= "0" && c <= "9") || c === "_" || c === "-") out += c;
        else out += "_";
    }
    return out || sprintf("%d", time());
}

function _quarantine_candidate(trace_id) {
    if (!access(PATH_CANDIDATE_CONFIG)) return null;

    ExecSafe(BIN.MKDIR, ["-p", PATH_FAILED_CONFIG_DIR], null, trace_id);
    let failed_path = sprintf("%s/sing-box-run.%s.json", PATH_FAILED_CONFIG_DIR, _safe_artifact_id(trace_id));
    let mv_res = ExecSafe(BIN.MV, ["-f", PATH_CANDIDATE_CONFIG, failed_path], null, trace_id);
    return mv_res.ok ? failed_path : PATH_CANDIDATE_CONFIG;
}

function _commit_candidate_if_present(trace_id, must_generate) {
    let gateway_script = sprintf("%s/runtime/generate.uc", PATH.BASE);

    if (must_generate || !access(PATH_CANDIDATE_CONFIG)) {
        ExecSafe(BIN.RM, ["-f", PATH_CANDIDATE_CONFIG], null, trace_id);
        let gen_res = ExecSafe(BIN.UCODE, [gateway_script, PATH_CANDIDATE_CONFIG], null, trace_id);
        if (!gen_res.ok) return gen_res;
    }

    if (!access(PATH_CANDIDATE_CONFIG)) return { ok: true };

    let check_res = check(PATH_CANDIDATE_CONFIG, { caller: 'runtime.manager' }, trace_id);
    if (!check_res.ok) {
        let failed_path = _quarantine_candidate(trace_id);
        check_res.detail = check_res.detail + (failed_path ? (" | failed_artifact=" + failed_path) : "");
        return check_res;
    }

    if (access(PATH.RUN_JSON)) {
        ExecSafe(BIN.CP, ["-f", PATH.RUN_JSON, sprintf("%s/sing-box-run.prev.json", PATH.RUNTIME)], null, trace_id);
    }

    return ExecSafe(BIN.MV, ["-f", PATH_CANDIDATE_CONFIG, PATH.RUN_JSON], null, trace_id);
}

function _lifecycle_reason(cmd, trace_id) {
    if (cmd === "setup-network") {
        if (index(trace_id || "", "init_start:") === 0) return "start";
        return "setup_network_only";
    }
    if (cmd === "teardown-network") {
        if (index(trace_id || "", "init_stop:") === 0) return "stop";
        return "teardown_network_only";
    }
    return "unknown";
}

function _arg_value(arg, key) {
    let prefix = key + "=";
    if (index(arg || "", prefix) === 0) return substr(arg, length(prefix));
    return null;
}

function _parse_opts(start) {
    let opts = {};
    for (let i = start; i < length(ARGV); i++) {
        let arg = ARGV[i] || "";
        let pos = index(arg, "=");
        if (pos <= 0) continue;
        opts[substr(arg, 0, pos)] = substr(arg, pos + 1);
    }
    return opts;
}

function main() {
    let cmd = (length(ARGV) > 0) ? ARGV[0] : "";
    let trace_id = (length(ARGV) > 1) ? ARGV[1] : ("ctl_" + gen_trace_id());
    let cli_opts = _parse_opts(2);
    let reason_arg = cli_opts.reason || null;
    let gc_policy_arg = cli_opts.gc_policy || null;
    let mode_arg = cli_opts.mode || null;
    let no_run_json_policy_arg = cli_opts.no_run_json_policy || null;

    if (!cmd) {
        exit(2);
    }

    if (cmd === "healthcheck") {
        let health = dataplane_verify(trace_id);
        print(sprintf("%.J\n", health));
        exit(health.ok ? 0 : 1);
    }

    let reason = reason_arg || _lifecycle_reason(cmd, trace_id);
    let gc_policy = gc_policy_arg || "auto";
    log(trace_id, 'INFO', 'CONTROL', sprintf('control command=%s reason=%s gc_policy=%s', cmd, reason, gc_policy));

    let has_apply_marker = access(PATH_APPLY_MARKER);
    let lock_handle = null;

    if (!has_apply_marker) {
        let lock_res = acquire(trace_id, "worker");
        if (!lock_res.ok) {
            log(trace_id, 'ERROR', 'CONTROL', lock_res.detail);
            exit(1);
        }
        lock_handle = lock_res.data;
    } else {
        log(trace_id, 'INFO', 'CONTROL', 'apply.marker detected; bypassing worker.lock for procd restart path.');
    }

    if (cmd === "setup-network") {
        let commit_res = _commit_candidate_if_present(trace_id, !has_apply_marker);
        if (!commit_res || !commit_res.ok) {
            if (lock_handle) lock_handle.release();
            log(trace_id, 'CRIT', 'CONTROL', (commit_res && commit_res.detail) ? commit_res.detail : "candidate commit failed");
            exit(1);
        }
    }

    let res;
    if (cmd === "setup-network") {
        res = RuntimeOrchestrator.setup_network_only(trace_id, { reason: reason, gc_policy: gc_policy });
    } else if (cmd === "teardown-network") {
        res = RuntimeOrchestrator.teardown_network_only(trace_id, {
            reason: reason,
            mode: mode_arg || "auto",
            no_run_json_policy: no_run_json_policy_arg || "teardown_both"
        });
    } else {
        if (lock_handle) lock_handle.release();
        exit(2);
    }

    if (lock_handle) lock_handle.release();

    if (!res || !res.ok) {
        log(trace_id, 'CRIT', 'CONTROL', (res && res.detail) ? res.detail : "control failed");
        exit(1);
    }
    exit(0);
}

main();
