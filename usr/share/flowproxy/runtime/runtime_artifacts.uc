/**
 * FlowProxy | runtime/runtime_artifacts.uc
 * Role: runtime artifact inspection, checksum, failed candidate preservation.
 */

'use strict';

import { access, readfile } from 'fs';
import { PATH, BIN } from 'flowproxy.core.constants';
import { ExecSafe } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';

const PATH_CANDIDATE_CONFIG = sprintf("%s/sing-box-run.candidate.json", PATH.RUNTIME);
const PATH_FAILED_CONFIG = sprintf("%s/sing-box-run.failed.json", PATH.RUNTIME);
const PATH_FAILED_CONFIG_DIR = sprintf("%s/failed", PATH.RUNTIME);

function safe_artifact_id(trace_id) {
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

function shell_path(path) {
    let out = "'";
    let s = sprintf("%s", path || "");
    for (let i = 0; i < length(s); i++) {
        let c = substr(s, i, 1);
        if (c === "'") out += "'\\''";
        else out += c;
    }
    return out + "'";
}

function artifact_checksum(path, trace_id) {
    if (!path || !access(path)) return "missing";
    let res = ExecSafe(BIN.SH, ["-c", sprintf("sha256sum %s 2>/dev/null | awk '{print $1}'", shell_path(path))], null, trace_id);
    if (res.ok && res.data && trim(res.data.stdout || "")) return trim(res.data.stdout || "");
    res = ExecSafe(BIN.SH, ["-c", sprintf("wc -c %s 2>/dev/null | awk '{print \"bytes:\"$1}'", shell_path(path))], null, trace_id);
    if (res.ok && res.data && trim(res.data.stdout || "")) return trim(res.data.stdout || "");
    return "unknown";
}

function artifact_info(path) {
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

function log_artifact(trace_id, label, path) {
    let info = artifact_info(path);
    log(trace_id, 'INFO', 'RUNTIME', sprintf(
        '%s_path=%s %s_mode=%s %s_checksum=%s %s_inbounds=[%s]',
        label,
        path || "(none)",
        label,
        info.mode,
        label,
        artifact_checksum(path, trace_id),
        label,
        info.inbounds
    ));
}

function preserve_failed_candidate(trace_id, reason) {
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
        artifact_checksum(PATH_FAILED_CONFIG, trace_id)
    ));
    log_artifact(trace_id, 'failed_candidate', PATH_FAILED_CONFIG);
    return PATH_FAILED_CONFIG;
}

function quarantine_candidate(trace_id) {
    if (!access(PATH_CANDIDATE_CONFIG)) return null;

    ExecSafe(BIN.MKDIR, ["-p", PATH_FAILED_CONFIG_DIR], null, trace_id);
    let failed_path = sprintf("%s/sing-box-run.%s.json", PATH_FAILED_CONFIG_DIR, safe_artifact_id(trace_id));
    let cp_res = ExecSafe(BIN.CP, ["-f", PATH_CANDIDATE_CONFIG, failed_path], null, trace_id);
    preserve_failed_candidate(trace_id, "candidate_check_failed");
    if (!cp_res.ok) {
        log(trace_id, 'WARN', 'RUNTIME', 'Failed to quarantine bad candidate: ' + cp_res.detail);
        return PATH_CANDIDATE_CONFIG;
    }
    return failed_path;
}

export {
    safe_artifact_id,
    shell_path,
    artifact_checksum,
    artifact_info,
    log_artifact,
    preserve_failed_candidate,
    quarantine_candidate
};
