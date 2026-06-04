/**
 * FlowProxy | system/network.uc | v2.0
 * Role: dataplane facade. It detects or accepts an explicit run mode, then
 * dispatches to the selected isolated network plane. GC is manual/fallback only.
 */

'use strict';

import { readfile } from 'fs';

import { PATH } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { log } from 'flowproxy.core.logger';
import { gc_all } from 'flowproxy.system.network.gc';
import { setup_redirect_tproxy, teardown_redirect_tproxy } from 'flowproxy.system.network.plane_tproxy';
import { setup_tun, teardown_tun } from 'flowproxy.system.network.plane_tun';

function load_run_config(trace_id) {
    let raw_json = readfile(PATH.RUN_JSON);
    if (!raw_json) {
        return Fail(ERR.E_CONFIG_FAULT, "run.json missing: " + PATH.RUN_JSON, trace_id);
    }

    try {
        return Success(json(raw_json), 200, trace_id);
    } catch(e) {
        return Fail(ERR.E_CONFIG_FAULT, "run.json parse failed: " + e, trace_id);
    }
}

function detect_plane(run_config) {
    let inbounds = (run_config && type(run_config.inbounds) === 'array') ? run_config.inbounds : [];
    let has_tun = false;
    let has_redirect = false;
    let has_tproxy = false;

    for (let i = 0; i < length(inbounds); i++) {
        let t = inbounds[i].type;
        if (t === 'tun') has_tun = true;
        else if (t === 'redirect') has_redirect = true;
        else if (t === 'tproxy') has_tproxy = true;
    }

    if (has_tun) return "tun";
    if (has_redirect || has_tproxy) return "redirect_tproxy";
    return "none";
}

function _reason(opts) {
    opts = (type(opts) === 'object') ? opts : {};
    return opts.reason || "unknown";
}

function _gc_policy(opts) {
    opts = (type(opts) === 'object') ? opts : {};
    return opts.gc_policy || "auto";
}

function _mode(opts) {
    opts = (type(opts) === 'object') ? opts : {};
    let mode = opts.mode || "";
    if (mode === "auto") return "";
    if (mode === "redirect" || mode === "redirect_tproxy") return "redirect_tproxy";
    if (mode === "redirect_tun" || mode === "tun") return "tun";
    return mode;
}

function _no_run_json_policy(opts) {
    opts = (type(opts) === 'object') ? opts : {};
    return opts.no_run_json_policy || "none";
}

function setup(trace_id, opts) {
    try {
        let reason = _reason(opts);
        let policy = _gc_policy(opts);
        log(trace_id, 'INFO', 'NETWORK', 'setup begin reason=' + reason);
        log(trace_id, 'INFO', 'NETWORK', 'setup gc_policy ignored by Phase B dispatcher policy=' + policy + ' reason=' + reason);

        let cfg_res = load_run_config(trace_id);
        if (!cfg_res.ok) return cfg_res;

        let run_config = cfg_res.data;
        let plane = _mode(opts) || detect_plane(run_config);
        log(trace_id, 'INFO', 'NETWORK', 'Detected dataplane: ' + plane);

        if (plane === "redirect_tproxy") {
            return setup_redirect_tproxy(trace_id, run_config);
        }

        if (plane === "tun") {
            log(trace_id, 'INFO', 'NETWORK', 'assembling_tun_device: dispatching to TUN preflight plane.');
            return setup_tun(trace_id, run_config);
        }

        log(trace_id, 'INFO', 'NETWORK', 'No kernel interception plane detected.');
        return Success(true, 200, trace_id);
    } catch(e) {
        let err_msg = "" + e;
        log(trace_id, 'CRIT', 'NETWORK', 'Facade setup exception: ' + err_msg);
        return Fail(ERR.E_SYSTEM_BUSY, "Network Setup Exception: " + err_msg, trace_id);
    }
}

function teardown(trace_id, opts) {
    let reason = _reason(opts);
    let requested_mode = _mode(opts);
    let no_run_json_policy = _no_run_json_policy(opts);
    log(trace_id, 'INFO', 'NETWORK', 'teardown begin reason=' + reason);

    let cfg_res = load_run_config(trace_id);
    let run_config = cfg_res.ok ? cfg_res.data : null;
    let plane = requested_mode || (run_config ? detect_plane(run_config) : "none");
    log(trace_id, 'INFO', 'NETWORK', 'teardown detected dataplane: ' + plane);

    if (!run_config && !requested_mode && no_run_json_policy === "teardown_both") {
        log(trace_id, 'WARN', 'NETWORK', 'teardown_current_mode fallback reason=no_run_json policy=teardown_both');
        let tun_res = teardown_tun(trace_id, null, { reason: "no_run_json" });
        let tproxy_res = teardown_redirect_tproxy(trace_id, null, { reason: "no_run_json" });
        if ((tun_res && !tun_res.ok) || (tproxy_res && !tproxy_res.ok)) {
            return Fail(ERR.E_SYSTEM_BUSY, sprintf(
                "no_run_json fallback teardown failed: tun=%s redirect_tproxy=%s",
                tun_res && tun_res.ok ? "ok" : ((tun_res && tun_res.detail) ? tun_res.detail : "unknown"),
                tproxy_res && tproxy_res.ok ? "ok" : ((tproxy_res && tproxy_res.detail) ? tproxy_res.detail : "unknown")
            ), trace_id);
        }
        return Success(true, 200, trace_id);
    }

    if (plane === "redirect_tproxy") {
        return teardown_redirect_tproxy(trace_id, run_config, { reason: reason });
    }

    if (plane === "tun") {
        return teardown_tun(trace_id, run_config, { reason: reason });
    }

    log(trace_id, 'INFO', 'NETWORK', 'No dataplane teardown required.');
    return Success(true, 200, trace_id);
}

function manual_gc(trace_id, opts) {
    let reason = _reason(opts);
    log(trace_id, 'WARN', 'NETWORK', 'manual/fallback GC requested reason=' + reason);
    return gc_all(trace_id, { reason: reason });
}

export { setup, teardown, manual_gc, detect_plane, load_run_config };
