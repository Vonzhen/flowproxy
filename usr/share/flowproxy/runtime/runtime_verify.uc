/**
 * FlowProxy | runtime/runtime_verify.uc
 * Role: restart-only runtime verification helpers.
 */

'use strict';

import { access, readfile } from 'fs';
import { PATH, BIN } from 'flowproxy.core.constants';
import { ExecSafe } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';
import { verify_process } from 'flowproxy.runtime.healthcheck';
import { shell_path } from 'flowproxy.runtime.runtime_artifacts';

function load_json_config(path) {
    if (!path || !access(path)) return { ok: false, cfg: null, detail: "run.json missing" };
    let raw = readfile(path);
    if (!raw || length(raw) === 0) return { ok: false, cfg: null, detail: "run.json empty" };
    try {
        return { ok: true, cfg: json(raw), detail: "" };
    } catch (e) {
        return { ok: false, cfg: null, detail: "run.json parse failed: " + ("" + e) };
    }
}

function find_inbound(cfg, inbound_type, tag) {
    let inbounds = (cfg && type(cfg.inbounds) === 'array') ? cfg.inbounds : [];
    for (let i = 0; i < length(inbounds); i++) {
        let inb = inbounds[i];
        if (!inb || type(inb) !== 'object') continue;
        if ((inbound_type && inb.type === inbound_type) || (tag && inb.tag === tag)) return inb;
    }
    return null;
}

function run_json_mode(cfg) {
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

function core_listener_inbound(cfg) {
    let mixed = find_inbound(cfg, "mixed", "mixed-in");
    if (mixed) return mixed;
    let socks = find_inbound(cfg, "socks", "socks-in");
    if (socks) return socks;
    return null;
}

function core_listener_port(cfg) {
    let listener = core_listener_inbound(cfg);
    if (listener && listener.listen_port) return int(listener.listen_port);
    return 0;
}

function verify_listen_port(port) {
    if (!port || int(port) <= 0) return false;
    let safe_port = sprintf("%d", int(port));
    let grep_expr = sprintf("(^|[.:])%s[[:space:]]", safe_port);
    let cmd = sprintf(
        "(%s -lnt 2>/dev/null || ss -lnt 2>/dev/null) | grep -Eq %s",
        shell_path(BIN.NETSTAT),
        shell_path(grep_expr)
    );
    let res = ExecSafe(BIN.SH, ["-c", cmd], null, null);
    return res.ok;
}

function verify_tun_up(tun_in) {
    if (!tun_in) return { ok: false, detail: "tun-in inbound missing" };
    let iface = tun_in.interface_name || "singtun0";
    let cmd = sprintf(
        "ip link show dev %s 2>/dev/null | grep -q 'state UP' || ip link show dev %s 2>/dev/null | grep -q 'UP'",
        shell_path(iface),
        shell_path(iface)
    );
    let res = ExecSafe(BIN.SH, ["-c", cmd], null, null);
    if (res.ok) return { ok: true, detail: "", iface: iface };
    return { ok: false, detail: sprintf("%s missing or not UP", iface), iface: iface };
}

function verify_proxy_curl(trace_id, port) {
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

function verify_restart_only_runtime(trace_id) {
    let cfg_info = load_json_config(PATH.RUN_JSON);
    let cfg = cfg_info.cfg;
    let mode = cfg_info.ok ? run_json_mode(cfg) : "unknown";
    let hard_errors = [];
    let soft_warnings = [];

    let process_ok = verify_process();
    if (!process_ok) push(hard_errors, "sing-box process not running");

    let run_json_ok = !!cfg_info.ok;
    if (!run_json_ok) push(hard_errors, cfg_info.detail || "run.json invalid");

    let listener = run_json_ok ? core_listener_inbound(cfg) : null;
    let port = run_json_ok ? core_listener_port(cfg) : 0;
    let listener_ok = !!listener;
    if (!listener_ok) push(hard_errors, "core listener inbound missing");

    let port_ok = listener_ok && verify_listen_port(port);
    if (!port_ok) push(hard_errors, sprintf("core listener port %d not listening", port || 0));

    let tun_ok = true;
    if (run_json_ok && mode === "tun") {
        let tun_in = find_inbound(cfg, "tun", "tun-in");
        if (!tun_in) {
            tun_ok = false;
            push(hard_errors, "run.json mode=tun but tun-in inbound missing");
        } else {
            let tun_chk = verify_tun_up(tun_in);
            tun_ok = !!tun_chk.ok;
            if (!tun_ok) push(hard_errors, tun_chk.detail || "tun interface missing");
        }
    } else if (run_json_ok && mode === "redirect_tproxy") {
        if (!find_inbound(cfg, "redirect", "redirect-in")) push(hard_errors, "redirect inbound missing");
        if (!find_inbound(cfg, "tproxy", "tproxy-in")) push(hard_errors, "tproxy inbound missing");
    } else if (run_json_ok && mode === "unknown") {
        push(hard_errors, "run.json mode unknown");
    }

    let curl_ok = true;
    if (port_ok) {
        let curl_res = verify_proxy_curl(trace_id, port);
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

export {
    load_json_config,
    find_inbound,
    run_json_mode,
    core_listener_inbound,
    core_listener_port,
    verify_listen_port,
    verify_tun_up,
    verify_proxy_curl,
    verify_restart_only_runtime
};
