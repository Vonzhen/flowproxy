/**
 * FlowProxy | runtime/healthcheck.uc | v2.0 Plane-Aware Verify
 * Role: read-only dataplane verification for Redirect+TProxy and pure TUN.
 */

'use strict';

import { access, readfile, stat, writefile, unlink } from 'fs';
import { cursor } from 'uci';
import { PATH, BIN, DATAPLANE } from 'flowproxy.core.constants';
import { ExecSafe, shell_escape } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';

const MIN_RUN_JSON_BYTES = 32;
const STAGE_DATAPLANE = "dataplane_verify";
const MODE_MARKER = sprintf("%s/dataplane.mode", PATH.RUNTIME);
const NETWORK_READY_MARKER = sprintf("%s/.fp_network_ready", PATH.RUNTIME);
const APPLY_MARKER = sprintf("%s/apply.marker", PATH.RUNTIME);
const LIFECYCLE_STARTING_MARKER = sprintf("%s/lifecycle.starting", PATH.RUNTIME);
const LIFECYCLE_STOPPING_MARKER = sprintf("%s/lifecycle.stopping", PATH.RUNTIME);
const LIFECYCLE_PROTECT_MARKER = sprintf("%s/lifecycle.protect", PATH.RUNTIME);
const TUN_GRACE_SEC = 20;
const TXN_GRACE_SEC = 90;

function _load_run_config_info() {
    if (!access(PATH.RUN_JSON)) return { ok: false, cfg: null, error: "run.json missing" };
    let raw = readfile(PATH.RUN_JSON);
    if (!raw || length(raw) === 0) return { ok: false, cfg: null, error: "run.json empty" };
    try {
        return { ok: true, cfg: json(raw), error: "" };
    } catch (e) {
        return { ok: false, cfg: null, error: "run.json parse failed: " + ("" + e) };
    }
}

function _load_run_config() {
    let info = _load_run_config_info();
    return info.ok ? info.cfg : null;
}

function _load_mode_marker() {
    if (!access(MODE_MARKER)) return null;
    let raw = readfile(MODE_MARKER);
    if (!raw || length(raw) === 0) return null;
    try {
        return json(raw);
    } catch (e) {
        return null;
    }
}

function _load_run_inbound_types(cfg) {
    let types = {};
    let inbounds = (cfg && type(cfg.inbounds) === 'array') ? cfg.inbounds : [];
    for (let i = 0; i < length(inbounds); i++) {
        let t = inbounds[i].type;
        if (t) types[t] = true;
    }
    return types;
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

function _inbound_summary(cfg) {
    let inbounds = (cfg && type(cfg.inbounds) === 'array') ? cfg.inbounds : [];
    let out = [];
    for (let i = 0; i < length(inbounds); i++) {
        let inb = inbounds[i];
        if (!inb || type(inb) !== 'object') continue;
        push(out, sprintf("%s/%s/%s", inb.tag || "-", inb.type || "-", inb.listen_port || "-"));
    }
    return join(", ", out);
}

function _cmd_stdout(cmd) {
    let res = ExecSafe(BIN.SH, ["-c", cmd]);
    if (!res.ok || !res.data) return sprintf("(failed: %s)", res.detail || "unknown");
    return trim(res.data.stdout || "");
}

function _resolve_mode_info(cfg_info, marker) {
    cfg_info = cfg_info || { ok: false, cfg: null, error: "run.json unavailable" };
    if (!cfg_info.ok || !cfg_info.cfg) {
        return {
            mode: "unknown",
            source: "unknown",
            warning: cfg_info.error || "run.json unavailable"
        };
    }

    let cfg = cfg_info.cfg;
    let inbound_types = _load_run_inbound_types(cfg);
    let mode = "none";
    let warning = "";

    if (inbound_types.tun) mode = "tun";
    else if (inbound_types.redirect || inbound_types.tproxy) mode = "redirect_tproxy";
    else if (inbound_types.mixed || inbound_types.socks) mode = "mixed";
    else warning = "run.json has no dataplane inbound";

    if (marker && marker.mode && marker.mode !== mode) {
        warning = warning ? (warning + "; marker mode=" + marker.mode) : ("marker mode=" + marker.mode + " ignored");
    }

    return {
        mode: mode,
        source: "run_json",
        warning: warning
    };
}

function _resolve_mode(cfg, marker) {
    return _resolve_mode_info({ ok: !!cfg, cfg: cfg, error: cfg ? "" : "run.json unavailable" }, marker).mode;
}

function _is_tun_assembling(marker) {
    if (!marker || marker.mode !== "tun" || marker.phase !== "assembling_tun_device") return false;
    let ts = int(marker.timestamp || 0);
    return ts > 0 && (time() - ts) <= TUN_GRACE_SEC;
}

function _marker_fresh(path, max_age) {
    if (!access(path)) return false;
    let st = stat(path);
    if (!st || !st.mtime) return true;
    return (time() - st.mtime) <= max_age;
}

function lifecycle_grace_reason() {
    if (_marker_fresh(NETWORK_READY_MARKER, TXN_GRACE_SEC)) return ".fp_network_ready";
    if (_marker_fresh(APPLY_MARKER, TXN_GRACE_SEC)) return "apply.marker";
    if (_marker_fresh(LIFECYCLE_STARTING_MARKER, TXN_GRACE_SEC)) return "lifecycle.starting";
    if (_marker_fresh(LIFECYCLE_STOPPING_MARKER, TXN_GRACE_SEC)) return "lifecycle.stopping";
    if (_marker_fresh(LIFECYCLE_PROTECT_MARKER, TXN_GRACE_SEC)) return "lifecycle.protect";

    let marker = _load_mode_marker();
    if (_is_tun_assembling(marker)) return "assembling_tun_device";
    return "";
}

function _sync_pidfile(pid) {
    if (pid && pid > 0) {
        writefile(DATAPLANE.PROCESS.PIDFILE, sprintf("%d\n", pid));
    } else {
        unlink(DATAPLANE.PROCESS.PIDFILE);
    }
}

function _find_singbox_pid() {
    let cmd = sprintf(
        "ps w 2>/dev/null | grep '[s]ing-box' | grep ' run ' | grep -- %s | awk '{print $1; exit}'",
        shell_escape(PATH.RUN_JSON)
    );
    let res = ExecSafe(BIN.SH, ["-c", cmd]);
    if (!res.ok || !res.data || !res.data.stdout) return 0;

    let pid = int(trim(res.data.stdout));
    if (!pid || pid <= 0) return 0;
    return pid;
}

function _pid_cmdline_matches(pid) {
    let alive_res = ExecSafe(BIN.SH, ["-c", sprintf("kill -0 %d 2>/dev/null", pid)]);
    if (!alive_res.ok) return false;

    let cmdline_path = sprintf("/proc/%d/cmdline", pid);
    if (!access(cmdline_path)) return false;

    let cmdline = readfile(cmdline_path);
    if (!cmdline || length(cmdline) === 0) return false;

    return index(cmdline, DATAPLANE.PROCESS.CONF_MARKER) >= 0 && index(cmdline, "sing-box") >= 0;
}

function _log_excerpt(path, lines) {
    if (!access(path)) return "";
    let n = lines || 24;
    let res = ExecSafe(BIN.SH, ["-c", sprintf("tail -n %d %s 2>/dev/null", n, shell_escape(path))]);
    if (!res.ok || !res.data || !res.data.stdout) return "";
    return trim(res.data.stdout || "");
}

function lifecycle_error_detail(reason) {
    let parts = [];

    let run_log = _log_excerpt(PATH.LOG_RUN, 30);
    if (run_log) push(parts, "sing-box log tail: " + run_log);

    let sys_log = _log_excerpt(PATH.LOG_SYS, 20);
    if (sys_log) push(parts, "flowproxy log tail: " + sys_log);

    let logread_res = ExecSafe(BIN.SH, ["-c", "logread 2>/dev/null | grep -E 'flowproxy|sing-box|procd' | tail -n 30"]);
    if (logread_res.ok && logread_res.data && trim(logread_res.data.stdout || "")) {
        push(parts, "system log tail: " + trim(logread_res.data.stdout));
    }

    if (length(parts) === 0) return reason || "no recent lifecycle error log captured";
    return (reason ? (reason + " | ") : "") + join(" | ", parts);
}

function verify_process() {
    let pid = _find_singbox_pid();
    if (pid > 0 && _pid_cmdline_matches(pid)) {
        _sync_pidfile(pid);
        return true;
    }

    _sync_pidfile(0);
    return false;
}

function verify_run_json() {
    if (!access(PATH.RUN_JSON)) return { ok: false, detail: "sing-box run.json missing" };
    let st = stat(PATH.RUN_JSON);
    if (!st || !st.size || st.size < MIN_RUN_JSON_BYTES) {
        return { ok: false, detail: "sing-box run.json empty or invalid" };
    }
    return { ok: true, detail: "" };
}

function verify_nft_chains(need_redirect, need_tproxy) {
    let res = ExecSafe(BIN.SH, ["-c", sprintf("nft list table %s 2>/dev/null", DATAPLANE.NFT_TABLE)]);
    if (!res.ok || !res.data || !res.data.stdout || length(trim(res.data.stdout)) === 0) {
        return { ok: false, detail: sprintf("nft table %s missing", DATAPLANE.NFT_TABLE) };
    }

    let out = res.data.stdout;
    let missing = [];
    let chains = DATAPLANE.NFT_CHAINS_REQUIRED;
    for (let i = 0; i < length(chains); i++) {
        let chain = chains[i];
        if (index(out, sprintf("chain %s", chain)) < 0) push(missing, chain);
    }
    if (need_redirect && index(out, "redirect to") < 0) push(missing, "redirect rule");
    if (need_tproxy && index(out, "tproxy") < 0) push(missing, "tproxy rule");
    if (length(missing) > 0) return { ok: false, detail: "nft missing: " + join(", ", missing) };
    return { ok: true, detail: "" };
}

function verify_iprule(mark) {
    let res = ExecSafe(BIN.SH, ["-c", sprintf("ip rule show | grep -Eq 'fwmark (0x%x|%s)(/0x[0-9a-f]+)? .*lookup %s'", int(mark), mark, mark)]);
    return res.ok;
}

function verify_route(mark) {
    let res = ExecSafe(BIN.SH, ["-c", sprintf("ip route show table %s | grep -Eq 'local (0\\.0\\.0\\.0/0|default) dev lo'", mark)]);
    return res.ok;
}

function verify_tproxy_route() {
    let u = cursor();
    u.load("flowproxy");
    let mark = u.get("flowproxy", "infra", "tproxy_mark") || "101";

    if (verify_iprule(mark) && verify_route(mark)) {
        return { ok: true, detail: sprintf("fwmark lookup %s + local route ok", mark) };
    }
    return { ok: false, detail: sprintf("fwmark lookup %s or local route table missing", mark) };
}

function verify_common_process_and_config() {
    let detail = [];
    let ok = true;

    if (!verify_process()) {
        ok = false;
        push(detail, "sing-box process not running");
    }

    let cfg_chk = verify_run_json();
    if (!cfg_chk.ok) {
        ok = false;
        push(detail, cfg_chk.detail);
    }

    return { ok: ok, detail: detail };
}

function _core_proxy_port(cfg) {
    let mixed = _find_inbound(cfg, "mixed", "mixed-in");
    if (mixed && mixed.listen_port) return int(mixed.listen_port);

    let socks = _find_inbound(cfg, "socks", "socks-in");
    if (socks && socks.listen_port) return int(socks.listen_port);

    return 5330;
}

function _verify_listen_port(port) {
    let safe_port = sprintf("%d", int(port));
    let grep_expr = sprintf("(^|[.:])%s[[:space:]]", safe_port);
    let cmd = sprintf(
        "(%s -lnt 2>/dev/null || ss -lnt 2>/dev/null) | grep -Eq %s",
        shell_escape(BIN.NETSTAT),
        shell_escape(grep_expr)
    );
    let res = ExecSafe(BIN.SH, ["-c", cmd]);
    return res.ok;
}

function verify_core_proxy(trace_id, opts) {
    opts = opts || {};
    let cfg = _load_run_config();
    let port = _core_proxy_port(cfg);
    let detail = [];

    if (!verify_process()) {
        push(detail, "sing-box process not running");
    }

    let cfg_chk = verify_run_json();
    if (!cfg_chk.ok) {
        push(detail, cfg_chk.detail);
    }

    if (!_verify_listen_port(port)) {
        push(detail, sprintf("core proxy port %d not listening", port));
    }

    let skip_curl = opts.skip_curl === true;
    let curl_ok = true;
    if (!skip_curl && access(BIN.CURL)) {
        let proxy_url = sprintf("socks5h://127.0.0.1:%d", port);
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
        curl_ok = curl_res.ok && code === "204";
        if (!curl_ok) {
            push(detail, sprintf("proxy curl failed: http_code=%s detail=%s", code || "-", curl_res.detail || "unknown"));
        }
    }

    let ok = length(detail) === 0;
    if (ok) {
        log(trace_id, "INFO", "CORE_VERIFY", sprintf("core proxy verify success: port=%d", port));
    } else {
        log(trace_id, "WARN", "CORE_VERIFY", "core proxy verify failed: " + join(" | ", detail));
    }

    return {
        ok: ok,
        error: ok ? "" : "core_proxy_incomplete",
        detail: ok ? "" : join(" | ", detail),
        process_ok: ok || index(join(",", detail), "sing-box process") < 0,
        port_ok: ok || index(join(",", detail), "not listening") < 0,
        curl_ok: curl_ok,
        port: port,
        stage: "core_proxy_verify"
    };
}

function verify_tproxy_plane(cfg, inbound_types, trace_id) {
    let common = verify_common_process_and_config();

    let need_redirect = (inbound_types.redirect == true);
    let need_tproxy = (inbound_types.tproxy == true);

    if (need_redirect && !_find_inbound(cfg, "redirect", "redirect-in")) {
        common.ok = false;
        push(common.detail, "run.json missing redirect inbound");
    }
    if (need_tproxy && !_find_inbound(cfg, "tproxy", "tproxy-in")) {
        common.ok = false;
        push(common.detail, "run.json missing tproxy inbound");
    }

    let nft_res = verify_nft_chains(need_redirect, need_tproxy);
    let route_chk = verify_tproxy_route();

    let ok = common.ok && nft_res.ok && route_chk.ok;
    let parts = [];
    if (!common.ok && length(common.detail) > 0) push(parts, "process: " + join("; ", common.detail));
    if (!nft_res.ok) push(parts, "nft: " + (nft_res.detail || "incomplete"));
    if (!route_chk.ok) push(parts, "route: " + (route_chk.detail || "incomplete"));

    if (!ok) {
        let u = cursor();
        u.load("flowproxy");
        let mark = u.get("flowproxy", "infra", "tproxy_mark") || "101";
        log(trace_id, 'WARN', 'DATAPLANE_VERIFY', sprintf(
            "mode=redirect_tproxy inbounds=[%s] ip_rule=[%s] ip_route_table_%s=[%s] ip6_rule=[%s] ip6_route_table_%s=[%s]",
            _inbound_summary(cfg),
            _cmd_stdout("ip rule show 2>/dev/null"),
            mark,
            _cmd_stdout(sprintf("ip route show table %s 2>/dev/null", shell_escape(mark))),
            _cmd_stdout("ip -6 rule show 2>/dev/null"),
            mark,
            _cmd_stdout(sprintf("ip -6 route show table %s 2>/dev/null", shell_escape(mark)))
        ));
    }

    return {
        ok: ok,
        detail: ok ? "" : join(" | ", parts),
        nft_ok: nft_res.ok,
        route_ok: route_chk.ok,
        process_ok: common.ok
    };
}

function verify_tun_interface(tun_in) {
    let iface = tun_in.interface_name || "singtun0";
    let safe_iface = shell_escape(iface);

    let up_res = ExecSafe(BIN.SH, ["-c", sprintf("ip link show dev %s 2>/dev/null | grep -q 'state UP'", safe_iface)]);
    if (!up_res.ok) {
        up_res = ExecSafe(BIN.SH, ["-c", sprintf("ip link show dev %s 2>/dev/null | grep -q 'UP'", safe_iface)]);
    }
    if (!up_res.ok) return { ok: false, detail: sprintf("%s is missing or not UP", iface), iface: iface };

    let route_res = ExecSafe(BIN.SH, ["-c", sprintf("ip route show table all dev %s 2>/dev/null | grep -q .", safe_iface)]);
    let route6_res = ExecSafe(BIN.SH, ["-c", sprintf("ip -6 route show table all dev %s 2>/dev/null | grep -q .", safe_iface)]);
    if (!route_res.ok && !route6_res.ok) {
        return { ok: false, detail: sprintf("%s has no route ownership in kernel tables", iface), iface: iface };
    }

    return { ok: true, detail: sprintf("%s UP with route ownership", iface), iface: iface };
}

function verify_tun_plane(cfg, marker, trace_id) {
    let common = verify_common_process_and_config();
    let tun_in = _find_inbound(cfg, "tun", "tun-in");
    let grace = _is_tun_assembling(marker);

    if (!tun_in) {
        common.ok = false;
        push(common.detail, "run.json missing tun-in inbound");
    }

    let tun_ok = false;
    let tun_detail = "";
    if (tun_in) {
        let tun_chk = verify_tun_interface(tun_in);
        tun_ok = tun_chk.ok;
        tun_detail = tun_chk.detail || "";
    }

    let process_ok = common.ok;
    if (grace && (!process_ok || !tun_ok)) {
        return {
            ok: true,
            detail: "TUN plane is within assembling_tun_device grace window",
            nft_ok: true,
            route_ok: true,
            process_ok: true,
            tun_ok: true,
            transient: true
        };
    }

    let ok = process_ok && tun_ok;
    let parts = [];
    if (!process_ok && length(common.detail) > 0) push(parts, "process: " + join("; ", common.detail));
    if (!tun_ok) push(parts, "tun: " + (tun_detail || "interface incomplete"));

    return {
        ok: ok,
        detail: ok ? "" : join(" | ", parts),
        nft_ok: true,
        route_ok: tun_ok,
        process_ok: process_ok,
        tun_ok: tun_ok,
        transient: false
    };
}

function _push_unique(arr, key) {
    for (let i = 0; i < length(arr); i++) {
        if (arr[i] === key) return;
    }
    push(arr, key);
}

function _raw_failed(dp) {
    let failed = [];
    if (dp.mode === "unknown") _push_unique(failed, "mode_detection_failed");
    if (!dp.config_ok) _push_unique(failed, "config");
    if (!dp.process_ok) _push_unique(failed, "process");
    if (!dp.nft_ok) _push_unique(failed, "nft");
    if (!dp.route_ok) _push_unique(failed, dp.mode === "tun" ? "tun" : "route");
    return failed;
}

function _failed_allowed(mode, key) {
    if (key === "process" || key === "listener" || key === "config") return true;

    if (mode === "redirect_tproxy") {
        return key === "nft" || key === "route" || key === "ip_rule";
    }

    if (mode === "tun") {
        return key === "tun" || key === "tun_iface" || key === "tun_route" || key === "auto_route";
    }

    if (mode === "mixed" || mode === "none" || mode === "unknown") {
        return key === "mode" || key === "mode_detection_failed";
    }

    return false;
}

function _filter_failed(raw, mode) {
    let filtered = [];
    for (let i = 0; i < length(raw); i++) {
        let key = raw[i];
        if (_failed_allowed(mode, key)) _push_unique(filtered, key);
    }
    return filtered;
}

function _failed_detail(key, dp) {
    if (key === "mode_detection_failed") return dp.mode_warning || "run.json/mode detection failed";
    if (key === "config") return "run.json missing, empty, or invalid";
    if (key === "process") return "sing-box process or required runtime config is unavailable";
    if (key === "nft") return "nft table/chains/rules missing";
    if (key === "route") return "fwmark lookup/table route missing";
    if (key === "tun") return "TUN interface or TUN route ownership missing";
    if (key === "listener") return "listener port missing";
    return dp.detail || key;
}

function _missing_items(failed, mode, dp) {
    let items = [];
    for (let i = 0; i < length(failed); i++) {
        let key = failed[i];
        push(items, {
            key: key,
            mode: mode,
            category: (key === "process" || key === "listener" || key === "config" || key === "mode_detection_failed") ? "core" : "dataplane",
            detail: _failed_detail(key, dp)
        });
    }
    return items;
}

function dataplane_verify(trace_id) {
    let cfg_info = _load_run_config_info();
    let cfg = cfg_info.cfg;
    let marker = _load_mode_marker();
    let inbound_types = _load_run_inbound_types(cfg);
    let mode_info = _resolve_mode_info(cfg_info, marker);
    let mode = mode_info.mode;

    if (mode === "unknown") {
        log(trace_id, 'WARN', 'HEALTHCHECK', 'mode detection failed: ' + (mode_info.warning || "unknown"));
    } else if (mode_info.warning) {
        log(trace_id, 'WARN', 'HEALTHCHECK', sprintf(
            'mode warning: mode=%s source=%s warning=%s',
            mode, mode_info.source, mode_info.warning
        ));
    }

    let plane_res;
    if (mode === "tun") {
        plane_res = verify_tun_plane(cfg, marker, trace_id);
    } else if (mode === "redirect_tproxy") {
        plane_res = verify_tproxy_plane(cfg, inbound_types, trace_id);
    } else {
        let common = verify_common_process_and_config();
        plane_res = {
            ok: common.ok,
            detail: common.ok ? "" : "process: " + join("; ", common.detail),
            nft_ok: true,
            route_ok: true,
            process_ok: common.ok
        };
    }

    return {
        ok: plane_res.ok,
        error: plane_res.ok ? "" : "dataplane_incomplete",
        detail: plane_res.detail || "",
        mode: mode,
        mode_source: mode_info.source,
        mode_warning: mode_info.warning || "",
        config_ok: !!cfg_info.ok,
        stage: STAGE_DATAPLANE,
        nft_ok: plane_res.nft_ok,
        route_ok: plane_res.route_ok,
        process_ok: plane_res.process_ok,
        tun_ok: plane_res.tun_ok,
        transient: plane_res.transient || false
    };
}

function verify_redirect_tproxy(trace_id) {
    let cfg_info = _load_run_config_info();
    let cfg = cfg_info.cfg;
    let inbound_types = _load_run_inbound_types(cfg);
    if (!cfg_info.ok) {
        return {
            ok: false,
            detail: cfg_info.error || "run.json unavailable",
            mode: "redirect_tproxy",
            stage: STAGE_DATAPLANE
        };
    }
    let res = verify_tproxy_plane(cfg, inbound_types, trace_id);
    res.mode = "redirect_tproxy";
    res.stage = STAGE_DATAPLANE;
    return res;
}

function verify_tun(trace_id) {
    let cfg_info = _load_run_config_info();
    let cfg = cfg_info.cfg;
    let marker = _load_mode_marker();
    if (!cfg_info.ok) {
        return {
            ok: false,
            detail: cfg_info.error || "run.json unavailable",
            mode: "tun",
            stage: STAGE_DATAPLANE
        };
    }
    let res = verify_tun_plane(cfg, marker, trace_id);
    res.mode = "tun";
    res.stage = STAGE_DATAPLANE;
    return res;
}

const HealthCheck = {
    verify: function(opts) {
        opts = opts || {};
        let dp = dataplane_verify(null);
        let raw_failed = _raw_failed(dp);
        let failed = _filter_failed(raw_failed, dp.mode);
        if (join(",", raw_failed) !== join(",", failed)) {
            log(null, 'WARN', 'HEALTHCHECK', sprintf(
                'mode-aware failed raw=[%s] filtered=[%s] mode=%s source=%s',
                join(",", raw_failed),
                join(",", failed),
                dp.mode,
                dp.mode_source || "unknown"
            ));
        } else {
            log(null, 'INFO', 'HEALTHCHECK', sprintf(
                'mode-aware failed raw=[%s] filtered=[%s] mode=%s source=%s',
                join(",", raw_failed),
                join(",", failed),
                dp.mode,
                dp.mode_source || "unknown"
            ));
        }
        let grace_reason = lifecycle_grace_reason();
        if (!dp.ok && opts.allow_transient === true && grace_reason) {
            return {
                ok: true,
                failed: [],
                mode: dp.mode,
                mode_source: dp.mode_source,
                mode_warning: dp.mode_warning,
                missing: {
                    mode: dp.mode,
                    mode_source: dp.mode_source,
                    mode_warning: dp.mode_warning,
                    failed: [],
                    items: []
                },
                transient: true,
                grace_reason: grace_reason,
                dataplane: dp
            };
        }
        return {
            ok: dp.ok,
            failed: failed,
            mode: dp.mode,
            mode_source: dp.mode_source,
            mode_warning: dp.mode_warning,
            missing: {
                mode: dp.mode,
                mode_source: dp.mode_source,
                mode_warning: dp.mode_warning,
                failed: failed,
                items: _missing_items(failed, dp.mode, dp)
            },
            transient: false,
            grace_reason: "",
            dataplane: dp
        };
    }
};

export { HealthCheck, dataplane_verify, verify_tun, verify_redirect_tproxy, verify_process, verify_core_proxy, lifecycle_grace_reason, lifecycle_error_detail };
