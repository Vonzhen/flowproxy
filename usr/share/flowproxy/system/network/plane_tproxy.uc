/**
 * FlowProxy | system/network/plane_tproxy.uc | v2.0
 * Role: Redirect TCP + TProxy UDP dataplane assembly.
 */

'use strict';

import { cursor } from 'uci';
import { access, readfile, writefile } from 'fs';

import { PATH, BIN, DATAPLANE } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { ExecSafe, shell_escape } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';
import { build_tproxy_firewall } from 'flowproxy.system.network.firewall_tproxy';

const MODE_MARKER = sprintf("%s/dataplane.mode", PATH.RUNTIME);

function has_tproxy_inbound(run_config) {
    let inbounds = (run_config && type(run_config.inbounds) === 'array') ? run_config.inbounds : [];
    for (let i = 0; i < length(inbounds); i++) {
        if (inbounds[i].type === 'tproxy') return true;
    }
    return false;
}

function find_inbound(run_config, inbound_type, tag) {
    let inbounds = (run_config && type(run_config.inbounds) === 'array') ? run_config.inbounds : [];
    for (let i = 0; i < length(inbounds); i++) {
        let inb = inbounds[i];
        if (!inb || type(inb) !== 'object') continue;
        if ((inbound_type && inb.type === inbound_type) || (tag && inb.tag === tag)) return inb;
    }
    return null;
}

function validate_redirect_tproxy_inbounds(run_config) {
    if (!find_inbound(run_config, 'redirect', 'redirect-in')) return "redirect-in inbound missing";
    if (!find_inbound(run_config, 'tproxy', 'tproxy-in')) return "tproxy-in inbound missing";
    let inbounds = (run_config && type(run_config.inbounds) === 'array') ? run_config.inbounds : [];
    for (let i = 0; i < length(inbounds); i++) {
        if (inbounds[i].type === 'tun') return "Redirect+TProxy plane run.json contains tun inbound";
    }
    return null;
}

function write_mode_marker(trace_id, tproxy_mark) {
    let marker = {
        mode: "redirect_tproxy",
        phase: "assembled_redirect_tproxy",
        tproxy_mark: tproxy_mark || "101",
        timestamp: time()
    };

    let ok = writefile(MODE_MARKER, sprintf("%.J", marker));
    if (!ok) return Fail(ERR.E_SYSTEM_BUSY, "failed to write Redirect+TProxy mode marker: " + MODE_MARKER, trace_id);
    return Success(true, 200, trace_id);
}

function read_marker_mark() {
    if (!access(MODE_MARKER)) return null;
    try {
        let marker = json(readfile(MODE_MARKER) || "{}");
        if (marker && marker.tproxy_mark) return marker.tproxy_mark;
    } catch(e) {}
    return null;
}

function add_mark_once(marks, mark) {
    if (!mark) return;
    for (let i = 0; i < length(marks); i++) {
        if (marks[i] === mark) return;
    }
    push(marks, mark);
}

function setup_redirect_tproxy(trace_id, run_config) {
    try {
        log(trace_id, 'INFO', 'PLANE_TPROXY', 'Assembling Redirect+TProxy dataplane...');

        let u = cursor();
        u.load("flowproxy");
        let ipv6_support = u.get("flowproxy", "config", "ipv6_support") === '1';
        let tproxy_mark = u.get("flowproxy", "infra", "tproxy_mark") || "101";
        let validation_error = validate_redirect_tproxy_inbounds(run_config);
        if (validation_error) return Fail(ERR.E_CONFIG_FAULT, validation_error, trace_id);

        if (has_tproxy_inbound(run_config)) {
            log(trace_id, 'INFO', 'PLANE_TPROXY', 'Assembling Linux policy routing for UDP TProxy...');

            let res;
            let t_mark = tproxy_mark;

            ExecSafe(BIN.SH, ['-c', sprintf("while ip rule del fwmark %s table %s 2>/dev/null; do :; done", t_mark, t_mark)], null, trace_id);
            let cmd_rule_v4 = sprintf("ip rule add fwmark %s table %s 2>&1", t_mark, t_mark);
            res = ExecSafe(BIN.SH, ['-c', cmd_rule_v4], null, trace_id);
            if (!res.ok || (res.data && index(res.data.stdout || "", "RTNETLINK") !== -1)) {
                let err_msg = (res.data && res.data.stdout) ? res.data.stdout : (res.detail || "Unknown shell error");
                log(trace_id, 'CRIT', 'PLANE_TPROXY', 'IPv4 ip rule setup failed. RAW ERROR: ' + err_msg);
                return Fail(ERR.E_SYSTEM_BUSY, "IPv4 ip rule error: " + err_msg, trace_id);
            }

            ExecSafe(BIN.SH, ['-c', sprintf("ip route flush table %s 2>/dev/null", t_mark)], null, trace_id);
            ExecSafe(BIN.SH, ['-c', sprintf("ip route del local 0.0.0.0/0 dev lo table %s 2>/dev/null || true", t_mark)], null, trace_id);
            let cmd_route_v4 = sprintf("ip route add local 0.0.0.0/0 dev lo table %s 2>&1", t_mark);
            res = ExecSafe(BIN.SH, ['-c', cmd_route_v4], null, trace_id);
            if (!res.ok || (res.data && index(res.data.stdout || "", "RTNETLINK") !== -1)) {
                let err_msg = (res.data && res.data.stdout) ? res.data.stdout : (res.detail || "Unknown shell error");
                log(trace_id, 'CRIT', 'PLANE_TPROXY', 'IPv4 ip route setup failed. RAW ERROR: ' + err_msg);
                return Fail(ERR.E_SYSTEM_BUSY, "IPv4 ip route error: " + err_msg, trace_id);
            }

            if (ipv6_support) {
                ExecSafe(BIN.SH, ['-c', sprintf("while ip -6 rule del fwmark %s table %s 2>/dev/null; do :; done", t_mark, t_mark)], null, trace_id);
                let cmd_rule_v6 = sprintf("ip -6 rule add fwmark %s table %s 2>&1", t_mark, t_mark);
                res = ExecSafe(BIN.SH, ['-c', cmd_rule_v6], null, trace_id);
                if (!res.ok || (res.data && index(res.data.stdout || "", "RTNETLINK") !== -1)) {
                    let err_msg = (res.data && res.data.stdout) ? res.data.stdout : (res.detail || "Unknown shell error");
                    log(trace_id, 'CRIT', 'PLANE_TPROXY', 'IPv6 ip rule setup failed. RAW ERROR: ' + err_msg);
                    return Fail(ERR.E_SYSTEM_BUSY, "IPv6 ip rule error: " + err_msg, trace_id);
                }

                ExecSafe(BIN.SH, ['-c', sprintf("ip -6 route flush table %s 2>/dev/null", t_mark)], null, trace_id);
                ExecSafe(BIN.SH, ['-c', sprintf("ip -6 route del local ::/0 dev lo table %s 2>/dev/null || true", t_mark)], null, trace_id);
                let cmd_route_v6 = sprintf("ip -6 route add local ::/0 dev lo table %s 2>&1", t_mark);
                res = ExecSafe(BIN.SH, ['-c', cmd_route_v6], null, trace_id);
                if (!res.ok || (res.data && index(res.data.stdout || "", "RTNETLINK") !== -1)) {
                    let err_msg = (res.data && res.data.stdout) ? res.data.stdout : (res.detail || "Unknown shell error");
                    log(trace_id, 'CRIT', 'PLANE_TPROXY', 'IPv6 ip route setup failed. RAW ERROR: ' + err_msg);
                    return Fail(ERR.E_SYSTEM_BUSY, "IPv6 ip route error: " + err_msg, trace_id);
                }
            }
        }

        let fw_compile_res = build_tproxy_firewall(trace_id);
        if (!fw_compile_res.ok) {
            log(trace_id, 'CRIT', 'PLANE_TPROXY', 'Firewall compilation failed. Aborting kernel injection.');
            return fw_compile_res;
        }

        log(trace_id, 'INFO', 'PLANE_TPROXY', 'Injecting Redirect+TProxy nftables ruleset...');
        let nft_load_res = ExecSafe(BIN.NFT, ['-f', PATH.FIREWALL_NFT], null, trace_id);
        if (!nft_load_res.ok) {
            let nft_err = nft_load_res.detail || 'Unknown nftables syntax fault';
            log(trace_id, 'CRIT', 'PLANE_TPROXY', 'Kernel injection rejected by nftables: ' + nft_err);
            return Fail(ERR.E_SYSTEM_BUSY, "Nftables Kernel Injection Failed: " + nft_err, trace_id);
        }

        let marker_res = write_mode_marker(trace_id, tproxy_mark);
        if (!marker_res.ok) return marker_res;

        log(trace_id, 'INFO', 'PLANE_TPROXY', 'Redirect+TProxy dataplane setup completed.');
        return Success(true, 200, trace_id);
    } catch(e) {
        let err_msg = "" + e;
        log(trace_id, 'CRIT', 'PLANE_TPROXY', 'Setup Exception: ' + err_msg);
        return Fail(ERR.E_SYSTEM_BUSY, "TProxy Plane Setup Exception: " + err_msg, trace_id);
    }
}

function teardown_redirect_tproxy(trace_id, run_config, opts) {
    try {
        opts = (type(opts) === 'object') ? opts : {};
        let reason = opts.reason || "unknown";
        log(trace_id, 'INFO', 'PLANE_TPROXY', 'teardown_redirect_tproxy begin reason=' + reason);

        let u = cursor();
        u.load("flowproxy");
        let tproxy_mark = u.get("flowproxy", "infra", "tproxy_mark") || "101";
        let marker_mark = read_marker_mark();
        let marks = [];
        add_mark_once(marks, marker_mark);
        add_mark_once(marks, tproxy_mark);
        add_mark_once(marks, "101");

        ExecSafe(BIN.SH, ['-c', sprintf('nft delete table %s 2>/dev/null || true', DATAPLANE.NFT_TABLE)], null, trace_id);
        for (let i = 0; i < length(marks); i++) {
            let mark = shell_escape(marks[i]);
            ExecSafe(BIN.SH, ['-c', sprintf('while ip rule del fwmark %s table %s 2>/dev/null; do :; done', mark, mark)], null, trace_id);
            ExecSafe(BIN.SH, ['-c', sprintf('while ip -6 rule del fwmark %s table %s 2>/dev/null; do :; done', mark, mark)], null, trace_id);
            ExecSafe(BIN.SH, ['-c', sprintf('ip route flush table %s 2>/dev/null || true', mark)], null, trace_id);
            ExecSafe(BIN.SH, ['-c', sprintf('ip -6 route flush table %s 2>/dev/null || true', mark)], null, trace_id);
        }
        ExecSafe(BIN.RM, ['-f', MODE_MARKER], null, trace_id);

        log(trace_id, 'INFO', 'PLANE_TPROXY', 'teardown_redirect_tproxy completed marks=' + join(",", marks));
        return Success(true, 200, trace_id);
    } catch(e) {
        let err_msg = "" + e;
        log(trace_id, 'CRIT', 'PLANE_TPROXY', 'Teardown Exception: ' + err_msg);
        return Fail(ERR.E_SYSTEM_BUSY, "TProxy Plane Teardown Exception: " + err_msg, trace_id);
    }
}

const setup = setup_redirect_tproxy;

export { setup_redirect_tproxy, teardown_redirect_tproxy, setup };
