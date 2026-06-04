/**
 * FlowProxy | system/network/plane_tun.uc | v2.0
 * Role: pure TUN preflight plane. sing-box owns TUN device, addresses,
 * auto_route, strict_route, and auto_redirect lifecycle.
 */

'use strict';

import { access, writefile } from 'fs';

import { PATH, BIN } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { ExecSafe, shell_escape } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';

const MODE_MARKER = sprintf("%s/dataplane.mode", PATH.RUNTIME);

function find_tun_inbound(run_config) {
    let inbounds = (run_config && type(run_config.inbounds) === 'array') ? run_config.inbounds : [];
    let tun_in = null;

    for (let i = 0; i < length(inbounds); i++) {
        let inb = inbounds[i];
        if (!inb || type(inb) !== 'object') continue;

        if (inb.type === 'redirect' || inb.type === 'tproxy') {
            return { ok: false, detail: "TUN plane run.json contains legacy inbound: " + inb.type };
        }

        if (inb.type === 'tun' || inb.tag === 'tun-in') tun_in = inb;
    }

    if (!tun_in) return { ok: false, detail: "tun-in inbound missing" };
    return { ok: true, data: tun_in };
}

function validate_tun_inbound(tun_in) {
    if (tun_in.type !== 'tun') return "tun-in type must be tun";
    if (tun_in.tag !== 'tun-in') return "tun inbound tag must be tun-in";
    if (!tun_in.interface_name) return "tun-in interface_name missing";
    if (type(tun_in.address) !== 'array' || length(tun_in.address) === 0) return "tun-in address missing";
    if (!tun_in.mtu) return "tun-in mtu missing";
    if (tun_in.auto_route !== true) return "tun-in auto_route must be true";
    if (tun_in.strict_route !== true) return "tun-in strict_route must be true";
    if (tun_in.auto_redirect !== true) return "tun-in auto_redirect must be true";
    if (!tun_in.dns_mode) return "tun-in dns_mode missing";
    if (!tun_in.stack) return "tun-in stack missing";
    return null;
}

function write_mode_marker(trace_id, tun_in) {
    let marker = {
        mode: "tun",
        phase: "assembling_tun_device",
        interface_name: tun_in.interface_name,
        timestamp: time()
    };

    let ok = writefile(MODE_MARKER, sprintf("%.J", marker));
    if (!ok) return Fail(ERR.E_SYSTEM_BUSY, "failed to write TUN mode marker: " + MODE_MARKER, trace_id);
    return Success(true, 200, trace_id);
}

function setup_tun(trace_id, run_config) {
    try {
        log(trace_id, 'INFO', 'PLANE_TUN', 'assembling_tun_device: starting TUN preflight.');

        if (!access('/dev/net/tun')) {
            return Fail(ERR.E_SYSTEM_BUSY, "/dev/net/tun missing; kernel TUN clone device is unavailable", trace_id);
        }

        let inbound_res = find_tun_inbound(run_config);
        if (!inbound_res.ok) return Fail(ERR.E_CONFIG_FAULT, inbound_res.detail, trace_id);

        let tun_in = inbound_res.data;
        let validation_error = validate_tun_inbound(tun_in);
        if (validation_error) return Fail(ERR.E_CONFIG_FAULT, validation_error, trace_id);

        let marker_res = write_mode_marker(trace_id, tun_in);
        if (!marker_res.ok) return marker_res;

        log(trace_id, 'INFO', 'PLANE_TUN', 'TUN preflight completed. Device creation remains owned by sing-box.');
        return Success(true, 200, trace_id);
    } catch(e) {
        let err_msg = "" + e;
        log(trace_id, 'CRIT', 'PLANE_TUN', 'Setup Exception: ' + err_msg);
        return Fail(ERR.E_SYSTEM_BUSY, "TUN Plane Setup Exception: " + err_msg, trace_id);
    }
}

function teardown_tun(trace_id, run_config, opts) {
    try {
        opts = (type(opts) === 'object') ? opts : {};
        let reason = opts.reason || "unknown";
        log(trace_id, 'INFO', 'PLANE_TUN', 'teardown_tun begin reason=' + reason);

        let iface = "singtun0";
        let inbound_res = find_tun_inbound(run_config);
        if (inbound_res && inbound_res.ok && inbound_res.data && inbound_res.data.interface_name) {
            iface = inbound_res.data.interface_name;
        }

        let safe_iface = shell_escape(iface);
        ExecSafe(BIN.SH, ['-c', sprintf('ip link set %s down 2>/dev/null || true', safe_iface)], null, trace_id);
        ExecSafe(BIN.SH, ['-c', sprintf('ip tuntap del mode tun name %s 2>/dev/null || true', safe_iface)], null, trace_id);
        ExecSafe(BIN.RM, ['-f', MODE_MARKER], null, trace_id);

        log(trace_id, 'INFO', 'PLANE_TUN', 'teardown_tun completed iface=' + iface);
        return Success(true, 200, trace_id);
    } catch(e) {
        let err_msg = "" + e;
        log(trace_id, 'CRIT', 'PLANE_TUN', 'Teardown Exception: ' + err_msg);
        return Fail(ERR.E_SYSTEM_BUSY, "TUN Plane Teardown Exception: " + err_msg, trace_id);
    }
}

const setup = setup_tun;

export { setup_tun, teardown_tun, setup };
