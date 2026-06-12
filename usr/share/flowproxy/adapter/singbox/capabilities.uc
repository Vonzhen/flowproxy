/**
 * FlowProxy | adapter/singbox/capabilities.uc
 * sing-box version capability detection entrypoint.
 *
 * Phase 6.1: detection only. This module is intentionally not wired into
 * generation, apply, or healthcheck paths yet.
 */

'use strict';

import { BIN } from 'flowproxy.core.constants';
import { ExecSafe } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';

function _cap_payload(version, capabilities) {
    return {
        version: version || "unknown",
        capabilities: capabilities
    };
}

function default_caps() {
    return _cap_payload("unknown", {
        tun_auto_redirect: true,
        dns_rule_action: true,
        dns_match_response: true,
        route_resolve_action: true,
        route_hijack_dns: true,
        route_sniff_action: true,
        cache_file_store_dns: true,
        tls_ech: true
    });
}

function _parse_version(output) {
    let raw = trim(sprintf("%s", output || ""));
    if (length(raw) === 0) return "";

    let m = match(raw, regexp('([0-9]+\\.[0-9]+\\.[0-9]+)'));
    if (m && length(m) > 1) return m[1];

    m = match(raw, regexp('([0-9]+\\.[0-9]+)'));
    if (m && length(m) > 1) return m[1];

    return "";
}

function from_version(version) {
    let v = trim(sprintf("%s", version || ""));
    let caps = default_caps();
    caps.version = length(v) > 0 ? v : "unknown";
    return caps;
}

function detect(trace_id) {
    try {
        let res = ExecSafe(BIN.SINGBOX, [ "version" ], { timeout: 5 }, trace_id);
        if (!res || !res.ok || !res.data) {
            log(trace_id, 'WARN', 'SINGBOX_CAPS', '[SINGBOX_CAPS] sing-box version probe failed; using default capabilities');
            return default_caps();
        }

        let version = _parse_version(res.data.stdout || "");
        if (length(version) === 0) {
            log(trace_id, 'WARN', 'SINGBOX_CAPS', '[SINGBOX_CAPS] sing-box version parse failed; using default capabilities');
            return default_caps();
        }

        let caps = from_version(version);
        log(trace_id, 'INFO', 'SINGBOX_CAPS', sprintf('[SINGBOX_CAPS] detected sing-box version=%s', caps.version));
        return caps;
    } catch (e) {
        log(trace_id, 'WARN', 'SINGBOX_CAPS', '[SINGBOX_CAPS] capability detection exception; using default capabilities: ' + ("" + e));
        return default_caps();
    }
}

export { detect, from_version, default_caps };
