/**
 * FlowProxy | modules/protocols/legacy.uc
 * Legacy protocol parser fallback extracted from modules/subscription.uc.
 *
 * Phase 3.5a only: this module is not wired into subscription.uc yet.
 */

'use strict';

import { log } from 'flowproxy.core.logger';
import {
    _urldecode,
    _decode_base64_str,
    _parse_url,
    _resolve_server_target,
    _generate_stable_id
} from 'flowproxy.modules.protocols.common';

function _probe_match_value(v) {
    v = trim(sprintf("%s", v || ""));
    if (index(v, "26cnmdsb.266nets.com") >= 0) return true;
    if (index(v, "24.d.d.d.d.266nets.com") >= 0) return true;
    return false;
}

function _probe_should_log(raw_uri, url, params, target) {
    if (_probe_match_value(raw_uri)) return true;
    if (url && (_probe_match_value(url.hostname) || _probe_match_value(url.port))) return true;
    params = params || {};
    if (_probe_match_value(params.server)) return true;
    if (_probe_match_value(params.address)) return true;
    if (_probe_match_value(params.add)) return true;
    if (_probe_match_value(params.remote)) return true;
    if (_probe_match_value(params.endpoint)) return true;
    if (_probe_match_value(params.host)) return true;
    if (_probe_match_value(params.sni)) return true;
    if (target && (_probe_match_value(target.host) || _probe_match_value(target.port) || _probe_match_value(target.source))) return true;
    return false;
}

function _probe_log_server_target(trace_id, stage, raw_uri, scheme, url, params, target, config) {
    try {
        params = params || {};
        if (!_probe_should_log(raw_uri, url, params, target)) return;

        log(trace_id, 'WARN', 'SUBSCRIPTION', sprintf(
            "[PARSE_PROBE:%s] scheme=%s authority_host=%s authority_port=%s q_server=%s q_address=%s q_add=%s q_remote=%s q_endpoint=%s q_host=%s q_sni=%s target_host=%s target_port=%s target_source=%s final_address=%s label=%s raw_uri=%s",
            stage || "-",
            scheme || "-",
            url ? (url.hostname || "-") : "-",
            url ? (url.port || "-") : "-",
            params.server || "-",
            params.address || "-",
            params.add || "-",
            params.remote || "-",
            params.endpoint || "-",
            params.host || "-",
            params.sni || "-",
            target ? (target.host || "-") : "-",
            target ? (target.port || "-") : "-",
            target ? (target.source || "-") : "-",
            config ? (config.address || "-") : "-",
            config ? (config.label || "-") : "-",
            raw_uri || "-"
        ));
    } catch (e) {
        log(trace_id, 'WARN', 'SUBSCRIPTION', '[PARSE_PROBE:skipped] ' + ("" + e));
    }
}

function parse(uri, global_opts, trace_id) {
    let raw_uri = trim(uri);
    let parts = split(raw_uri, '://');
    if (length(parts) < 2) return null;

    let scheme = parts[0];
    let url = _parse_url(raw_uri);
    let params = url ? url.searchParams : {};
    let config = null;

    let default_label = (url && url.hash) ? url.hash : "";
    let scheme_upper = uc(scheme);

    // Normalize allowInsecure / insecure / allow_insecure flags.
    let p_insec = params.allowInsecure || params.insecure || params.allow_insecure || "";
    let is_insec = (p_insec === '1' || p_insec === 'true') ? '1' : '0';

    let v_json = null, ss_parts, full_dec, full_url, up, dec, hy2_pass, server_target, transport;

    switch (scheme) {
        case 'vless':
            if (params.type === 'kcp') return null;
            transport = (params.type && params.type !== 'tcp') ? params.type : "";
            server_target = _resolve_server_target(url, params, scheme, params.type || "");
            config = {
                label: default_label, type: 'vless', address: server_target.host, port: server_target.port, uuid: url.username,
                tls: (params.security === 'tls' || params.security === 'xtls' || params.security === 'reality') ? '1' : '0',
                tls_sni: params.sni || "", tls_utls: params.fp || "",
                tls_reality: (params.security === 'reality') ? '1' : '0',
                tls_reality_public_key: params.pbk || "", tls_reality_short_id: params.sid || "",
                vless_flow: (params.security === 'tls' || params.security === 'reality') ? (params.flow || "") : "",
                transport: transport,
                tls_alpn: params.alpn || "", tls_insecure: is_insec
            };
            _probe_log_server_target(trace_id, "vless-after-target", raw_uri, scheme, url, params, server_target, config);
            if (params.type === 'ws') {
                config.ws_host = params.host || "";
                config.ws_path = params.path || "";
                let ed_idx = index(config.ws_path, "?ed=");
                if (ed_idx >= 0) {
                    config.websocket_early_data_header = 'Sec-WebSocket-Protocol';
                    config.websocket_early_data = substr(config.ws_path, ed_idx + 4);
                    config.ws_path = substr(config.ws_path, 0, ed_idx);
                }
            } else if (params.type === 'grpc') {
                config.grpc_servicename = params.serviceName || "";
            }
            break;
        case 'vmess':
            try { v_json = json(_decode_base64_str(parts[1])); } catch(e) {}
            if (v_json && v_json.v == '2') {
                config = {
                    label: v_json.ps ? _urldecode(v_json.ps) : "", type: 'vmess', address: v_json.add, port: v_json.port + "", uuid: v_json.id,
                    vmess_alterid: v_json.aid + "", vmess_encrypt: v_json.scy || 'auto', transport: (v_json.net !== 'tcp') ? (v_json.net || "") : "",
                    tls: (v_json.tls === 'tls') ? '1' : '0', tls_sni: v_json.sni || v_json.host || "", tls_utls: v_json.fp || ""
                };
                if (v_json.net === 'ws') {
                    config.ws_host = v_json.host || "";
                    config.ws_path = v_json.path || "";
                    let ed_idx = index(config.ws_path, "?ed=");
                    if (ed_idx >= 0) {
                        config.websocket_early_data_header = 'Sec-WebSocket-Protocol';
                        config.websocket_early_data = substr(config.ws_path, ed_idx + 4);
                        config.ws_path = substr(config.ws_path, 0, ed_idx);
                    }
                } else if (v_json.net === 'grpc') {
                    config.grpc_servicename = v_json.path || "";
                }
            }
            break;
        case 'ss':
            dec = _decode_base64_str(url.username);
            if (!dec && length(url.hostname) > 20) { full_dec = _decode_base64_str(url.hostname); if (full_dec) { full_url = _parse_url("ss://" + full_dec); if (full_url) { up = split(full_url.username, ':'); config = { label: "", type: 'shadowsocks', address: full_url.hostname, port: full_url.port, shadowsocks_encrypt_method: up[0] || "", password: up[1] || "" }; } } } else if (dec) { up = split(dec, ':'); config = { label: "", type: 'shadowsocks', address: url.hostname, port: url.port, shadowsocks_encrypt_method: up[0] || "", password: up[1] || "" }; }
            if (config) { ss_parts = split(parts[1], '#'); config.label = (length(ss_parts) >= 2) ? _urldecode(ss_parts[1]) : ""; }
            break;
        case 'trojan':
            transport = (params.type && params.type !== 'tcp') ? params.type : "";
            server_target = _resolve_server_target(url, params, scheme, params.type || "");
            config = {
                label: default_label, type: 'trojan', address: server_target.host, port: server_target.port, password: url.username,
                transport: transport,
                tls: '1', tls_sni: params.sni || "", tls_utls: params.fp || "", tls_insecure: is_insec
            };
            _probe_log_server_target(trace_id, "trojan-after-target", raw_uri, scheme, url, params, server_target, config);
            if (params.type === 'ws') {
                config.ws_host = params.host || "";
                config.ws_path = params.path || "";
                let ed_idx = index(config.ws_path, "?ed=");
                if (ed_idx >= 0) {
                    config.websocket_early_data_header = 'Sec-WebSocket-Protocol';
                    config.websocket_early_data = substr(config.ws_path, ed_idx + 4);
                    config.ws_path = substr(config.ws_path, 0, ed_idx);
                }
            } else if (params.type === 'grpc') { config.grpc_servicename = params.serviceName || ""; }
            break;
        case 'tuic':
            server_target = _resolve_server_target(url, params, scheme, "");
            config = { label: default_label, type: 'tuic', address: server_target.host, port: server_target.port, uuid: url.username, password: url.password || "", tls: '1', tls_sni: params.sni || "", tuic_congestion_control: params.congestion_control || "", tuic_udp_relay_mode: params.udp_relay_mode || "", tls_alpn: params.alpn || "", tls_insecure: is_insec };
            _probe_log_server_target(trace_id, "tuic-after-target", raw_uri, scheme, url, params, server_target, config);
            break;
        case 'anytls':
            server_target = _resolve_server_target(url, params, scheme, "");
            config = { label: default_label, type: 'anytls', address: server_target.host, port: server_target.port, password: url.username, tls: '1', tls_sni: params.sni || "", tls_insecure: is_insec };
            _probe_log_server_target(trace_id, "anytls-after-target", raw_uri, scheme, url, params, server_target, config);
            break;
        case 'hysteria2':
        case 'hy2':
            server_target = _resolve_server_target(url, params, scheme, "");
            hy2_pass = url.username || ""; if (url.password) hy2_pass += ":" + url.password;
            config = { label: default_label, type: 'hysteria2', address: server_target.host, port: server_target.port, password: hy2_pass, hysteria_obfs_type: params.obfs || "", hysteria_obfs_password: params['obfs-password'] || "", tls: '1', tls_insecure: is_insec, tls_sni: params.sni || "" };
            _probe_log_server_target(trace_id, "hy2-after-target", raw_uri, scheme, url, params, server_target, config);
            break;
    }

    if (!config || !config.address || config.address === "") return null;

    config.label = replace(config.label || "", regexp("[\r\n\t]", 'g'), " ");
    config.label = trim(config.label);

    if (length(config.label) === 0) config.label = sprintf("[%s] %s:%s", scheme_upper, config.address, config.port);

    config.address = replace(config.address, regexp('[\\[\\]]', 'g'), '');
    let finger_raw = sprintf("%s|%s|%s|%s|%s", config.type, config.address, config.port, config.uuid || config.password || "", config.transport || "");
    config.id = _generate_stable_id(finger_raw);

    if (config.tls === '1' && global_opts.allow_insecure === '1') config.tls_insecure = '1';
    if (global_opts.packet_encoding && (config.type === 'vless' || config.type === 'vmess')) config.packet_encoding = global_opts.packet_encoding;

    return config;
}

export { parse };
