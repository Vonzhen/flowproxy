/**
 * FlowProxy | modules/protocols/registry.uc
 * Explicit protocol parser registry. Do not use runtime directory scans.
 */

'use strict';

import { log } from 'flowproxy.core.logger';
import {
    _parse_url,
    _generate_stable_id
} from 'flowproxy.modules.protocols.common';
import { parse as parse_anytls } from 'flowproxy.modules.protocols.anytls';
import { parse as parse_tuic } from 'flowproxy.modules.protocols.tuic';
import { parse as parse_hysteria2 } from 'flowproxy.modules.protocols.hysteria2';
import { parse as parse_trojan } from 'flowproxy.modules.protocols.trojan';
import { parse as parse_shadowsocks } from 'flowproxy.modules.protocols.shadowsocks';
import { parse as parse_vless } from 'flowproxy.modules.protocols.vless';
import { parse as parse_vmess } from 'flowproxy.modules.protocols.vmess';

let REGISTRY = {};

function register(scheme, parser) {
    REGISTRY[scheme] = parser;
}

register("anytls", parse_anytls);
register("tuic", parse_tuic);
register("hysteria2", parse_hysteria2);
register("hy2", parse_hysteria2);
register("trojan", parse_trojan);
register("ss", parse_shadowsocks);
register("vless", parse_vless);
register("vmess", parse_vmess);

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

function _finalize_config(config, scheme, global_opts) {
    if (!config || !config.address || config.address === "") return null;

    config.label = replace(config.label || "", regexp("[\r\n\t]", 'g'), " ");
    config.label = trim(config.label);

    if (length(config.label) === 0) config.label = sprintf("[%s] %s:%s", uc(scheme), config.address, config.port);

    config.address = replace(config.address, regexp('[\\[\\]]', 'g'), '');
    let finger_raw = sprintf("%s|%s|%s|%s|%s", config.type, config.address, config.port, config.uuid || config.password || "", config.transport || "");
    config.id = _generate_stable_id(finger_raw);

    global_opts = global_opts || {};
    if (config.tls === '1' && global_opts.allow_insecure === '1') config.tls_insecure = '1';
    if (global_opts.packet_encoding && (config.type === 'vless' || config.type === 'vmess')) config.packet_encoding = global_opts.packet_encoding;

    return config;
}

function parse(uri, global_opts, trace_id) {
    let raw_uri = trim(uri);
    let parts = split(raw_uri, '://');
    if (length(parts) < 2) return null;

    let scheme = parts[0];
    let parser = REGISTRY[scheme];
    if (!parser) return null;

    let url = _parse_url(raw_uri);
    if (!url) return null;

    let params = url.searchParams || {};
    let p_insec = params.allowInsecure || params.insecure || params.allow_insecure || "";
    let is_insec = (p_insec === '1' || p_insec === 'true') ? '1' : '0';
    let parsed = parser({
        raw_uri: raw_uri,
        scheme: scheme,
        url: url,
        params: params,
        default_label: url.hash || "",
        is_insec: is_insec
    });

    if (!parsed || !parsed.config) return null;

    _probe_log_server_target(trace_id, parsed.probe_stage, raw_uri, scheme, url, params, parsed.target, parsed.config);
    return _finalize_config(parsed.config, scheme, global_opts);
}

export { parse, register };
