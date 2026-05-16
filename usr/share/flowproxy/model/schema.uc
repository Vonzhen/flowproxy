/**
 * FlowProxy | model/schema.uc | v1.14 Aligned Edition
 * 配置抽象提取器 (SSOT Aligned Edition)
 */

'use strict';

import { cursor } from 'uci';
import { PATH } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';

function strToInt(val) { return (val != null && val !== "") ? int(val) : null; }
function strToBool(val) { return (val != null && val !== "") ? (val === '1' || val === 'true') : null; }
function strToTime(val) { return (val != null && val !== "") ? (val) : null; }
function parse_port(val) { return strToInt(val); }

function normalize_uuid(u) {
    if (!u || type(u) !== 'string') return u;
    if (length(u) === 32 && index(u, '-') < 0) {
        return sprintf("%s-%s-%s-%s-%s", substr(u,0,8), substr(u,8,4), substr(u,12,4), substr(u,16,4), substr(u,20,12));
    }
    return u;
}

const U_CONFIG = 'flowproxy';
const S_INFRA = 'infra';
const S_MAIN = 'config';

function build_inbounds(u) {
    let inbounds = [];
    let mixed_port = u.get(U_CONFIG, S_INFRA, 'mixed_port');
    let dns_port = u.get(U_CONFIG, S_INFRA, 'dns_port');
    let proxy_mode = u.get(U_CONFIG, S_MAIN, 'proxy_mode');

    if (dns_port) push(inbounds, { type: 'direct', tag: 'dns-in', listen: '::', listen_port: strToInt(dns_port) });
    if (mixed_port) push(inbounds, { type: 'mixed', tag: 'mixed-in', listen: '::', listen_port: strToInt(mixed_port), set_system_proxy: false });
    
    if (match(proxy_mode, /redirect/)) {
        let redirect_port = u.get(U_CONFIG, S_INFRA, 'redirect_port');
        push(inbounds, { type: 'redirect', tag: 'redirect-in', listen: '::', listen_port: strToInt(redirect_port) });
    }
    if (match(proxy_mode, /tproxy/)) {
        let tproxy_port = u.get(U_CONFIG, S_INFRA, 'tproxy_port');
        push(inbounds, { type: 'tproxy', tag: 'tproxy-in', listen: '::', listen_port: strToInt(tproxy_port), network: 'udp' });
    }
    if (match(proxy_mode, /tun/)) {
        push(inbounds, {
            type: 'tun',
            tag: 'tun-in',
            interface_name: u.get(U_CONFIG, S_INFRA, 'tun_name') || 'singtun0',
            address: [ u.get(U_CONFIG, S_INFRA, 'tun_addr4') || '172.19.0.1/30' ],
            mtu: strToInt(u.get(U_CONFIG, S_INFRA, 'tun_mtu') || '9000'),
            auto_route: true,
            strict_route: true,
            stack: 'mixed'
        });
    }

    u.foreach(U_CONFIG, 'server', (cfg) => {
        if (cfg.enabled !== '1') return;
        push(inbounds, { type: cfg.type, tag: sprintf("cfg-server-%s-in", cfg['.name']), listen: cfg.address || '::', listen_port: strToInt(cfg.port), tcp_fast_open: strToBool(cfg.tcp_fast_open), tcp_multi_path: strToBool(cfg.tcp_multi_path), udp_fragment: strToBool(cfg.udp_fragment) });
    });

    return inbounds;
}

function generate_endpoint(node, self_mark) {
    if (type(node) !== 'object') return null;

    let ep = { type: node.type, tag: sprintf("cfg-%s-out", node['.name']), server: node.address, server_port: strToInt(node.port), routing_mark: self_mark };

    switch (node.type) {
        case 'wireguard':
            delete ep.server; delete ep.server_port;
            ep.local_address = node.wireguard_local_address; ep.mtu = strToInt(node.wireguard_mtu);
            ep.private_key = node.wireguard_private_key;
            ep.peers = [{ server: node.address, server_port: strToInt(node.port), public_key: node.wireguard_peer_public_key, pre_shared_key: node.wireguard_pre_shared_key, allowed_ips: ['0.0.0.0/0', '::/0'], persistent_keepalive_interval: strToInt(node.wireguard_persistent_keepalive_interval), reserved: parse_port(node.wireguard_reserved) }];
            break;
        case 'ssh':
            ep.user = node.username; ep.password = node.password; ep.client_version = node.ssh_client_version;
            ep.host_key = node.ssh_host_key; ep.host_key_algorithms = node.ssh_host_key_algo;
            ep.private_key = node.ssh_priv_key; ep.private_key_passphrase = node.ssh_priv_key_pp;
            break;
        case 'shadowsocks':
            ep.method = node.shadowsocks_encrypt_method; ep.password = node.password;
            ep.plugin = node.shadowsocks_plugin; ep.plugin_opts = node.shadowsocks_plugin_opts;
            break;
        case 'shadowtls':
            ep.password = node.password; ep.version = strToInt(node.shadowtls_version);
            break;
        case 'hysteria':
        case 'hysteria2':
            ep.password = node.password;
            ep.up_mbps = strToInt(node.hysteria_up_mbps); ep.down_mbps = strToInt(node.hysteria_down_mbps);
            ep.obfs = node.hysteria_obfs_type ? { type: node.hysteria_obfs_type, password: node.hysteria_obfs_password } : node.hysteria_obfs_password;
            ep.auth = (node.hysteria_auth_type === 'base64') ? node.hysteria_auth_payload : null;
            ep.auth_str = (node.hysteria_auth_type === 'string') ? node.hysteria_auth_payload : null;
            ep.recv_window_conn = strToInt(node.hysteria_recv_window_conn); 
            ep.recv_window = strToInt(node.hysteria_recv_window || node.hysteria_revc_window);
            ep.disable_mtu_discovery = strToBool(node.hysteria_disable_mtu_discovery);
            break;
        case 'tuic':
            ep.uuid = normalize_uuid(node.uuid); ep.password = node.password; ep.congestion_control = node.tuic_congestion_control;
            ep.udp_relay_mode = node.tuic_udp_relay_mode; ep.udp_over_stream = strToBool(node.tuic_udp_over_stream);
            ep.zero_rtt_handshake = strToBool(node.tuic_enable_zero_rtt); ep.heartbeat = strToTime(node.tuic_heartbeat);
            break;
        case 'vmess':
            ep.uuid = normalize_uuid(node.uuid); ep.alter_id = strToInt(node.vmess_alterid); ep.security = node.vmess_encrypt;
            ep.global_padding = strToBool(node.vmess_global_padding); ep.authenticated_length = strToBool(node.vmess_authenticated_length);
            ep.packet_encoding = node.packet_encoding;
            break;
        case 'vless':
            ep.uuid = normalize_uuid(node.uuid); ep.flow = node.vless_flow; ep.packet_encoding = node.packet_encoding;
            break;
        case 'trojan':
            ep.password = node.password;
            break;
        case 'socks':
        case 'http':
            ep.version = node.type === 'socks' ? node.socks_version : null;
            ep.username = node.username; ep.password = node.password;
            break;
    }

    if (node.transport && node.transport !== 'tcp') {
        let tp = { 
            type: node.transport, 
            host: node.http_host || node.httpupgrade_host, 
            path: node.http_path || node.ws_path, 
            method: node.http_method, 
            service_name: node.grpc_servicename, 
            idle_timeout: strToTime(node.http_idle_timeout), 
            ping_timeout: strToTime(node.http_ping_timeout), 
            permit_without_stream: strToBool(node.grpc_permit_without_stream) 
        };

        if (node.ws_host) { tp.headers = { "Host": [ node.ws_host ] }; }
        if (node.websocket_early_data) {
            tp.max_early_data = strToInt(node.websocket_early_data) || 2048;
            tp.early_data_header_name = node.websocket_early_data_header || "Sec-WebSocket-Protocol";
        }
        ep.transport = tp;
    }

    if (node.multiplex === '1') {
        ep.multiplex = { enabled: true, protocol: node.multiplex_protocol, max_connections: strToInt(node.multiplex_max_connections), min_streams: strToInt(node.multiplex_min_streams), max_streams: strToInt(node.multiplex_max_streams), padding: strToBool(node.multiplex_padding) };
    }

    if (node.tls === '1') {
        ep.tls = { enabled: true, server_name: node.tls_sni, insecure: strToBool(node.tls_insecure), alpn: node.tls_alpn ? split(node.tls_alpn, ',') : null, min_version: node.tls_min_version, max_version: node.tls_max_version, cipher_suites: node.tls_cipher_suites ? split(node.tls_cipher_suites, ',') : null, certificate_path: node.tls_cert_path, utls: node.tls_utls ? { enabled: true, fingerprint: node.tls_utls } : null, reality: (node.tls_reality === '1') ? { enabled: true, public_key: node.tls_reality_public_key, short_id: node.tls_reality_short_id } : null, ech: (node.tls_ech === '1') ? { enabled: true, config: node.tls_ech_config, config_path: node.tls_ech_config_path } : null };
    }
    return ep;
}

function build_outbounds(u) {
    let endpoints = [];
    let outbounds = [];
    let endpoint_dict = {};
    
    let self_mark = strToInt(u.get(U_CONFIG, S_INFRA, 'self_mark')) || 100;

    push(outbounds, { type: 'direct', tag: 'direct-out', routing_mark: self_mark });
    push(outbounds, { type: 'block', tag: 'block-out' });

    u.foreach(U_CONFIG, 'node', (cfg) => {
        let ep = generate_endpoint(cfg, self_mark);
        if (ep) { push(endpoints, ep); endpoint_dict[ep.tag] = true; }
    });

    u.foreach(U_CONFIG, 'routing_node', (cfg) => {
        if (cfg.enabled !== '1') return;
        let out_group = { type: cfg.node || 'urltest', tag: sprintf("cfg-%s-out", cfg['.name']), outbounds: [] };

        if (out_group.type === 'urltest') {
            let tol = strToInt(cfg.urltest_tolerance);
            out_group.tolerance = tol != null ? tol : 150;

            let interval = strToInt(cfg.urltest_interval);
            if (interval != null) out_group.interval = interval + "s";
            if (cfg.urltest_url) out_group.url = cfg.urltest_url;
            if (cfg.urltest_interrupt_exist_connections === '1') out_group.interrupt_exist_connections = true;

            let raw_nodes = cfg.urltest_nodes || [];
            if (type(raw_nodes) === 'string') raw_nodes = [raw_nodes];

            for (let i = 0; i < length(raw_nodes); i++) {
                let target_tag = sprintf("cfg-%s-out", raw_nodes[i]);
                if (endpoint_dict[target_tag]) push(out_group.outbounds, target_tag);
            }
        }
        if (length(out_group.outbounds) > 0) push(outbounds, out_group);
    });

    return { endpoints, outbounds };
}

function build_policies(u, valid_outbounds) {
    let route = { rules: [], rule_set: [] };
    let dns = { servers: [], rules: [] };

    let dns_strat = u.get(U_CONFIG, 'dns', 'dns_strategy');
    if (dns_strat) dns.strategy = dns_strat;

    u.foreach(U_CONFIG, 'dns_server', (cfg) => {
        if (cfg.enabled !== '1') return;
        let out_target = (cfg.outbound === 'direct-out' || cfg.outbound === 'block-out') ? cfg.outbound : sprintf("cfg-%s-out", cfg.outbound);
        if (out_target !== 'direct-out' && out_target !== 'block-out' && !valid_outbounds[out_target]) out_target = 'direct-out';
        push(dns.servers, { tag: sprintf("cfg-%s-dns", cfg['.name']), type: cfg.type || 'udp', server: cfg.server, detour: out_target });
    });

    u.foreach(U_CONFIG, 'dns_rule', (cfg) => {
        if (cfg.enabled !== '1') return;
        let rule_sets = [];
        if (cfg.rule_set) {
            let rs = type(cfg.rule_set) === 'array' ? cfg.rule_set : [cfg.rule_set];
            for (let i = 0; i < length(rs); i++) push(rule_sets, sprintf("cfg-%s-rule", rs[i]));
        }
        let rule_obj = {};
        if (length(rule_sets) > 0) rule_obj.rule_set = rule_sets;
        
        switch (cfg.action) {
            case 'reject': rule_obj.action = 'reject'; rule_obj.method = cfg.reject_method || 'default'; break;
            case 'route': rule_obj.action = 'route'; if (cfg.match_response === '1') rule_obj.match_response = true; if (cfg.server) rule_obj.server = sprintf("cfg-%s-dns", cfg.server); break;
            case 'evaluate': rule_obj.action = 'evaluate'; if (cfg.server) rule_obj.server = sprintf("cfg-%s-dns", cfg.server); break;
            case 'respond': rule_obj.action = 'respond'; break;
            default: if (cfg.server) rule_obj.server = sprintf("cfg-%s-dns", cfg.server); break;
        }
        push(dns.rules, rule_obj);
    });

    u.foreach(U_CONFIG, 'ruleset', (cfg) => {
        if (cfg.enabled !== '1') return;
        push(route.rule_set, { type: cfg.type, tag: sprintf("cfg-%s-rule", cfg['.name']), format: cfg.format, path: cfg.path });
    });

    // 🚨 1.14.0 核心修复：全局嗅探与协议级 DNS 劫持
    push(route.rules, { action: "sniff" });
    push(route.rules, { protocol: "dns", action: "hijack-dns" });
    push(route.rules, { action: "resolve", strategy: u.get(U_CONFIG, 'routing', 'domain_strategy') || 'prefer_ipv4' });

    u.foreach(U_CONFIG, 'routing_rule', (cfg) => {
        if (cfg.enabled !== '1') return;
        let rule_sets = [];
        if (cfg.rule_set) {
            let rs = type(cfg.rule_set) === 'array' ? cfg.rule_set : [cfg.rule_set];
            for(let i=0; i<length(rs); i++) push(rule_sets, sprintf("cfg-%s-rule", rs[i]));
        }
        let rule_obj = { action: cfg.action };
        if (length(rule_sets) > 0) rule_obj.rule_set = rule_sets;

        if (cfg.action === 'route') {
            let out_target = cfg.outbound;
            if (out_target) {
                out_target = (out_target === 'direct-out' || out_target === 'block-out') ? out_target : sprintf("cfg-%s-out", out_target);
                if (out_target !== 'direct-out' && out_target !== 'block-out' && !valid_outbounds[out_target]) out_target = 'direct-out';
                rule_obj.outbound = out_target;
            } else { rule_obj.outbound = 'direct-out'; }
        } else if (cfg.action === 'reject') {
            rule_obj.method = cfg.reject_method || 'default';
        }
        push(route.rules, rule_obj);
    });

    let default_out = u.get(U_CONFIG, 'routing', 'default_outbound');
    if (default_out) {
         let final_out = (default_out === 'direct-out' || default_out === 'block-out') ? default_out : sprintf("cfg-%s-out", default_out);
         if (final_out !== 'direct-out' && final_out !== 'block-out' && !valid_outbounds[final_out]) final_out = 'direct-out';
         route.final = final_out;
    }

    let def_dns =u.get(U_CONFIG, 'dns', 'default_server' );
    if (def_dns) dns.final =sprintf( "cfg-%s-dns", def_dns );
    
    let default_outbound_dns = u.get(U_CONFIG, 'routing', 'default_outbound_dns');
    if (default_outbound_dns) route.default_domain_resolver = { server: sprintf( "cfg-%s-dns", default_outbound_dns) };

    // 🚨 1.14.0 救命药：自动探测物理网卡，防止 missing default interface 死锁
    route.auto_detect_interface = true;

    return { route, dns, default_out };
}

function build_experimental(u) {
    let host = u.get(U_CONFIG, S_INFRA, 'clash_api_host');
    let port_str = u.get(U_CONFIG, S_INFRA, 'clash_api_port');
    let port = strToInt(port_str);

    if (!port) {
        u.foreach(U_CONFIG, S_INFRA, (s) => {
            if (s.clash_api_port) { port = strToInt(s.clash_api_port); host = s.clash_api_host || host; }
        });
    }

    if (!host) host = '0.0.0.0';
    let exp_model = { cache_file: { enabled: true, store_dns: true } };
    if (port) exp_model.clash_api = { external_controller: sprintf("%s:%d", host, port) };
    return exp_model;
}

function build_flow_model(trace_id) {
    try {
        let u = cursor();
        u.load(U_CONFIG); 

        let inbounds = build_inbounds(u);
        let obs = build_outbounds(u);
        
        let valid_outbounds = {};
        for (let i = 0; i < length(obs.outbounds); i++) valid_outbounds[obs.outbounds[i].tag] = true;
        for (let i = 0; i < length(obs.endpoints); i++) valid_outbounds[obs.endpoints[i].tag] = true;

        let pd = build_policies(u, valid_outbounds);
        let exp_model = build_experimental(u);

        let flow_model = {
            schema_version: "1.2",
            enabled: (pd.default_out !== 'disabled' && pd.default_out !== null && pd.default_out !== ""),
            log: { level: u.get(U_CONFIG, S_MAIN, 'log_level') || 'warn', output_path: PATH.LOG_RUN },
            experimental: exp_model,
            inbounds: inbounds,
            endpoints: obs.endpoints,
            outbounds: obs.outbounds,
            route: pd.route,
            dns: pd.dns
        };

        // 🚨 架构修复：NTP 逻辑已连根拔除，确保 Sing-box 不在启动时因对时而死锁。

        return Success(flow_model, 200, trace_id);
    } catch(e) {
        let err_str = "" + e;
        return Fail(ERR.E_CONFIG_FAULT, "Schema Build Exception: " + err_str, trace_id);
    }
}

export { build_flow_model };
