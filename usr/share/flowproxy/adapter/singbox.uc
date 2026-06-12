/**
 * FlowProxy | adapter/singbox.uc | v1.0
 * 配置物理翻译器 (SSOT Aligned Edition)
 * 架构角色：执行流水线 Step 2 (Model -> JSON)。
 * 核心对齐：全量接入 Result 协议，注入 Trace 追踪机制，增加黑匣子观测。
 * 核心特性：深度递归清洗器，剔除所有 null 属性，还原纯净 JSON。
 */

'use strict';

// 🚨 铁律 3: 绝对命名空间寻址
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { log } from 'flowproxy.core.logger';
import { build_dns } from 'flowproxy.adapter.singbox.dns';
import { build_route } from 'flowproxy.adapter.singbox.route';
import { build_inbounds } from 'flowproxy.adapter.singbox.inbounds';
import { build_experimental } from 'flowproxy.adapter.singbox.experimental';
import { apply as apply_outbound_adapter } from 'flowproxy.adapter.singbox.outbounds.registry';
import { apply_transport, apply_multiplex } from 'flowproxy.adapter.singbox.outbounds.common';

// 递归清洗空对象，保证内核不报错 (业务逻辑 100% 保留)
function clean_obj(obj) {
    if (type(obj) === 'array') {
        let ret = [];
        for (let i = 0; i < length(obj); i++) {
            if (obj[i] != null) {
                push(ret, clean_obj(obj[i]));
            }
        }
        return ret;
    } else if (type(obj) === 'object') {
        let ret = {};
        for (let k in obj) {
            if (obj[k] != null) {
                ret[k] = clean_obj(obj[k]);
            }
        }
        return ret;
    }
    return obj; // 基础类型直接返回
}

function strToInt(val) { return (val != null && val !== "") ? int(val) : null; }
function strToBool(val) { return (val != null && val !== "") ? (val === '1' || val === 'true') : null; }
function strToTime(val) {
    if (val != null && val !== "") {
       return match(val, /^[0-9]+$/) ? val + "s" : val;
    }
    return null;
}
function parse_port(val) { return strToInt(val); }

function normalize_uuid(u) {
    if (!u || type(u) !== 'string') return u;
    if (length(u) === 32 && index(u, '-') < 0) {
        return sprintf("%s-%s-%s-%s-%s", substr(u,0,8), substr(u,8,4), substr(u,12,4), substr(u,16,4), substr(u,20,12));
    }
    return u;
}

function generate_endpoint(node, endpoint_policy) {
    if (type(node) !== 'object') return null;

    endpoint_policy = (type(endpoint_policy) === 'object') ? endpoint_policy : {};
    let self_mark = strToInt(endpoint_policy.self_mark) || 100;
    let use_routing_mark = endpoint_policy.use_routing_mark === true;

    let ep = { type: node.type, tag: sprintf("cfg-%s-out", node['.name']), server: node.address, server_port: strToInt(node.port) };
    if (use_routing_mark) ep.routing_mark = self_mark;

    let adapter_handled = apply_outbound_adapter(node, ep);
    if (!adapter_handled) {
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
            case 'anytls': ep.password = node.password; break;
            case 'http':
                ep.version = node.type === 'socks' ? node.socks_version : null;
                ep.username = node.username; ep.password = node.password;
                break;
        }
    }

    apply_transport(ep, node);
    apply_multiplex(ep, node);

    if (node.tls === '1') {
        ep.tls = { enabled: true, server_name: node.tls_sni, insecure: strToBool(node.tls_insecure), alpn: (type(node.tls_alpn) === 'array') ? node.tls_alpn : (node.tls_alpn ? split(node.tls_alpn, ',') : null), min_version: node.tls_min_version, max_version: node.tls_max_version, cipher_suites: (type(node.tls_cipher_suites) === 'array') ? node.tls_cipher_suites : (node.tls_cipher_suites ? split(node.tls_cipher_suites, ',') : null), certificate_path: node.tls_cert_path, utls: node.tls_utls ? { enabled: true, fingerprint: node.tls_utls } : ((node.type === 'tuic' || node.type === 'hysteria2' || node.type === 'hysteria') ? null : { enabled: true, fingerprint: 'chrome' }), reality: (node.tls_reality === '1') ? { enabled: true, public_key: node.tls_reality_public_key, short_id: node.tls_reality_short_id } : null, ech: (node.tls_ech === '1') ? { enabled: true, config: node.tls_ech_config, config_path: node.tls_ech_config_path } : null };
    }
    return ep;
}

const Adapter = {
    /**
     * 将 FlowModel 翻译为 Sing-box JSON 字符串
     * @param {object} flow_model - 抽象数据模型
     * @param {object} caps - sing-box capability detection result (observe-only)
     * @param {string} trace_id - 贯穿链路的 Trace ID
     */
    translate: function(flow_model, caps, trace_id) {
        log(trace_id, 'INFO', 'ADAPTER', 'Translating FlowModel to Sing-box JSON...');

        try {
            // ⭐ 协议对齐：防御性边界检查
            if (!flow_model || type(flow_model) !== 'object') {
                log(trace_id, 'CRIT', 'ADAPTER', 'Invalid flow_model input object.');
                return Fail(ERR.E_CONFIG_FAULT, "Adapter Error: Invalid flow_model input", trace_id);
            }
            log(trace_id, 'INFO', 'ADAPTER', sprintf('[SINGBOX_CAPS] version=%s caps=%s', caps.version, sprintf("%.J", caps.capabilities)));

            let listen_policy = (type(flow_model.listen_policy) === 'object') ? flow_model.listen_policy : {};
            let safe_listen_addr = listen_policy.safe_listen_addr || (listen_policy.allow_lan === true ? '::' : '127.0.0.1');

            let config = {};

            if (flow_model.log) {
                config.log = {
                    disabled: flow_model.log.disabled || false,
                    level: flow_model.log.level || 'warn',
                    output: flow_model.log.output_path,
                    timestamp: true
                };
            }
            
            if (flow_model.ntp) config.ntp = flow_model.ntp;

            if (flow_model.dns) {
                config.dns = build_dns(flow_model.dns, caps, trace_id);
            }

            config.inbounds = build_inbounds(flow_model.inbounds, caps, trace_id, safe_listen_addr);

            let final_outbounds = [];
            if (type(flow_model.outbounds) === 'array') {
                for (let i = 0; i < length(flow_model.outbounds); i++) push(final_outbounds, flow_model.outbounds[i]);
            }
            if (type(flow_model.endpoints) === 'array') {
                for (let i = 0; i < length(flow_model.endpoints); i++) {
                    let ep = generate_endpoint(flow_model.endpoints[i], flow_model.endpoint_policy);
                    if (ep) push(final_outbounds, ep);
                }
            }
            config.outbounds = final_outbounds;

            if (flow_model.route) {
                config.route = build_route(flow_model.route, caps, trace_id);
            }

            if (flow_model.experimental) config.experimental = build_experimental(flow_model.experimental, caps, trace_id);

            // 终极清洗：剥离所有 null，产出完美 JSON
            let final_json = sprintf("%.J", clean_obj(config));

            log(trace_id, 'INFO', 'ADAPTER', 'Translation complete. JSON generated successfully.');

            return Success(final_json, 200, trace_id);

        } catch(e) {
            let err_str = "" + e;
            log(trace_id, 'CRIT', 'ADAPTER', 'Translation Crash: ' + err_str);
            return Fail(ERR.E_CONFIG_FAULT, "Adapter Translation Exception: " + err_str, trace_id);
        }
    }
};

// 🚨 铁律 1: 文件末尾统一导出
export { Adapter };
