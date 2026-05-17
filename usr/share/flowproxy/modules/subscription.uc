/**
 * FlowProxy | modules/subscription.uc | v1.2 (Ultimate Syntax & Padding Safe Edition)
 * 职责：负责订阅节点拉取、协议深度解析并落地 UCI 格式。
 * 架构更新：
 * 1. 彻底清除正则字面量陷阱，保障 Ucode 编译期 100% 存活。
 * 2. 引入极限纯净 Base64 清洗器与智能 Padding 补全算法，免疫机场劣质数据。
 */

'use strict';

import { open as fs_open } from 'fs';
import { PATH, BIN } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { ExecSafe, shell_escape } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';

function _net_fetch(url, user_agent, trace_id) {
    let tmp_file = sprintf("%s/fp_sub_dl_%d.txt", PATH.RUNTIME, time());
    
    // 🚨 终极绝杀：强行接入 Sing-box 大脑 (-x socks5h)。
    // 这样不仅能完美解析您的自建域名，还能享受 Sing-box 的国内直连分流规则！
    let curl_args = ["-s", "-L", "-k", "-4", "-m", "15", "-x", "socks5h://127.0.0.1:5330"];
    
    if (user_agent && length(user_agent) > 0) {
        push(curl_args, "-A");
        push(curl_args, user_agent);
    }
    push(curl_args, "-o");
    push(curl_args, tmp_file);
    push(curl_args, url);

    // 🚨 同步解除沙箱封印，给予 15 秒充足的拉取与分流时间
    ExecSafe(BIN.CURL, curl_args, { timeout: 15 }, trace_id);

    let content = null;
    let fd = fs_open(tmp_file, "r");
    if (fd) { 
        content = fd.read("all"); 
        fd.close(); 
    }
    ExecSafe(BIN.RM, ["-f", tmp_file], null, trace_id);
    
    return (content && length(content) > 0) ? content : null;
}

function _generate_stable_id(str) {
    let h1 = 0x12345678, h2 = 0x87654321, h3 = 0x9abcdef0, h4 = 0x0fedcba9;
    for (let i = 0; i < length(str); i++) {
        let c = ord(substr(str, i, 1));
        h1 = ((h1 * 33) + c) % 4294967296;
        h2 = ((h2 * 65599) + c) % 4294967296;
        h3 = ((h3 * 31) + c) % 4294967296;
        h4 = ((h4 * 17) + c) % 4294967296;
    }
    return sprintf("%08x%08x%08x%08x", h1, h2, h3, h4);
}

function _decode_base64_str(str) {
    if (!str) return null;
    
    // 1. 标准 URL-Safe 字符替换 (- -> +, _ -> /)
    let s = replace(replace(str, regexp('-', 'g'), '+'), regexp('_', 'g'), '/');
    
    // 2. 🚨 极限清洗：使用白名单模式，物理抹杀所有不属于 Base64 的垃圾字符
    s = replace(s, regexp('[^A-Za-z0-9+/=]', 'g'), ""); 
    
    // 3. 🚨 智能补齐：机场经常省略等号，导致 Ucode 引擎崩溃，我们手工帮它补齐
    let mod = length(s) % 4;
    if (mod === 2) {
        s += "==";
    } else if (mod === 3) {
        s += "=";
    }
    
    try { 
        return b64dec(s); 
    } catch(e) { 
        return null; 
    }
}

function _urldecode(str) {
    if (type(str) !== 'string') return "";
    let res = replace(str, '+', ' ');
    let hex_map = { '0':0, '1':1, '2':2, '3':3, '4':4, '5':5, '6':6, '7':7, '8':8, '9':9, 'A':10, 'B':11, 'C':12, 'D':13, 'E':14, 'F':15, 'a':10, 'b':11, 'c':12, 'd':13, 'e':14, 'f':15 };
    return replace(res, regexp('%([0-9a-fA-F]{2})', 'g'), function(m, h) {
        let d = hex_map[substr(h, 0, 1)] * 16 + hex_map[substr(h, 1, 1)];
        return sprintf("%c", d);
    });
}

// ============================================================================
// 🚀 重构版：完美复刻 HomeProxy 容错解析引擎 (无 Regex 崩溃风险)
// ============================================================================
function _parse_url(url_string) {
    let res = { protocol: "", username: "", password: "", hostname: "", port: "", searchParams: {}, hash: "" };
    let idx = index(url_string, "://");
    if (idx < 0) return null;
    res.protocol = substr(url_string, 0, idx);
    let payload = substr(url_string, idx + 3);
    
    // 1. 提取并解码 Hash (标签)
    let hash_idx = index(payload, "#");
    if (hash_idx >= 0) {
        res.hash = _urldecode(substr(payload, hash_idx + 1));
        payload = substr(payload, 0, hash_idx);
    }
    
    // 2. 提取并解码 Query Params
    let qs_idx = index(payload, "?");
    if (qs_idx >= 0) {
        let qs = substr(payload, qs_idx + 1);
        payload = substr(payload, 0, qs_idx);
        let pairs = split(qs, "&");
        for (let i = 0; i < length(pairs); i++) {
            let kv = split(pairs[i], "=");
            if (length(kv) == 2) res.searchParams[_urldecode(kv[0])] = _urldecode(kv[1]);
        }
    }
    
    // 3. 剥离尾部垃圾斜杠 (拯救 anytls)
    if (substr(payload, length(payload) - 1, 1) === "/") {
        payload = substr(payload, 0, length(payload) - 1);
    }
    
    // 4. 提取并解码 Auth (用户名/密码/UUID)
    let auth_idx = index(payload, "@");
    let host_port = payload;
    if (auth_idx >= 0) {
        let auth = substr(payload, 0, auth_idx);
        host_port = substr(payload, auth_idx + 1);
        let up_idx = index(auth, ":");
        if (up_idx >= 0) {
            res.username = _urldecode(substr(auth, 0, up_idx));
            res.password = _urldecode(substr(auth, up_idx + 1));
        } else {
            res.username = _urldecode(auth);
        }
    }
    
    // 5. 纯字符串提取 Host 和 Port (彻底抛弃危险正则，完美兼容 IPv6)
    if (substr(host_port, 0, 1) === "[") {
        let close_idx = index(host_port, "]");
        if (close_idx > 0) {
            res.hostname = substr(host_port, 1, close_idx - 1);
            let remainder = substr(host_port, close_idx + 1);
            if (substr(remainder, 0, 1) === ":") res.port = substr(remainder, 1);
        }
    } else {
        let colon_idx = index(host_port, ":");
        if (colon_idx >= 0) {
            res.hostname = substr(host_port, 0, colon_idx);
            res.port = substr(host_port, colon_idx + 1);
        } else {
            res.hostname = host_port;
        }
    }
    
    if (!res.port) res.port = "80"; 
    // 清理端口中可能残留的垃圾字符
    res.port = replace(res.port, regexp('[^0-9]', 'g'), '');
    return res;
}

function _parse_node_uri(uri, global_opts) {
    let raw_uri = trim(uri);
    let parts = split(raw_uri, '://');
    if (length(parts) < 2) return null;
    
    let scheme = parts[0];
    let url = _parse_url(raw_uri);
    let params = url ? url.searchParams : {};
    let config = null;

    let default_label = (url && url.hash) ? url.hash : "";
    let scheme_upper = uc(scheme); 

    // 🚨 架构修复：同时兼容驼峰命名(allowInsecure)、简写(insecure) 和 下划线命名(allow_insecure)！
    let p_insec = params.allowInsecure || params.insecure || params.allow_insecure || "";
    let is_insec = (p_insec === '1' || p_insec === 'true') ? '1' : '0';

    let v_json = null, ss_parts, full_dec, full_url, up, dec, hy2_pass;

    switch (scheme) {
        case 'vless':
            if (params.type === 'kcp') return null;
            config = { 
                label: default_label, type: 'vless', address: url.hostname, port: url.port, uuid: url.username, 
                tls: (params.security === 'tls' || params.security === 'xtls' || params.security === 'reality') ? '1' : '0', 
                tls_sni: params.sni || "", tls_utls: params.fp || "",
                tls_reality: (params.security === 'reality') ? '1' : '0', 
                tls_reality_public_key: params.pbk || "", tls_reality_short_id: params.sid || "", 
                vless_flow: (params.security === 'tls' || params.security === 'reality') ? (params.flow || "") : "", 
                transport: (params.type && params.type !== 'tcp') ? params.type : "", 
                tls_alpn: params.alpn || "", tls_insecure: is_insec 
            };
            if (params.type === 'ws') { 
                config.ws_host = params.host || ""; 
                config.ws_path = params.path || ""; 
                // 🌟 复刻 HomeProxy 的 Websocket Early Data (ed) 提取逻辑
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
            config = { 
                label: default_label, type: 'trojan', address: url.hostname, port: url.port, password: url.username, 
                transport: (params.type && params.type !== 'tcp') ? params.type : "", 
                tls: '1', tls_sni: params.sni || "", tls_utls: params.fp || "", tls_insecure: is_insec 
            };
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
            config = { label: default_label, type: 'tuic', address: url.hostname, port: url.port, uuid: url.username, password: url.password || "", tls: '1', tls_sni: params.sni || "", tuic_congestion_control: params.congestion_control || "", tuic_udp_relay_mode: params.udp_relay_mode || "", tls_alpn: params.alpn || "", tls_insecure: is_insec };
            break;
        case 'anytls':
            config = { label: default_label, type: 'anytls', address: url.hostname, port: url.port, password: url.username, tls: '1', tls_sni: params.sni || "", tls_insecure: is_insec };
            break;
        case 'hysteria2':
        case 'hy2':
            hy2_pass = url.username || ""; if (url.password) hy2_pass += ":" + url.password;
            config = { label: default_label, type: 'hysteria2', address: url.hostname, port: url.port, password: hy2_pass, hysteria_obfs_type: params.obfs || "", hysteria_obfs_password: params['obfs-password'] || "", tls: '1', tls_insecure: is_insec, tls_sni: params.sni || "" };
            break;
    }

    if (!config || !config.address || config.address === "") return null;

    // 清理不可见控制字符 (遵循 1.0 铁律，不碰正则陷阱)
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

function fetch_and_parse(airport_cfg, global_opts, trace_id) {
    log(trace_id, 'INFO', 'SUBSCRIPTION', 'Starting network fetch and parse sequence...');

    try {
        let res = _net_fetch(airport_cfg.url, global_opts.user_agent, trace_id);
        
        if (!res) {
            return Fail(ERR.E_SYSTEM_BUSY, "Network fetch failed or returned empty payload", trace_id);
        }

        let lines = [];
        try { 
            let j_data = json(res);
            lines = j_data.servers || j_data; 
        } catch(json_err) { 
            let d = _decode_base64_str(res); 
            lines = d ? split(trim(d), '\n') : []; 
        }

        let nodes = [];
        let fp_cache = {};
        let collision_idx = 0;

        for (let i = 0; i < length(lines); i++) {
            let n = _parse_node_uri(lines[i], global_opts);
            if (n) {
                n.airport_id = airport_cfg.id;
                while (fp_cache[n.id]) { 
                    collision_idx++;
                    n.id = _generate_stable_id(n.id + "|" + collision_idx); 
                }
                fp_cache[n.id] = true;
                push(nodes, n);
            }
        }

        log(trace_id, 'INFO', 'SUBSCRIPTION', sprintf('Successfully parsed %d nodes.', length(nodes)));
        return Success({ nodes: nodes }, 200, trace_id);

    } catch (e) {
        let err_msg = "" + e;
        log(trace_id, 'CRIT', 'SUBSCRIPTION', 'Fatal Crash during parsing: ' + err_msg);
        return Fail(ERR.E_SYSTEM_BUSY, err_msg, trace_id);
    }
}

export { fetch_and_parse };
