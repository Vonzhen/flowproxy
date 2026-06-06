/**
 * FlowProxy | modules/subscription.uc | v1.2 (Ultimate Syntax & Padding Safe Edition)
 * 职责：负责订阅节点拉取、协议深度解析并落地 UCI 格式。
 * 架构更新：
 * 1. 彻底清除正则字面量陷阱，保障 Ucode 编译期 100% 存活。
 * 2. 引入极限纯净 Base64 清洗器与智能 Padding 补全算法，免疫机场劣质数据。
 */

'use strict';

import { open as fs_open, stat } from 'fs';
import { PATH, BIN } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { with_changed } from 'flowproxy.core.module_result';
import { ExecSafe, shell_escape } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';
import { NetExec } from 'flowproxy.core.netexec';
import { LIMIT } from 'flowproxy.core.constants';
import {
    list_enabled_airports,
    build_subscription_opts
} from 'flowproxy.core.config_helper';
import { task_rebuild_groups } from 'flowproxy.modules.groups';
import { StateManager } from 'flowproxy.runtime.state';

const MIN_PAYLOAD_BYTES = 16;
const STAGE_FETCH = "fetch";

function _net_fetch_fail(error, mode, proxy_port, extra) {
    let out = {
        ok: false,
        error: error,
        detail: "",
        mode: mode || "",
        stage: STAGE_FETCH
    };
    if (proxy_port) out.proxy_port = proxy_port;
    if (extra) {
        for (let k in extra) out[k] = extra[k];
        if (extra.detail) out.detail = extra.detail;
        else if (extra.http_code != null) {
            out.detail = sprintf("http_code=%s exit=%s", extra.http_code, extra.exit_code != null ? extra.exit_code : (extra.curl_exit != null ? extra.curl_exit : "-"));
        } else if (extra.exit_code != null) {
            out.detail = sprintf("exit=%d", extra.exit_code);
        } else if (extra.curl_exit != null) {
            out.detail = sprintf("exit=%d", extra.curl_exit);
        } else if (extra.file_size != null) {
            out.detail = sprintf("file_size=%d", extra.file_size);
        }
    }
    return out;
}

function _net_fetch_ok(content, mode, proxy_port, meta) {
    let out = {
        ok: true,
        content: content,
        error: "",
        detail: "",
        mode: mode || "",
        stage: STAGE_FETCH
    };
    if (proxy_port) out.proxy_port = proxy_port;
    if (meta) {
        for (let k in meta) out[k] = meta[k];
        if (meta.http_code != null && meta.file_size != null) {
            out.detail = sprintf("http_code=%s size=%d", meta.http_code, meta.file_size);
        }
    }
    return out;
}

function _http_code_valid(code_str) {
    let c = int(trim(code_str || ""));
    return (c >= 200 && c < 300);
}

function _net_fetch(url, global_opts, trace_id) {
    let tmp_file = sprintf("%s/fp_sub_dl_%d.txt", PATH.RUNTIME, time());
    let opts = global_opts || {};
    let use_proxy = (opts.update_via_proxy === '1' || opts.update_via_proxy === 1 || opts.update_via_proxy === true);
    let mode = use_proxy ? "proxy" : "direct";
    let proxy_port = null;

    if (use_proxy) {
        proxy_port = opts.proxy_port ? trim(sprintf("%s", opts.proxy_port)) : null;
        if (!proxy_port || length(proxy_port) === 0) {
            log(trace_id, 'WARN', 'SUBSCRIPTION', 'update_via_proxy=1 but no mixed/socks port (proxy_unavailable)');
            return _net_fetch_fail("proxy_unavailable", "proxy", null, {
                detail: "no mixed/socks inbound port",
                exit_code: 127
            });
        }
    }

    let nx = NetExec.fetch({
        url: url,
        dest_file: tmp_file,
        effective_mode: mode,
        proxy_port: proxy_port,
        timeout_sec: 15,
        connect_timeout: LIMIT.NET_CONNECT_TIMEOUT,
        retry: LIMIT.NET_RETRY,
        retry_delay: LIMIT.NET_RETRY_DELAY,
        insecure: true,
        ipv4: true,
        user_agent: opts.user_agent,
        trace_id: trace_id
    });

    let curl_exit = nx.exit_code;
    let http_code = nx.http_code || "";

    if (!nx.ok) {
        ExecSafe(BIN.RM, ["-f", tmp_file], null, trace_id);
        log(trace_id, 'WARN', 'SUBSCRIPTION', sprintf(
            "curl_failed mode=%s port=%s exit=%d http=%s stderr=%s",
            mode, proxy_port || "-", curl_exit, http_code || "-", nx.stderr || ""
        ));
        return _net_fetch_fail("curl_failed", mode, proxy_port, {
            exit_code: curl_exit,
            curl_exit: curl_exit,
            http_code: http_code,
            detail: nx.stderr || sprintf("curl exit %d", curl_exit)
        });
    }

    if (!_http_code_valid(http_code)) {
        ExecSafe(BIN.RM, ["-f", tmp_file], null, trace_id);
        log(trace_id, 'WARN', 'SUBSCRIPTION', sprintf(
            "http_error mode=%s port=%s exit=%d http=%s",
            mode, proxy_port || "-", curl_exit, http_code || "-"
        ));
        return _net_fetch_fail("http_error", mode, proxy_port, {
            exit_code: curl_exit,
            curl_exit: curl_exit,
            http_code: http_code,
            detail: sprintf("HTTP %s", http_code || "unknown")
        });
    }

    let st = stat(tmp_file);
    let file_size = (st && st.size) ? st.size : 0;
    if (!st || file_size < MIN_PAYLOAD_BYTES) {
        ExecSafe(BIN.RM, ["-f", tmp_file], null, trace_id);
        log(trace_id, 'WARN', 'SUBSCRIPTION', sprintf(
            "empty_payload mode=%s exit=%d http=%s size=%d",
            mode, curl_exit, http_code, file_size
        ));
        return _net_fetch_fail("empty_payload", mode, proxy_port, {
            exit_code: curl_exit,
            curl_exit: curl_exit,
            http_code: http_code,
            file_size: file_size,
            detail: sprintf("payload size %d < %d", file_size, MIN_PAYLOAD_BYTES)
        });
    }

    let content = null;
    let fd = fs_open(tmp_file, "r");
    if (fd) {
        content = fd.read("all");
        fd.close();
    }
    ExecSafe(BIN.RM, ["-f", tmp_file], null, trace_id);

    if (!content || length(content) < MIN_PAYLOAD_BYTES) {
        return _net_fetch_fail("empty_payload", mode, proxy_port, {
            exit_code: curl_exit,
            curl_exit: curl_exit,
            http_code: http_code,
            file_size: length(content || ""),
            detail: sprintf("body length %d < %d", length(content || ""), MIN_PAYLOAD_BYTES)
        });
    }

    return _net_fetch_ok(content, mode, proxy_port, {
        exit_code: curl_exit,
        curl_exit: curl_exit,
        http_code: http_code,
        file_size: file_size
    });
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

function _first_param(params, keys) {
    params = params || {};
    for (let i = 0; i < length(keys); i++) {
        let v = params[keys[i]];
        if (v != null && length(trim(sprintf("%s", v))) > 0) return trim(sprintf("%s", v));
    }
    return "";
}

function _split_host_port(raw_host, fallback_port) {
    let out = {
        host: trim(sprintf("%s", raw_host || "")),
        port: fallback_port || ""
    };

    if (length(out.host) === 0) return out;

    if (substr(out.host, 0, 1) === "[") {
        let close_idx = index(out.host, "]");
        if (close_idx > 0) {
            let inner_host = substr(out.host, 1, close_idx - 1);
            let remainder = substr(out.host, close_idx + 1);
            if (substr(remainder, 0, 1) === ":") {
                let p = replace(substr(remainder, 1), regexp('[^0-9]', 'g'), '');
                if (length(p) > 0) out.port = p;
            }
            out.host = inner_host;
        }
        return out;
    }

    let colon_idx = index(out.host, ":");
    if (colon_idx >= 0 && index(substr(out.host, colon_idx + 1), ":") < 0) {
        let tail = substr(out.host, colon_idx + 1);
        let p = replace(tail, regexp('[^0-9]', 'g'), '');
        if (length(p) > 0 && length(p) === length(tail)) {
            out.host = substr(out.host, 0, colon_idx);
            out.port = p;
        }
    }

    return out;
}

function _resolve_server_target(url, params, scheme, transport) {
    let raw = _first_param(params, [ "server", "address", "add", "remote", "endpoint" ]);
    let source = "explicit";

    /*
     * Some converters put the real dial target in host for URI-style AnyTLS or
     * plain TCP links. Do not use host for WS/HTTP transports by default,
     * because there it normally means the HTTP Host header.
     */
    if (!raw) {
        let allow_host = (scheme === "anytls" || scheme === "tuic" || scheme === "hysteria2" || scheme === "hy2");
        if ((scheme === "trojan" || scheme === "vless") && (!transport || transport === "tcp")) {
            allow_host = true;
        }
        if (allow_host) {
            raw = _first_param(params, [ "host" ]);
            source = "host";
        }
    }

    if (!raw) {
        return {
            host: url ? (url.hostname || "") : "",
            port: url ? (url.port || "") : "",
            source: "authority"
        };
    }

    let hp = _split_host_port(raw, url ? (url.port || "") : "");
    hp.source = source;
    return hp;
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
            transport = (params.type && params.type !== 'tcp') ? params.type : "";
            server_target = _resolve_server_target(url, params, scheme, params.type || "");
            config = { 
                label: default_label, type: 'trojan', address: server_target.host, port: server_target.port, password: url.username, 
                transport: transport, 
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
            server_target = _resolve_server_target(url, params, scheme, "");
            config = { label: default_label, type: 'tuic', address: server_target.host, port: server_target.port, uuid: url.username, password: url.password || "", tls: '1', tls_sni: params.sni || "", tuic_congestion_control: params.congestion_control || "", tuic_udp_relay_mode: params.udp_relay_mode || "", tls_alpn: params.alpn || "", tls_insecure: is_insec };
            break;
        case 'anytls':
            server_target = _resolve_server_target(url, params, scheme, "");
            config = { label: default_label, type: 'anytls', address: server_target.host, port: server_target.port, password: url.username, tls: '1', tls_sni: params.sni || "", tls_insecure: is_insec };
            break;
        case 'hysteria2':
        case 'hy2':
            server_target = _resolve_server_target(url, params, scheme, "");
            hy2_pass = url.username || ""; if (url.password) hy2_pass += ":" + url.password;
            config = { label: default_label, type: 'hysteria2', address: server_target.host, port: server_target.port, password: hy2_pass, hysteria_obfs_type: params.obfs || "", hysteria_obfs_password: params['obfs-password'] || "", tls: '1', tls_insecure: is_insec, tls_sni: params.sni || "" };
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
        let fetch_res = _net_fetch(airport_cfg.url, global_opts, trace_id);

        if (!fetch_res || !fetch_res.ok) {
            let err_code = (fetch_res && fetch_res.error) ? fetch_res.error : "network_fetch_failed";
            let err_mode = (fetch_res && fetch_res.mode) ? fetch_res.mode : "unknown";
            let err_stage = (fetch_res && fetch_res.stage) ? fetch_res.stage : STAGE_FETCH;
            let err_port = (fetch_res && fetch_res.proxy_port) ? fetch_res.proxy_port : "";
            let curl_exit = (fetch_res && fetch_res.curl_exit != null) ? fetch_res.curl_exit : -1;
            let http_code = (fetch_res && fetch_res.http_code) ? fetch_res.http_code : "";
            let file_size = (fetch_res && fetch_res.file_size != null) ? fetch_res.file_size : -1;
            let err_detail = sprintf(
                "fetch failed: error=%s stage=%s mode=%s curl_exit=%d http_code=%s size=%s detail=%s",
                err_code, err_stage, err_mode, curl_exit, http_code || "-",
                (file_size >= 0) ? sprintf("%d", file_size) : "-",
                (fetch_res && fetch_res.detail) ? fetch_res.detail : ""
            );
            if (length(err_port) > 0) err_detail += sprintf(" proxy_port=%s", err_port);
            if (err_code === "proxy_unavailable") {
                err_detail = "fetch failed: proxy_unavailable (no mixed/socks port configured)";
            }
            log(trace_id, 'WARN', 'SUBSCRIPTION', err_detail);
            return Fail(ERR.E_NETWORK_FAULT, err_detail, trace_id);
        }

        let res = fetch_res.content;
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
        return Success(with_changed(length(nodes) > 0, { nodes: nodes }), 200, trace_id);

    } catch (e) {
        let err_msg = "" + e;
        log(trace_id, 'CRIT', 'SUBSCRIPTION', 'Fatal Crash during parsing: ' + err_msg);
        return Fail(ERR.E_SYSTEM_BUSY, err_msg, trace_id);
    }
}

function task_update_subscriptions(trace_id, payload) {
    payload = payload || {};
    let start_time = time();
    let total_nodes = 0;
    let failed_airports = [];
    let success_airports = [];
    let airport_stats = [];

    let scope = payload.scope === 'all' ? 'all' : null;
    let ap_res = list_enabled_airports(trace_id, scope, payload.airport_id);
    if (!ap_res.ok) return Fail(ERR.E_SYSTEM_BUSY, ap_res.detail, trace_id);

    let target_airports = ap_res.data;
    if (length(target_airports) === 0) {
        return Fail(ERR.E_SYSTEM_BUSY, "没有找到任何已启用的订阅节点", trace_id);
    }

    let opts_res = build_subscription_opts(trace_id, payload);
    if (!opts_res.ok) return Fail(ERR.E_SYSTEM_BUSY, opts_res.detail, trace_id);
    let global_opts = opts_res.data;

    log(trace_id, 'INFO', 'SUBSCRIPTION', sprintf("Subscription fetch mode: %s, proxy_port: %s",
        (global_opts.update_via_proxy === '1' || global_opts.update_via_proxy === 1 || global_opts.update_via_proxy === true) ? "proxy" : "direct",
        global_opts.proxy_port || "(none)"));

    let success_count = 0;
    for (let i = 0; i < length(target_airports); i++) {
        let ap = target_airports[i];
        ap.id = ap.stable_airport_id || ap.name || ap['.name'];
        let res = fetch_and_parse(ap, global_opts, trace_id);
        let valid_nodes = (res.ok && res.data && type(res.data.nodes) === 'array') ? res.data.nodes : [];
        let ap_name = ap.name || ap.id;

        if (!res.ok || length(valid_nodes) === 0) {
            let fail_reason = res.ok ? "parse yielded 0 nodes" : (res.detail || "unknown");
            log(trace_id, 'ERROR', 'SUBSCRIPTION', sprintf("Airport [%s] fetch failed: %s", ap_name, fail_reason));
            push(failed_airports, ap_name);
        } else {
            let sync_res = StateManager.sync_uci_nodes(ap.id, valid_nodes, trace_id, [ap.legacy_airport_id]);
            if (!sync_res.ok) {
                log(trace_id, 'ERROR', 'SUBSCRIPTION', sprintf("Airport [%s] UCI write failed: %s", ap_name, sync_res.detail || "unknown"));
                push(failed_airports, ap_name + " (uci_write_failed)");
                continue;
            }
            log(trace_id, 'INFO', 'SUBSCRIPTION', sprintf("Airport [%s] subscription_success=true uci_write_success=true nodes=%d", ap_name, length(valid_nodes)));
            success_count++;
            total_nodes += length(valid_nodes);
            push(airport_stats, {
                name: ap_name,
                nodes: length(valid_nodes)
            });
            push(success_airports, sprintf("🔼 <b>%s:</b> %d 节点", ap_name, length(valid_nodes)));
        }
    }

    if (success_count === 0) {
        let fail_msg = "所有订阅均拉取失败";
        if (length(failed_airports) > 0) {
            fail_msg += "。失败清单: " + join(", ", failed_airports);
        }
        return Fail(ERR.E_SYSTEM_BUSY, fail_msg, trace_id);
    }

    let group_res = task_rebuild_groups(trace_id);
    if (!group_res.ok) return Fail(ERR.E_SYSTEM_BUSY, "分组重建失败: " + group_res.detail, trace_id);

    log(trace_id, 'INFO', 'SUBSCRIPTION', 'Subscription business phase completed: subscription_success=true uci_write_success=true group_rebuild_success=true');
    let duration = time() - start_time;
    let summary_msg = (length(failed_airports) > 0)
        ? "⚠️ <b>部分订阅更新失败</b>%0A"
        : "✅ <b>订阅全局更新成功</b>%0A";
    summary_msg += "━━━━━━━━━━━━━━━━━━%0A";
    summary_msg += sprintf("⏱️ <b>总耗时:</b> %d 秒 | <b>总节点:</b> %d%0A%0A", duration, total_nodes);
    summary_msg += "📑 <b>更新清单:</b>%0A" + join("%0A", success_airports) + "%0A";
    if (length(failed_airports) > 0) {
        summary_msg += "%0A❌ <b>失败断联:</b>%0A" + join(", ", failed_airports) + "%0A";
    }
    summary_msg += "%0A[RESTART_PENDING]";

    return Success(with_changed(true, {
        msg: summary_msg,
        subscription_success: true,
        uci_write_success: true,
        group_rebuild_success: true,
        dataplane_success: null,
        success_count: success_count,
        failed_count: length(failed_airports),
        failed_airports: failed_airports,
        airport_stats: airport_stats,
        duration_sec: duration,
        total_nodes: total_nodes
    }), 200, trace_id);
}

export { fetch_and_parse, task_update_subscriptions };
