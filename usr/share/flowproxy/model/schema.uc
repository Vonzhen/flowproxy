/**
 * FlowProxy | model/schema.uc | v1.0 TProxy-Redirect Full-Armor Edition
 * 职责：从 UCI 读取用户意图，构建系统抽象数据模型 (FlowModel)。
 * 核心对齐：全面回归 TProxy+Redirect 架构，对接 1.0 Result 协议，清除 TUN 依赖。
 */

'use strict';

// 🚨 铁律 5: 原生模块解构导入
import { cursor } from 'uci';

// 🚨 铁律 3: 绝对命名空间寻址
import { PATH } from 'flowproxy.core.constants';
import { load_uci_context } from 'flowproxy.core.config_helper';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';

function strToInt(val) { return (val != null && val !== "") ? int(val) : null; }
function strToBool(val) { return (val != null && val !== "") ? (val === '1' || val === 'true') : null; }
const U_CONFIG = 'flowproxy';
const S_INFRA = 'infra';
const S_MAIN = 'config';
const S_ROUTING = 'routing';

function strToIntDefault(val, fallback) {
    let parsed = strToInt(val);
    return parsed != null ? parsed : fallback;
}

function strToBoolDefault(val, fallback) {
    let parsed = strToBool(val);
    return parsed != null ? parsed : fallback;
}

function strOrDefault(val, fallback) {
    if (val == null) return fallback;
    let s = "" + val;
    return length(trim(s)) > 0 ? s : fallback;
}

function get_proxy_mode(u) {
    let mode = strOrDefault(
        u.get(U_CONFIG, S_MAIN, 'proxy_mode'),
        strOrDefault(u.get(U_CONFIG, S_ROUTING, 'proxy_mode'), "redirect_tproxy")
    );
    if (mode === "redirect" || mode === "redirect_tproxy") return "redirect_tproxy";
    if (mode === "redirect_tun" || mode === "tun") return "tun";
    return mode;
}

function get_tun_dns_mode(u) {
    return strOrDefault(u.get(U_CONFIG, S_INFRA, 'tun_dns_mode'), "hijack");
}

function build_listen_policy(u) {
    let allow_lan = u.get(U_CONFIG, S_MAIN, 'allow_lan') === '1';
    return {
        allow_lan: allow_lan,
        safe_listen_addr: allow_lan ? '::' : '127.0.0.1'
    };
}

function is_tun_dns_hijack(u, proxy_mode) {
    return proxy_mode === "tun" && get_tun_dns_mode(u) === "hijack";
}

/**
 * 组装 Sing-box 入站平面 (Inbounds)
 * 完美复刻 TProxy + Redirect 双擎，向下兼容 UI 混合模式变量
 */
function build_base_inbounds(u, snap, proxy_mode) {
    let inbounds = [];
    let mixed_port = (snap && snap.mixed_port) ? snap.mixed_port : u.get(U_CONFIG, S_INFRA, 'mixed_port');
    let dns_port = u.get(U_CONFIG, S_INFRA, 'dns_port');
    // 基础管理入站
    if (dns_port && !is_tun_dns_hijack(u, proxy_mode)) push(inbounds, { type: 'direct', tag: 'dns-in', listen: '::', listen_port: strToInt(dns_port) });
    if (mixed_port) push(inbounds, { type: 'mixed', tag: 'mixed-in', listen: '::', listen_port: strToInt(mixed_port), set_system_proxy: false });
    
    // 🚨 核心复刻：依据 UI 变量动态分发 TCP 与 UDP 物理拦截闸门
    // 💡 备忘：TUN 组装管线已奉旨无限期终止，彻底绝后

    u.foreach(U_CONFIG, 'server', (cfg) => {
        if (cfg.enabled !== '1') return;
        push(inbounds, { type: cfg.type, tag: sprintf("cfg-server-%s-in", cfg['.name']), listen: cfg.address || '::', listen_port: strToInt(cfg.port), tcp_fast_open: strToBool(cfg.tcp_fast_open), tcp_multi_path: strToBool(cfg.tcp_multi_path), udp_fragment: strToBool(cfg.udp_fragment) });
    });

    return inbounds;
}

function build_tproxy_inbounds(u) {
    let inbounds = [];
    let redirect_port = u.get(U_CONFIG, S_INFRA, 'redirect_port') || '5331';
    let tproxy_port = u.get(U_CONFIG, S_INFRA, 'tproxy_port') || '5332';

    push(inbounds, { type: 'redirect', tag: 'redirect-in', listen: '::', listen_port: strToInt(redirect_port) });
    push(inbounds, { type: 'tproxy', tag: 'tproxy-in', listen: '::', listen_port: strToInt(tproxy_port), network: 'udp' });

    return inbounds;
}

function build_tun_inbound(u) {
    let addr4 = strOrDefault(u.get(U_CONFIG, S_INFRA, 'tun_addr4'), "172.19.0.1/30");
    let addr6 = strOrDefault(u.get(U_CONFIG, S_INFRA, 'tun_addr6'), "fdfe:dcba:9876::1/126");
    let stack = strOrDefault(
        u.get(U_CONFIG, S_MAIN, 'tcpip_stack'),
        strOrDefault(
            u.get(U_CONFIG, S_ROUTING, 'tcpip_stack'),
            strOrDefault(u.get(U_CONFIG, S_INFRA, 'tun_stack'), "system")
        )
    );

    return {
        type: 'tun',
        tag: 'tun-in',
        interface_name: strOrDefault(u.get(U_CONFIG, S_INFRA, 'tun_name'), "singtun0"),
        address: [addr4, addr6],
        mtu: strToIntDefault(u.get(U_CONFIG, S_INFRA, 'tun_mtu'), 9000),
        auto_route: strToBoolDefault(u.get(U_CONFIG, S_INFRA, 'tun_auto_route'), true),
        strict_route: strToBoolDefault(u.get(U_CONFIG, S_INFRA, 'tun_strict_route'), true),
        auto_redirect: strToBoolDefault(u.get(U_CONFIG, S_INFRA, 'tun_auto_redirect'), true),
        dns_mode: get_tun_dns_mode(u),
        stack: stack
    };
}

function build_inbounds(u, snap) {
    let proxy_mode = get_proxy_mode(u);

    if (proxy_mode !== "redirect_tproxy" && proxy_mode !== "tun") {
        return Fail(ERR.E_CONFIG_FAULT, "Unsupported proxy mode: " + proxy_mode);
    }

    let inbounds = build_base_inbounds(u, snap, proxy_mode);

    if (proxy_mode === "redirect_tproxy") {
        let tproxy_inbounds = build_tproxy_inbounds(u);
        for (let i = 0; i < length(tproxy_inbounds); i++) push(inbounds, tproxy_inbounds[i]);
    } else if (proxy_mode === "tun") {
        push(inbounds, build_tun_inbound(u));
    }

    return inbounds;
}

function build_outbounds(u, proxy_mode) {
    let endpoints = [];
    let outbounds = [];
    let endpoint_dict = {};
    
    let self_mark = strToInt(u.get(U_CONFIG, S_INFRA, 'self_mark')) || 100;
    let tun_auto_redirect = strToBoolDefault(u.get(U_CONFIG, S_INFRA, 'tun_auto_redirect'), true);
    let use_routing_mark = !(proxy_mode === "tun" && tun_auto_redirect);

    let direct_out = { type: 'direct', tag: 'direct-out' };
    if (use_routing_mark) direct_out.routing_mark = self_mark;
    push(outbounds, direct_out);
    push(outbounds, { type: 'block', tag: 'block-out' });

    u.foreach(U_CONFIG, 'node', (cfg) => {
        if (type(cfg) !== 'object') return;
        let endpoint_tag = sprintf("cfg-%s-out", cfg['.name']);
        push(endpoints, cfg);
        endpoint_dict[endpoint_tag] = true;
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

    return {
        endpoint_policy: {
            self_mark: self_mark,
            use_routing_mark: use_routing_mark
        },
        endpoints: endpoints,
        outbounds: outbounds
    };
}

function build_policies(u, valid_outbounds) {
    let route = { rules: [], rule_set: [] };
    let dns = { servers: [], rules: [] };
    let proxy_mode = get_proxy_mode(u);
    let tun_auto_redirect = strToBoolDefault(u.get(U_CONFIG, S_INFRA, 'tun_auto_redirect'), true);

    let dns_strat = u.get(U_CONFIG, 'dns', 'dns_strategy');
    if (dns_strat) dns.strategy = dns_strat;

    u.foreach(U_CONFIG, 'dns_server', (cfg) => {
        if (cfg.enabled !== '1') return;
        let out_target = (cfg.outbound === 'direct-out' || cfg.outbound === 'block-out') ? cfg.outbound : sprintf("cfg-%s-out", cfg.outbound);
        if (out_target !== 'direct-out' && out_target !== 'block-out' && !valid_outbounds[out_target]) out_target = 'direct-out';
        let server_obj = { tag: sprintf("cfg-%s-dns", cfg['.name']), type: cfg.type || 'udp', server: cfg.server };
        if (!(proxy_mode === "tun" && tun_auto_redirect && out_target === 'direct-out')) {
            server_obj.detour = out_target;
        }
        push(dns.servers, server_obj);
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

    // 🚨 1.14+ 核心捍卫：全局嗅探与官方标准原生 DNS 劫持机制
    push(route.rules, { action: "sniff" });
    if (!is_tun_dns_hijack(u, proxy_mode)) push(route.rules, { inbound: "dns-in", action: "hijack-dns" });
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

    route.auto_detect_interface = true;

    let def_dns = u.get(U_CONFIG, 'dns', 'default_server');
    if (def_dns) dns.final = sprintf("cfg-%s-dns", def_dns);
    
    let default_outbound_dns = u.get(U_CONFIG, 'routing', 'default_outbound_dns');
    if (default_outbound_dns) route.default_domain_resolver = { server: sprintf("cfg-%s-dns", default_outbound_dns) };

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

/**
 * 核心流水线构建函数
 * 遵循 1.0 Result 协议封装，带有全局防爆 TRY...CATCH 装甲
 */
function build_flow_model(trace_id) {
    try {
        let ctx_res = load_uci_context(trace_id);
        if (!ctx_res.ok) {
            return Fail(ERR.E_CONFIG_FAULT, ctx_res.detail, trace_id);
        }
        let u = ctx_res.data.u;
        let snap = ctx_res.data.snap;

        let inbounds = build_inbounds(u, snap);
        if (inbounds && inbounds.ok === false) return inbounds;
        let proxy_mode = get_proxy_mode(u);
        let obs = build_outbounds(u, proxy_mode);
        
        let valid_outbounds = {};
        for (let i = 0; i < length(obs.outbounds); i++) valid_outbounds[obs.outbounds[i].tag] = true;
        for (let i = 0; i < length(obs.endpoints); i++) valid_outbounds[sprintf("cfg-%s-out", obs.endpoints[i]['.name'])] = true;

        let pd = build_policies(u, valid_outbounds);
        let exp_model = build_experimental(u);

        let flow_model = {
            schema_version: "1.2",
            enabled: snap.service_enabled,
            listen_policy: build_listen_policy(u),
            log: { level: u.get(U_CONFIG, S_MAIN, 'log_level') || 'warn', output_path: PATH.LOG_RUN },
            experimental: exp_model,
            inbounds: inbounds,
            endpoint_policy: obs.endpoint_policy,
            endpoints: obs.endpoints,
            outbounds: obs.outbounds,
            route: pd.route,
            dns: pd.dns
        };

        // 💡 架构备注：宿主本机 NTP 逻辑已自此彻底连根拔除，消灭冷启动死锁源

        return Success(flow_model, 200, trace_id);
    } catch(e) {
        // 🚨 铁律 6：隐式异常捕获与类型安全转换
        let err_str = "" + e;
        return Fail(ERR.E_CONFIG_FAULT, "Schema Build Exception: " + err_str, trace_id);
    }
}

// 🚨 铁律 1: 文件末尾统一集中导出，捍预零件身份
export { build_flow_model };
