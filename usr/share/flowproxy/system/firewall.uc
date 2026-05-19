/**
 * FlowProxy | system/firewall.uc | v1.4 TProxy-Armor Edition
 * 职责：独立主权防火墙图纸生成器。
 * 核心对齐：剥离 OUTPUT 链中的 tproxy 关键字，实现 TProxy 的合法内核注入。
 */

'use strict';

import { cursor } from 'uci';
import { readfile, writefile } from 'fs';
import { PATH } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { log } from 'flowproxy.core.logger';

function strToInt(val) { return (val != null && val !== "") ? int(val) : null; }

function load_resource(filename) {
    let content = readfile(sprintf('%s/%s', PATH.ASSETS, filename));
    if (!content) return '';
    let lines = split(trim(content), '\n');
    let valid = [];
    for (let i = 0; i < length(lines); i++) {
        let l = trim(lines[i]);
        if (length(l) > 0) push(valid, l);
    }
    return length(valid) > 0 ? sprintf('elements = { %s }', join(', ', valid)) : '';
}

function get_acl_list(u, option) {
    let list = u.get('flowproxy', 'control', option);
    if (!list) return '';
    if (type(list) === 'string') list = [list];
    let valid = [];
    for (let i = 0; i < length(list); i++) {
        let l = trim(list[i]);
        if (length(l) > 0) push(valid, l);
    }
    return length(valid) > 0 ? sprintf('{ %s }', join(', ', valid)) : '';
}

function build_firewall(trace_id) {
    try {
        log(trace_id, 'INFO', 'FIREWALL', 'Starting compilation of TProxy full-armor nftables ruleset...');
        
        let u = cursor();
        u.load('flowproxy');
        
        let redirect_port = strToInt(u.get('flowproxy', 'infra', 'redirect_port')) || 5331;
        let tproxy_port = strToInt(u.get('flowproxy', 'infra', 'tproxy_port')) || 5332;
        let dns_port = strToInt(u.get('flowproxy', 'infra', 'dns_port')) || 5333;
        
        // 🚨 架构修复：动态读取边界标识
        let self_mark = u.get('flowproxy', 'infra', 'self_mark') || '100';
        let tproxy_mark = u.get('flowproxy', 'infra', 'tproxy_mark') || '101';
        
        let cn_ipv4_elements = load_resource('china_ip4.txt');
        let cn_ipv6_elements = load_resource('china_ip6.txt');
        
        let mac_direct = get_acl_list(u, 'lan_direct_mac_addrs');
        let mac_global = get_acl_list(u, 'lan_global_proxy_mac_addrs');
        let ip4_direct = get_acl_list(u, 'lan_direct_ipv4_ips');
        let ip4_global = get_acl_list(u, 'lan_global_proxy_ipv4_ips');

        let rules = [];
        
        push(rules, "table inet flowproxy {");
        
        // --- 物理防线 ---
        push(rules, "    set local_ipv4 {");
        push(rules, "        type ipv4_addr; flags interval; auto-merge;");
        push(rules, "        elements = { 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }");
        push(rules, "    }");
        push(rules, "    set local_ipv6 {");
        push(rules, "        type ipv6_addr; flags interval; auto-merge;");
        push(rules, "        elements = { ::1/128, fc00::/7, fe80::/10, ff00::/8 }");
        push(rules, "    }");

        push(rules, "    set china_ipv4 {");
        push(rules, "        type ipv4_addr; flags interval; auto-merge;");
        if (cn_ipv4_elements) push(rules, "        " + cn_ipv4_elements);
        push(rules, "    }");
        push(rules, "    set china_ipv6 {");
        push(rules, "        type ipv6_addr; flags interval; auto-merge;");
        if (cn_ipv6_elements) push(rules, "        " + cn_ipv6_elements);
        push(rules, "    }");

        // ==========================================
        // ⚔️ 闸门 1：PREROUTING NAT (局域网 TCP & DNS)
        // ==========================================
        push(rules, "    chain prerouting_nat {");
        push(rules, "        type nat hook prerouting priority dstnat - 5; policy accept;");
        push(rules, "        iifname \"lo\" counter return");
        if (mac_direct) push(rules, "        ether saddr " + mac_direct + " counter return");
        if (ip4_direct) push(rules, "        ip saddr " + ip4_direct + " counter return");
        push(rules, "        meta nfproto { ipv4, ipv6 } udp dport 53 counter redirect to :" + dns_port + " comment \"FlowProxy: DNS Hijack\"");
        push(rules, "        meta l4proto tcp jump process_tcp");
        push(rules, "    }");

        // ==========================================
        // ⚔️ 闸门 2：PREROUTING MANGLE (局域网 UDP TProxy)
        // ==========================================
        push(rules, "    chain prerouting_mangle {");
        push(rules, "        type filter hook prerouting priority mangle - 5; policy accept;");
        push(rules, sprintf("        meta mark { %s, 255 } counter return", self_mark)); // 免疫环回无限死锁
        push(rules, "        meta l4proto udp jump process_udp_prerouting");
        push(rules, "    }");

        // ==========================================
        // 🛡️ 闸门 3：OUTPUT NAT (路由器本机 TCP)
        // ==========================================
        push(rules, "    chain output_nat {");
        push(rules, "        type nat hook output priority filter - 5; policy accept;");
        push(rules, sprintf("        meta mark { %s, 255 } counter return", self_mark)); // 放行 Sing-box 自身发出的 TCP
        push(rules, "        meta l4proto tcp jump process_tcp");
        push(rules, "    }");

        // ==========================================
        // 🛡️ 闸门 4：OUTPUT MANGLE (路由器本机 UDP 纯打标)
        // ==========================================
        push(rules, "    chain output_mangle {");
        push(rules, "        type route hook output priority mangle - 5; policy accept;");
        push(rules, sprintf("        meta mark { %s, 255 } counter return", self_mark)); // 放行 Sing-box 自身发出的 UDP
        push(rules, "        meta l4proto udp jump process_udp_output");
        push(rules, "    }");

        // --- 子链：共享的 TCP 处理 ---
        push(rules, "    chain process_tcp {");
        if (mac_direct) push(rules, "        ether saddr " + mac_direct + " counter return");
        if (ip4_direct) push(rules, "        ip saddr " + ip4_direct + " counter return");
        push(rules, "        meta l4proto tcp ip daddr @local_ipv4 counter return");
        push(rules, "        meta l4proto tcp ip6 daddr @local_ipv6 counter return");
        if (mac_global) push(rules, "        ether saddr " + mac_global + " counter redirect to :" + redirect_port);
        if (ip4_global) push(rules, "        ip saddr " + ip4_global + " counter redirect to :" + redirect_port);
        push(rules, "        meta l4proto tcp ip daddr @china_ipv4 counter return");
        push(rules, "        meta l4proto tcp ip6 daddr @china_ipv6 counter return");
        push(rules, "        meta l4proto tcp counter redirect to :" + redirect_port + " comment \"FlowProxy: TCP Redirect\"");
        push(rules, "    }");

        // --- 子链：PREROUTING 的 UDP (合法使用 tproxy) ---
        push(rules, "    chain process_udp_prerouting {");
        push(rules, "        udp dport 53 counter return");
        if (mac_direct) push(rules, "        ether saddr " + mac_direct + " counter return");
        if (ip4_direct) push(rules, "        ip saddr " + ip4_direct + " counter return");
        push(rules, "        meta l4proto udp ip daddr @local_ipv4 counter return");
        push(rules, "        meta l4proto udp ip6 daddr @local_ipv6 counter return");
        if (mac_global) push(rules, sprintf("        ether saddr %s meta mark set %s tproxy ip to 127.0.0.1:%s counter accept", mac_global, tproxy_mark, tproxy_port));
        if (ip4_global) push(rules, sprintf("        ip saddr %s meta mark set %s tproxy ip to 127.0.0.1:%s counter accept", ip4_global, tproxy_mark, tproxy_port));
        push(rules, "        meta l4proto udp ip daddr @china_ipv4 counter return");
        push(rules, "        meta l4proto udp ip6 daddr @china_ipv6 counter return");
        
        push(rules, sprintf("        meta l4proto udp meta mark set %s tproxy ip to 127.0.0.1:%s counter accept", tproxy_mark, tproxy_port));
        push(rules, sprintf("        meta l4proto udp meta mark set %s tproxy ip6 to [::1]:%s counter accept", tproxy_mark, tproxy_port));
        push(rules, "    }");

        // --- 子链：OUTPUT 的 UDP (禁止 tproxy，只允许打标) ---
        push(rules, "    chain process_udp_output {");
        push(rules, "        udp dport 53 counter return");
        if (ip4_direct) push(rules, "        ip saddr " + ip4_direct + " counter return");
        push(rules, "        meta l4proto udp ip daddr @local_ipv4 counter return");
        push(rules, "        meta l4proto udp ip6 daddr @local_ipv6 counter return");
        if (ip4_global) push(rules, sprintf("        ip saddr %s meta mark set %s counter accept", ip4_global, tproxy_mark));
        push(rules, "        meta l4proto udp ip daddr @china_ipv4 counter return");
        push(rules, "        meta l4proto udp ip6 daddr @china_ipv6 counter return");
        
        push(rules, sprintf("        meta l4proto udp meta mark set %s counter accept comment \"FlowProxy: Local UDP Mark\"", tproxy_mark));
        push(rules, "    }");

        push(rules, "}");

        let nft_template = join('\n', rules);

        writefile(PATH.FIREWALL_NFT, nft_template);
        log(trace_id, 'INFO', 'FIREWALL', 'Successfully compiled firewall armor to ' + PATH.FIREWALL_NFT);
        return Success(true, 200, trace_id);
    } catch(e) {
        let err_msg = "" + e;
        log(trace_id, 'CRIT', 'FIREWALL', 'Compilation Exception: ' + err_msg);
        return Fail(ERR.E_SYSTEM_BUSY, "Firewall Build Exception: " + err_msg, trace_id);
    }
}

export { build_firewall };
