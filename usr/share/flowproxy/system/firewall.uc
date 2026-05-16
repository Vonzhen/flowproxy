/**
 * FlowProxy | system/firewall.uc | v1.0 TProxy-Redirect Armor Edition
 * 职责：独立主权防火墙图纸生成器。
 * 核心对齐：解析国内外 IP 路由集与局域网策略，生成独立、可瞬间物理销毁的 nftables 规则文件。
 */

'use strict';

// 🚨 铁律 5: 原生模块解构导入
import { cursor } from 'uci';
import { readfile, writefile } from 'fs';

// 🚨 铁律 3: 绝对命名空间寻址
import { PATH } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { log } from 'flowproxy.core.logger';

const RES_DIR = '/etc/flowproxy/resources';

/**
 * 安全加载资源文件并转换为 nftables 集合格式
 */
function load_resource(filename) {
    let content = readfile(sprintf('%s/%s', RES_DIR, filename));
    if (!content) return '';
    
    let lines = split(trim(content), '\n');
    let valid_lines = [];
    for (let i = 0; i < length(lines); i++) {
        let l = trim(lines[i]);
        if (length(l) > 0) push(valid_lines, l);
    }
    
    return length(valid_lines) > 0 ? sprintf('elements = { %s }', join(', ', valid_lines)) : '';
}

/**
 * 从 UCI 读取局域网控制列表 (MAC/IP)，格式化为 nftables 数组
 */
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

/**
 * 核心业务：编译防火墙图纸
 * @param {string} trace_id - 全链路追踪 ID
 */
function build_firewall(trace_id) {
    try {
        log(trace_id, 'INFO', 'FIREWALL', 'Starting compilation of TProxy full-armor nftables ruleset...');
        
        let u = cursor();
        u.load('flowproxy');
        
        // 读取监听端口（向下兼容图纸）
        let redirect_port = strToInt(u.get('flowproxy', 'infra', 'redirect_port')) || 5331;
        let tproxy_port = strToInt(u.get('flowproxy', 'infra', 'tproxy_port')) || 5332;
        let dns_port = strToInt(u.get('flowproxy', 'infra', 'dns_port')) || 5333;
        
        // 加载武器库
        log(trace_id, 'INFO', 'FIREWALL', 'Loading IPv4/IPv6 resource dictionaries...');
        let cn_ipv4_elements = load_resource('china_ip4.txt');
        let cn_ipv6_elements = load_resource('china_ip6.txt');
        
        // 读取局域网特权策略
        let mac_direct = get_acl_list(u, 'lan_direct_mac_addrs');
        let mac_global = get_acl_list(u, 'lan_global_proxy_mac_addrs');
        let ip4_direct = get_acl_list(u, 'lan_direct_ipv4_ips');
        let ip4_global = get_acl_list(u, 'lan_global_proxy_ipv4_ips');

        // 🚨 架构战果：独立主权 table 宣告
        // 这是系统稳定性的核心基石。不混入 fw4，保证了卸载时的绝对无残留。
        let nft_template = sprintf(`
table inet flowproxy {
    # [物理防线 1] 内网保留地址（绝对不碰）
    set local_ipv4 {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }
    }
    set local_ipv6 {
        type ipv6_addr
        flags interval
        auto-merge
        elements = { ::1/128, fc00::/7, fe80::/10, ff00::/8 }
    }

    # [物理防线 2] 大陆白名单 IP 库
    set china_ipv4 {
        type ipv4_addr
        flags interval
        auto-merge
        %s
    }
    set china_ipv6 {
        type ipv6_addr
        flags interval
        auto-merge
        %s
    }

    # [拦截网 1] 局域网无感 DNS 劫持
    chain dstnat {
        type nat hook prerouting priority dstnat - 5; policy accept;
        
        # 直连设备豁免 DNS 劫持
        %s
        %s
        
        meta nfproto { ipv4, ipv6 } udp dport 53 counter redirect to :%d comment "FlowProxy: Core DNS Hijack"
    }

    # [拦截网 2] TCP 流量重定向 (Redirect)
    chain prerouting_tcp {
        # 1. 局域网强制直连名单豁免
        %s
        %s
        
        # 2. 内网互访豁免
        meta l4proto tcp ip daddr @local_ipv4 counter return
        meta l4proto tcp ip6 daddr @local_ipv6 counter return
        
        # 3. 局域网强制全局代理名单（跳过境内判定，直接击杀）
        %s
        %s
        
        # 4. BGP 境内直连判定
        meta l4proto tcp ip daddr @china_ipv4 counter return
        meta l4proto tcp ip6 daddr @china_ipv6 counter return
        
        # 5. 海外流量物理重定向
        meta l4proto tcp counter redirect to :%d comment "FlowProxy: TCP Redirect Engine"
    }

    # [拦截网 3] UDP 流量透明代理 (TProxy)
    chain prerouting_udp {
        # 0. 避让 DNS 端口 (已由 dstnat 链处理)
        udp dport 53 counter return
        
        # 1. 局域网强制直连名单豁免
        %s
        %s
        
        # 2. 内网互访豁免
        meta l4proto udp ip daddr @local_ipv4 counter return
        meta l4proto udp ip6 daddr @local_ipv6 counter return
        
        # 3. 局域网强制全局代理名单（跳过境内判定）
        %s
        %s
        
        # 4. BGP 境内直连判定
        meta l4proto udp ip daddr @china_ipv4 counter return
        meta l4proto udp ip6 daddr @china_ipv6 counter return
        
        # 5. 海外流量打标引流 (fwmark 101)
        meta l4proto udp meta mark set 101 tproxy ip to 127.0.0.1:%d counter accept comment "FlowProxy: UDP TProxy v4"
        meta l4proto udp meta mark set 101 tproxy ip6 to [::1]:%d counter accept comment "FlowProxy: UDP TProxy v6"
    }

    # [主网闸门] 过路流量嗅探
    chain prerouting {
        # 挂载于 mangle 表，接管局域网发往公网的所有前置流量
        type filter hook prerouting priority mangle - 5; policy accept;
        
        # 💡 绝对防爆设计：不挂载 hook output。路由器自身发包全部物理直连，免疫任何循环死锁！
        meta l4proto tcp jump prerouting_tcp
        meta l4proto udp jump prerouting_udp
    }
}
        `, 
        cn_ipv4_elements, 
        cn_ipv6_elements,
        // DNS 豁免注入
        mac_direct ? sprintf('ether saddr %s counter return', mac_direct) : '',
        ip4_direct ? sprintf('ip saddr %s counter return', ip4_direct) : '',
        // TCP 豁免注入
        mac_direct ? sprintf('ether saddr %s counter return', mac_direct) : '',
        ip4_direct ? sprintf('ip saddr %s counter return', ip4_direct) : '',
        // TCP 全局击杀注入
        mac_global ? sprintf('ether saddr %s counter redirect to :%d', mac_global, redirect_port) : '',
        ip4_global ? sprintf('ip saddr %s counter redirect to :%d', ip4_global, redirect_port) : '',
        redirect_port,
        // UDP 豁免注入
        mac_direct ? sprintf('ether saddr %s counter return', mac_direct) : '',
        ip4_direct ? sprintf('ip saddr %s counter return', ip4_direct) : '',
        // UDP 全局击杀注入
        mac_global ? sprintf('ether saddr %s meta mark set 101 tproxy ip to 127.0.0.1:%d counter accept', mac_global, tproxy_port) : '',
        ip4_global ? sprintf('ip saddr %s meta mark set 101 tproxy ip to 127.0.0.1:%d counter accept', ip4_global, tproxy_port) : '',
        tproxy_port, tproxy_port
        );

        // 将图纸写入运行时内存盘 (RAMFS)，保护闪存寿命
        let output_file = sprintf('%s/firewall.nft', PATH.RUN_DIR || '/var/run/flowproxy');
        writefile(output_file, nft_template);
        
        log(trace_id, 'INFO', 'FIREWALL', 'Successfully compiled firewall armor to ' + output_file);

        // ⭐ 协议对齐：透传 200 状态码
        return Success(true, 200, trace_id);
    } catch(e) {
        // 🚨 铁律 6：隐式异常捕获与类型安全转换
        let err_msg = "" + e;
        log(trace_id, 'CRIT', 'FIREWALL', 'Compilation Exception: ' + err_msg);
        return Fail(ERR.E_SYSTEM_BUSY, "Firewall Build Exception: " + err_msg, trace_id);
    }
}

// 🚨 铁律 1: 集中导出，捍卫零件身份
export { build_firewall };
