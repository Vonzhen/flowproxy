/**
 * FlowProxy | system/network.uc | v1.0
 * 职责：真实世界 (Reality Layer) 路由、IP Rule 与 Tun 网卡原子级装配器。
 */

'use strict';

// 1. [解构原生库] 遵守铁律 5
import { cursor } from 'uci';
import { readfile } from 'fs';

// 2. [引入基石法则] 遵守铁律 3
import { PATH, BIN } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { ExecSafe, shell_escape } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';

const ROUTE_TABLES = {
    SELF: 100,
    TPROXY: 101,
    TUN: 102
};

/**
 * 物理卸载所有的网络规则与虚拟网卡
 * @param {string} trace_id - 贯穿始终的链路 ID
 */
function teardown(trace_id) {
    try {
        // [Category B] 虚拟网卡清洗：基于实际系统快照的容错卸载
        let net_res = ExecSafe(BIN.SH, ['-c', 'ls /sys/class/net/ 2>/dev/null | grep "^singtun"'], null, trace_id);
        
        if (net_res.ok && net_res.data && net_res.data.stdout) {
            let tun_devices = split(net_res.data.stdout, '\n');
            for (let i = 0; i < length(tun_devices); i++) {
                let dev = trim(tun_devices[i]);
                if (dev && length(dev) > 0) {
                    let safe_dev = shell_escape(dev);
                    // [Category C] Note: 注入 || true 屏障，防止网卡在查询与删除间隙丢失引起的异常(Race Condition)
                    ExecSafe(BIN.SH, ['-c', sprintf('ip link set %s down 2>/dev/null || true', safe_dev)], null, trace_id);
                    ExecSafe(BIN.SH, ['-c', sprintf('ip tuntap del mode tun name %s 2>/dev/null || true', safe_dev)], null, trace_id);
                    // 在 teardown 函数的末尾，return Success 之前加入：
                    ExecSafe(BIN.SH, ['-c', 'nft list chain inet fw4 forward | grep "singtun" | while read -r line; do handle=$(echo "$line" | awk \'{print $NF}\'); nft delete rule inet fw4 forward handle "$handle"; done'], null, trace_id);
                    ExecSafe(BIN.SH, ['-c', 'nft list chain inet fw4 input | grep "singtun" | while read -r line; do handle=$(echo "$line" | awk \'{print $NF}\'); nft delete rule inet fw4 input handle "$handle"; done'], null, trace_id);
                    
                }
            }
        }

        // [Category B] 策略路由清洗：游离态规则与路由表的彻底清理
        let tables = [ROUTE_TABLES.SELF, ROUTE_TABLES.TPROXY, ROUTE_TABLES.TUN];
        for (let i = 0; i < length(tables); i++) {
            let tid = sprintf("%d", tables[i]);
            
            // [Category C] Warning: OpenWrt 可能存在多条指向同一 table 的遗留 rule。
            // 必须使用 while 循环彻底拔除，同时利用 || true 掩蔽“规则不存在”时的错误码，实现绝对幂等。
            let sh_clean_v4 = sprintf('while ip rule del table %s 2>/dev/null; do :; done; ip route flush table %s 2>/dev/null || true', tid, tid);
            let sh_clean_v6 = sprintf('while ip -6 rule del table %s 2>/dev/null; do :; done; ip -6 route flush table %s 2>/dev/null || true', tid, tid);
            
            ExecSafe(BIN.SH, ['-c', sh_clean_v4], null, trace_id);
            ExecSafe(BIN.SH, ['-c', sh_clean_v6], null, trace_id);
        }
        
        // [Category A] 返回标准化协议对象
        return Success(true, 200, trace_id);
        
    } catch(e) {
        // [Category C] Note: 兜底捕获，防止未知系统层报错引发的链路崩塌
        let err_msg = "" + e;
        log(trace_id, 'CRIT', 'NETWORK', 'Teardown Exception: ' + err_msg);
        return Fail(ERR.E_SYSTEM_BUSY, "Network Teardown Exception: " + err_msg, trace_id);
    }
}

/**
 * [Category B] 物理装配网络规则与虚拟网卡
 * @param {string} trace_id - 贯穿始终的链路 ID
 * [Category C] Note: 已解除外部参数依赖，直接读取本地唯一物理真相源。
 */
function setup(trace_id) {
    try {
        log(trace_id, 'INFO', 'NETWORK', 'Initiating network environment setup...');
        
        // 先清理残留
        teardown(trace_id);

        // [Category A] 核心解耦：自主读取并解析物理 JSON，杜绝上层传参错位
        let raw_json = readfile(PATH.RUN_JSON);
        let run_config = raw_json ? json(raw_json) : null;

        let has_tun = false;
        let has_tproxy = false;
        let tun_config = null;

        // [Category B] 安全提取 inbounds，严密防护空指针异常
        let inbounds = (run_config && type(run_config.inbounds) === 'array') ? run_config.inbounds : [];
        for (let i = 0; i < length(inbounds); i++) {
            let inb = inbounds[i];
            if (inb.type === 'tun') {
                has_tun = true;
                tun_config = inb;
            } else if (inb.type === 'tproxy') {
                has_tproxy = true;
            }
        }

        let u = cursor();
        u.load("flowproxy");
        let ipv6_support = u.get("flowproxy", "config", "ipv6_support") === '1';

        if (has_tproxy) {
            // ⭐ 物理与日志对齐：全部使用 BIN.IP，并注入 trace_id
            ExecSafe(BIN.IP, ['rule', 'add', 'fwmark', sprintf("%d", ROUTE_TABLES.TPROXY), 'table', sprintf("%d", ROUTE_TABLES.TPROXY)], null, trace_id);
            ExecSafe(BIN.IP, ['route', 'add', 'local', '0.0.0.0/0', 'dev', 'lo', 'table', sprintf("%d", ROUTE_TABLES.TPROXY)], null, trace_id);
            
            if (ipv6_support) {
                ExecSafe(BIN.IP, ['-6', 'rule', 'add', 'fwmark', sprintf("%d", ROUTE_TABLES.TPROXY), 'table', sprintf("%d", ROUTE_TABLES.TPROXY)], null, trace_id);
                ExecSafe(BIN.IP, ['-6', 'route', 'add', 'local', '::/0', 'dev', 'lo', 'table', sprintf("%d", ROUTE_TABLES.TPROXY)], null, trace_id);
            }
        }

        if (has_tun && tun_config) {
            let tun_name = tun_config.interface_name || 'singtun0';
            ExecSafe(BIN.IP, ['tuntap', 'add', 'mode', 'tun', 'user', 'root', 'name', tun_name], null, trace_id);
            if (tun_config.mtu) {
                ExecSafe(BIN.IP, ['link', 'set', 'dev', tun_name, 'mtu', sprintf("%d", tun_config.mtu)], null, trace_id);
            }
            
            ExecSafe(BIN.SH, ['-c', 'sleep 0.5'], null, trace_id);
            ExecSafe(BIN.IP, ['link', 'set', tun_name, 'up'], null, trace_id);

            if (tun_config.address && length(tun_config.address) > 0) {
                ExecSafe(BIN.IP, ['addr', 'add', tun_config.address[0], 'dev', tun_name], null, trace_id);
            }
            
            ExecSafe(BIN.IP, ['route', 'replace', 'default', 'dev', tun_name, 'table', sprintf("%d", ROUTE_TABLES.TUN)], null, trace_id);
            ExecSafe(BIN.IP, ['rule', 'add', 'fwmark', sprintf("%d", ROUTE_TABLES.TUN), 'lookup', sprintf("%d", ROUTE_TABLES.TUN)], null, trace_id);

            // 🚨 架构级修复：复刻 HomeProxy 的防火墙绿灯通行证
            // 强行在 nftables 的 forward 和 input 链的最顶端插入 accept 规则，防止局域网流量被 OpenWrt 物理拦截
            ExecSafe(BIN.SH, ['-c', sprintf('nft insert rule inet fw4 forward oifname "%s" counter accept', tun_name)], null, trace_id);
            ExecSafe(BIN.SH, ['-c', sprintf('nft insert rule inet fw4 input iifname "%s" counter accept', tun_name)], null, trace_id);
            // 允许 TUN 网卡自身的流量转发（配合 auto_route）
            ExecSafe(BIN.SH, ['-c', sprintf('nft insert rule inet fw4 forward iifname "%s" counter accept', tun_name)], null, trace_id);
            // 解决可能存在的 MSS / MTU 阻塞导致网页打不开的问题
            ExecSafe(BIN.SH, ['-c', sprintf('nft insert rule inet fw4 forward oifname "%s" tcp flags syn tcp option maxseg size set rt mtu', tun_name)], null, trace_id);

            if (ipv6_support) {
                ExecSafe(BIN.IP, ['-6', 'route', 'replace', 'default', 'dev', tun_name, 'table', sprintf("%d", ROUTE_TABLES.TUN)], null, trace_id);
                ExecSafe(BIN.IP, ['-6', 'rule', 'add', 'fwmark', sprintf("%d", ROUTE_TABLES.TUN), 'lookup', sprintf("%d", ROUTE_TABLES.TUN)], null, trace_id);
            }
        }

        log(trace_id, 'INFO', 'NETWORK', 'Network environment setup completed successfully.');
        return Success(true, 200, trace_id);
        
    } catch(e) {
        // 🚨 遵守铁律 6
        let err_msg = "" + e;
        log(trace_id, 'CRIT', 'NETWORK', 'Setup Exception: ' + err_msg);
        return Fail(ERR.E_SYSTEM_BUSY, "Network Setup Exception: " + err_msg, trace_id);
    }
}

// 🚨 遵守铁律 1: 绝对集中在文件末尾导出
export { setup, teardown };
