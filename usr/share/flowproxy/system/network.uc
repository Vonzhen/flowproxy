/**
 * FlowProxy | system/network.uc | v1.0 TProxy-Redirect Real-World Layer
 * 职责：真实世界 (Reality Layer) 路由、策略路由表与主权防火墙的原子级总装配器。
 * 核心对齐：全面引入独立主权防火墙动态编译与热装载流程， teardon 链具备 100% 物理幂等性。
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

// 3. [跨模块战略会师] 导入全新落成的防火墙动态编译零件
import { build_firewall } from 'flowproxy.system.firewall';

/**
 * 物理卸载所有的策略路由规则、历史残留虚拟网卡与主权防火墙（保证绝对的幂等性）
 * @param {string} trace_id - 贯穿始终的链路 ID
 */
function teardown(trace_id) {
    try {
        log(trace_id, 'INFO', 'NETWORK', 'Executing full cryptographic network teardown...');

        // 1. [主权防火墙清洗] 物理摧毁整表，保证前置拦截无残留
        ExecSafe(BIN.SH, ['-c', 'nft delete table inet flowproxy 2>/dev/null || true'], null, trace_id);

        // 2. [历史迁移安全护航] 幂等清洗旧时代 TUN 残留网卡
        let net_res = ExecSafe(BIN.SH, ['-c', 'ls /sys/class/net/ 2>/dev/null | grep "^singtun"'], null, trace_id);
        if (net_res.ok && net_res.data && net_res.data.stdout) {
            let tun_devices = split(net_res.data.stdout, '\n');
            for (let i = 0; i < length(tun_devices); i++) {
                let dev = trim(tun_devices[i]);
                if (dev && length(dev) > 0) {
                    let safe_dev = shell_escape(dev);
                    ExecSafe(BIN.SH, ['-c', sprintf('ip link set %s down 2>/dev/null || true', safe_dev)], null, trace_id);
                    ExecSafe(BIN.SH, ['-c', sprintf('ip tuntap del mode tun name %s 2>/dev/null || true', safe_dev)], null, trace_id);
                }
            }
        }

        // 3. [策略路由精确清洗] 🚨 拒绝核弹式清理！只删除我们明确打了 mark 的策略规则
        let u = cursor();
        u.load("flowproxy");
        let tproxy_mark = u.get("flowproxy", "infra", "tproxy_mark") || "101";
        let tun_mark = u.get("flowproxy", "infra", "tun_mark") || "102";
        let self_mark = u.get("flowproxy", "infra", "self_mark") || "100";
        
        let marks = [tproxy_mark, tun_mark, self_mark];
        for (let i = 0; i < length(marks); i++) {
            let m = marks[i];
            // 🚨 架构修复：严格使用 fwmark <ID> 匹配删除，绝不误伤 mwan3 或 sqm 等同表友军！
            let sh_clean_v4 = sprintf('while ip rule del fwmark %s table %s 2>/dev/null; do :; done; ip route flush table %s 2>/dev/null || true', m, m, m);
            let sh_clean_v6 = sprintf('while ip -6 rule del fwmark %s table %s 2>/dev/null; do :; done; ip -6 route flush table %s 2>/dev/null || true', m, m, m);
            
            ExecSafe(BIN.SH, ['-c', sh_clean_v4], null, trace_id);
            ExecSafe(BIN.SH, ['-c', sh_clean_v6], null, trace_id);
        }

        // 4. [深度 GC (Garbage Collection)] 🚨 清剿幽灵残留，恢复纯净物理态
        log(trace_id, 'INFO', 'NETWORK', 'Executing depth GC: Purging orphaned sockets and states...');
        // 强杀可能游离的孤儿进程 (procd 托管外的幽灵)
        ExecSafe(BIN.SH, ['-c', 'killall -9 sing-box 2>/dev/null || true'], null, trace_id);
        // 清理所有遗留的 UNIX Socket 与运行状态残骸
        ExecSafe(BIN.SH, ['-c', 'rm -f /var/run/flowproxy/*.socket /var/run/flowproxy/*.sock /var/run/flowproxy/*.state 2>/dev/null || true'], null, trace_id);
        
        return Success(true, 200, trace_id);
        
    } catch(e) {
        let err_msg = "" + e;
        log(trace_id, 'CRIT', 'NETWORK', 'Teardown Exception: ' + err_msg);
        return Fail(ERR.E_SYSTEM_BUSY, "Network Teardown Exception: " + err_msg, trace_id);
    }
}

/**
 * 物理装配 TProxy 策略路由链路并热装载全新主权防火墙
 * @param {string} trace_id - 贯穿始终的链路 ID
 */
function setup(trace_id) {
    try {
        log(trace_id, 'INFO', 'NETWORK', 'Initiating high-performance TProxy network environment setup...');
        
        // 1. 彻底清空旧战场，防止规则交叉污染
        teardown(trace_id);

        // 2. 读取物理 JSON 真相源，严防传参篡改
        let raw_json = readfile(PATH.RUN_JSON);
        let run_config = raw_json ? json(raw_json) : null;

        let has_tproxy = false;
        let inbounds = (run_config && type(run_config.inbounds) === 'array') ? run_config.inbounds : [];
        for (let i = 0; i < length(inbounds); i++) {
            if (inbounds[i].type === 'tproxy') {
                has_tproxy = true;
                break;
            }
        }

        let u = cursor();
        u.load("flowproxy");
        let ipv6_support = u.get("flowproxy", "config", "ipv6_support") === '1';
        let tproxy_mark = u.get("flowproxy", "infra", "tproxy_mark") || "101";

        // 3. 策略路由铺路：原子装配 UDP TProxy 本地环回策略路由表
        if (has_tproxy) {
            log(trace_id, 'INFO', 'NETWORK', 'Assembling Linux policy routing for UDP TProxy...');
            
            let res;
            let t_mark = tproxy_mark; 
            
            // [诊断式重构]：使用 sh -c 并捕获真实报错 (2>&1)，彻底查清底层为何拒绝执行
            
            // IPv4 策略路由注入
            ExecSafe(BIN.SH, ['-c', sprintf("ip rule del fwmark %s table %s 2>/dev/null", t_mark, t_mark)], null, trace_id); // 静默清理残留
            let cmd_rule_v4 = sprintf("ip rule add fwmark %s table %s 2>&1", t_mark, t_mark);
            res = ExecSafe(BIN.SH, ['-c', cmd_rule_v4], null, trace_id);
            if (!res.ok || (res.data && index(res.data.stdout || "", "RTNETLINK") !== -1)) {
                let err_msg = (res.data && res.data.stdout) ? res.data.stdout : (res.detail || "Unknown shell error");
                log(trace_id, 'CRIT', 'NETWORK', 'IPv4 ip rule setup failed. RAW ERROR: ' + err_msg);
                teardown(trace_id);
                return Fail(ERR.E_SYSTEM_BUSY, "IPv4 ip rule error: " + err_msg, trace_id);
            }
            
            ExecSafe(BIN.SH, ['-c', sprintf("ip route flush table %s 2>/dev/null", t_mark)], null, trace_id);
            let cmd_route_v4 = sprintf("ip route add local 0.0.0.0/0 dev lo table %s 2>&1", t_mark);
            res = ExecSafe(BIN.SH, ['-c', cmd_route_v4], null, trace_id);
            if (!res.ok || (res.data && index(res.data.stdout || "", "RTNETLINK") !== -1)) {
                let err_msg = (res.data && res.data.stdout) ? res.data.stdout : (res.detail || "Unknown shell error");
                log(trace_id, 'CRIT', 'NETWORK', 'IPv4 ip route setup failed. RAW ERROR: ' + err_msg);
                teardown(trace_id);
                return Fail(ERR.E_SYSTEM_BUSY, "IPv4 ip route error: " + err_msg, trace_id);
            }
            
            // IPv6 策略路由注入
            if (ipv6_support) {
                ExecSafe(BIN.SH, ['-c', sprintf("ip -6 rule del fwmark %s table %s 2>/dev/null", t_mark, t_mark)], null, trace_id);
                let cmd_rule_v6 = sprintf("ip -6 rule add fwmark %s table %s 2>&1", t_mark, t_mark);
                res = ExecSafe(BIN.SH, ['-c', cmd_rule_v6], null, trace_id);
                if (!res.ok || (res.data && index(res.data.stdout || "", "RTNETLINK") !== -1)) {
                    let err_msg = (res.data && res.data.stdout) ? res.data.stdout : (res.detail || "Unknown shell error");
                    log(trace_id, 'CRIT', 'NETWORK', 'IPv6 ip rule setup failed. RAW ERROR: ' + err_msg);
                    teardown(trace_id);
                    return Fail(ERR.E_SYSTEM_BUSY, "IPv6 ip rule error: " + err_msg, trace_id);
                }

                ExecSafe(BIN.SH, ['-c', sprintf("ip -6 route flush table %s 2>/dev/null", t_mark)], null, trace_id);
                let cmd_route_v6 = sprintf("ip -6 route add local ::/0 dev lo table %s 2>&1", t_mark);
                res = ExecSafe(BIN.SH, ['-c', cmd_route_v6], null, trace_id);
                if (!res.ok || (res.data && index(res.data.stdout || "", "RTNETLINK") !== -1)) {
                    let err_msg = (res.data && res.data.stdout) ? res.data.stdout : (res.detail || "Unknown shell error");
                    log(trace_id, 'CRIT', 'NETWORK', 'IPv6 ip route setup failed. RAW ERROR: ' + err_msg);
                    teardown(trace_id);
                    return Fail(ERR.E_SYSTEM_BUSY, "IPv6 ip route error: " + err_msg, trace_id);
                }
            }
        }

        // 4. 🔥 战役决胜点：跨模块调用防火墙零件，在内存盘动态编译出最新 .nft 图纸
        let fw_compile_res = build_firewall(trace_id);
        if (!fw_compile_res.ok) {
            log(trace_id, 'CRIT', 'NETWORK', 'Firewall compilation pipe broken. Aborting kernel injection.');
            // 🚨 新增：即使是编译失败，也要执行 teardown 扫尾，把前面步骤 3 可能已经装好的 ip rule 清掉
            teardown(trace_id);
            return fw_compile_res; 
        }

        // 5. 🔥 终极合围：将编译完毕的独立主权防火墙一次性原子级灌入 Linux 内核
        log(trace_id, 'INFO', 'NETWORK', 'Injecting compiled sovereign ruleset into nftables kernel space...');
        let nft_load_res = ExecSafe(BIN.NFT, ['-f', PATH.FIREWALL_NFT], null, trace_id);
        
        if (!nft_load_res.ok) {
            let nft_err = nft_load_res.detail || 'Unknown nftables syntax fault';
            log(trace_id, 'CRIT', 'NETWORK', 'Kernel injection rejected by nftables: ' + nft_err);
            
            // 容错降级安全回滚：注入失败时，立刻执行物理清洗，防止内核残留半挂起状态的畸形规则
            teardown(trace_id);
            return Fail(ERR.E_SYSTEM_BUSY, "Nftables Kernel Injection Failed: " + nft_err, trace_id);
        }

        log(trace_id, 'INFO', 'NETWORK', 'Network routing and firewall environment setup completed successfully.');
        return Success(true, 200, trace_id);
        
    } catch(e) {
        // 🚨 遵守铁律 6：隐式异常安全拦截
        let err_msg = "" + e;
        log(trace_id, 'CRIT', 'NETWORK', 'Setup Exception: ' + err_msg);
        return Fail(ERR.E_SYSTEM_BUSY, "Network Setup Exception: " + err_msg, trace_id);
    }
}

// 🚨 遵守铁律 1: 绝对集中在文件末尾统一导出，捍卫零件主权
export { setup, teardown };
