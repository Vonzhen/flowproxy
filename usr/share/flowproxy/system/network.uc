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

const ROUTE_TABLES = {
    SELF: 100,
    TPROXY: 101, // UDP TProxy 专属策略路由表
    TUN: 102     // 历史残留清洗靶向
};

/**
 * 物理卸载所有的策略路由规则、历史残留虚拟网卡与主权防火墙（保证绝对的幂等性）
 * @param {string} trace_id - 贯穿始终的链路 ID
 */
function teardown(trace_id) {
    try {
        log(trace_id, 'INFO', 'NETWORK', 'Executing full cryptographic network teardown...');

        // [维度一：主权防火墙清洗] 
        // 🚨 架构极致优雅体现：由于使用了独立主权 table，只需整表物理摧毁，一秒钟断掉所有前置拦截，绝无残留
        log(trace_id, 'INFO', 'NETWORK', 'Purging independent sovereign firewall table...');
        ExecSafe(BIN.SH, ['-c', 'nft delete table inet flowproxy 2>/dev/null || true'], null, trace_id);

        // [维度二：历史迁移安全护航] 若系统存在旧时代 TUN 残留网卡，在此处执行幂等清洗
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

        // [维度三：策略路由全量清洗] 将 SELF, TPROXY, TUN 相关的游离态规则与路由表彻底物理拔除
        let tables = [ROUTE_TABLES.SELF, ROUTE_TABLES.TPROXY, ROUTE_TABLES.TUN];
        for (let i = 0; i < length(tables); i++) {
            let tid = sprintf("%d", tables[i]);
            
            // 核心安全策略：使用 while 循环彻底清空可能由于多次异常重启叠加的同名规则
            let sh_clean_v4 = sprintf('while ip rule del table %s 2>/dev/null; do :; done; ip route flush table %s 2>/dev/null || true', tid, tid);
            let sh_clean_v6 = sprintf('while ip -6 rule del table %s 2>/dev/null; do :; done; ip -6 route flush table %s 2>/dev/null || true', tid, tid);
            
            ExecSafe(BIN.SH, ['-c', sh_clean_v4], null, trace_id);
            ExecSafe(BIN.SH, ['-c', sh_clean_v6], null, trace_id);
        }
        
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

        // 3. 策略路由铺路：原子装配 UDP TProxy 本地环回策略路由表 (Table 101)
        if (has_tproxy) {
            log(trace_id, 'INFO', 'NETWORK', 'Assembling Linux policy routing for UDP TProxy (Table 101)...');
            
            // IPv4 策略路由注入
            ExecSafe(BIN.IP, ['rule', 'add', 'fwmark', sprintf("%d", ROUTE_TABLES.TPROXY), 'table', sprintf("%d", ROUTE_TABLES.TPROXY)], null, trace_id);
            ExecSafe(BIN.IP, ['route', 'add', 'local', '0.0.0.0/0', 'dev', 'lo', 'table', sprintf("%d", ROUTE_TABLES.TPROXY)], null, trace_id);
            
            // IPv6 策略路由注入
            if (ipv6_support) {
                ExecSafe(BIN.IP, ['-6', 'rule', 'add', 'fwmark', sprintf("%d", ROUTE_TABLES.TPROXY), 'table', sprintf("%d", ROUTE_TABLES.TPROXY)], null, trace_id);
                ExecSafe(BIN.IP, ['-6', 'route', 'add', 'local', '::/0', 'dev', 'lo', 'table', sprintf("%d", ROUTE_TABLES.TPROXY)], null, trace_id);
            }
        }

        // 4. 🔥 战役决胜点：跨模块调用防火墙零件，在内存盘动态编译出最新 .nft 图纸
        let fw_compile_res = build_firewall(trace_id);
        if (!fw_compile_res.ok) {
            log(trace_id, 'CRIT', 'NETWORK', 'Firewall compilation pipe broken. Aborting kernel injection.');
            return fw_compile_res; // 阻断式异常熔断，回传 Fail 协议
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
