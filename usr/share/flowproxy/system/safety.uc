/**
 * FlowProxy | system/safety.uc | v1.0
 * 职责：极端情况下物理抹除 Nftables/IP Rule 规则及清理残留，恢复系统纯净网络。
 * 环境适配：冷启动时序容忍。避免向不存在的链注入规则。
 */

'use strict';

// 1. [解构原生库] 遵守铁律 5
import { stat } from 'fs';
import { cursor } from 'uci';

// 2. [引入基石法则] 遵守铁律 3
import { PATH, BIN } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { ExecSafe, shell_escape } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';

const ROUTE_TABLES = [100, 101, 102];

// 固件特定的高度定制临时路径，暂保留硬编码常量形式
const DNSMASQ_CONF_DIR = '/tmp/dnsmasq.d/dnsmasq-flowproxy.d';
const DNSMASQ_INC_FILE = '/tmp/dnsmasq.d/dnsmasq-flowproxy.conf';

const NFT_HP_CHAINS = [
    "flowproxy_dstnat_redir", "flowproxy_output_redir", "flowproxy_redirect",
    "flowproxy_mangle_prerouting", "flowproxy_mangle_output", "flowproxy_mangle_lanac"
];

/**
 * 注入紧急放行规则（Bypass）
 * @param {string} trace_id - 贯穿始终的链路 ID
 */
function inject_bypass(trace_id) {
    try {
        log(trace_id, 'INFO', 'SAFETY', 'Injecting network bypass rules...');
        
        // 🚨 宪法修正：冷启动探测。如果目标链根本不存在，直接静默退出，不报无用警告。
        let probe_res = ExecSafe(BIN.SH, ["-c", "nft list chain inet fw4 flowproxy_redirect_lanac >/dev/null 2>&1"], null, trace_id);
        if (!probe_res.ok) {
            log(trace_id, 'INFO', 'SAFETY', 'Bypass target chain missing (likely cold start). Injection skipped.');
            return Success(true, 200, trace_id);
        }

        let u = cursor();
        u.load("flowproxy");
        let safe_ports = u.get("flowproxy", "infra", "safe_ports") || '22, 80, 443';

        let rules = [
            sprintf("nft insert rule inet fw4 flowproxy_redirect_lanac tcp dport { %s } counter return", safe_ports),
            sprintf("nft insert rule inet fw4 flowproxy_mangle_lanac udp dport { %s } counter return", safe_ports)
        ];
        
        let has_err = false;
        for (let i = 0; i < length(rules); i++) {
            let res = ExecSafe(BIN.SH, ["-c", rules[i]], null, trace_id);
            if (!res.ok) has_err = true;
        }

        if (has_err) {
            log(trace_id, 'WARN', 'SAFETY', 'Failed to inject one or more bypass rules.');
            return Fail(ERR.E_SYSTEM_BUSY, "Failed to inject one or more bypass rules", trace_id);
        }
        
        return Success(true, 200, trace_id);
        
    } catch(e) {
        let err_msg = "" + e;
        log(trace_id, 'CRIT', 'SAFETY', 'Bypass Injection Exception: ' + err_msg);
        return Fail(ERR.E_SYSTEM_BUSY, "Bypass Injection Exception: " + err_msg, trace_id);
    }
}

/**
 * 执行灾难回滚，抹除所有代理拦截
 * @param {string} trace_id - 贯穿始终的链路 ID
 */
function execute_fallback(trace_id) {
    try {
        log(trace_id, 'INFO', 'SAFETY', 'Executing physical fallback (Network Panic Button)...');
        
        let success = true;
        let dns_dirty = false;
        
        if (stat(DNSMASQ_CONF_DIR)) { 
            success = success && ExecSafe(BIN.RM, ["-rf", DNSMASQ_CONF_DIR], null, trace_id).ok; 
            dns_dirty = true; 
        }
        if (stat(DNSMASQ_INC_FILE)) { 
            success = success && ExecSafe(BIN.RM, ["-f", DNSMASQ_INC_FILE], null, trace_id).ok; 
            dns_dirty = true; 
        }
        if (dns_dirty) {
            success = success && ExecSafe(BIN.SH, ["-c", "/etc/init.d/dnsmasq restart"], null, trace_id).ok;
        }

        for (let i = 0; i < length(ROUTE_TABLES); i++) {
            let table = sprintf("%d", ROUTE_TABLES[i]);
            ExecSafe(BIN.IP, ["rule", "del", "table", table], null, trace_id);
            ExecSafe(BIN.IP, ["route", "flush", "table", table], null, trace_id);
        }
        
        for (let j = 0; j < length(NFT_HP_CHAINS); j++) {
            ExecSafe(BIN.NFT, ["flush", "chain", "inet", "fw4", NFT_HP_CHAINS[j]], null, trace_id);
            ExecSafe(BIN.NFT, ["delete", "chain", "inet", "fw4", NFT_HP_CHAINS[j]], null, trace_id);
        }
        
        success = success && ExecSafe(BIN.SH, ["-c", "fw4 reload"], null, trace_id).ok;

        let u = cursor();
        u.load("flowproxy");
        let tun_name = u.get("flowproxy", "infra", "tun_name") || 'singtun0';

        ExecSafe(BIN.IP, ["link", "set", tun_name, "down"], null, trace_id);
        ExecSafe(BIN.IP, ["tuntap", "del", "mode", "tun", "name", tun_name], null, trace_id);
        
        if (!success) {
            log(trace_id, 'WARN', 'SAFETY', 'Partial failure during physical fallback execution.');
            return Fail(ERR.E_SYSTEM_BUSY, "Partial failure during physical fallback execution", trace_id);
        }
        
        log(trace_id, 'INFO', 'SAFETY', 'Fallback execution completed successfully. Network reverted.');
        return Success(true, 200, trace_id);
        
    } catch(e) {
        let err_msg = "" + e;
        log(trace_id, 'CRIT', 'SAFETY', 'Fallback Execution Exception: ' + err_msg);
        return Fail(ERR.E_SYSTEM_BUSY, "Fallback Execution Exception: " + err_msg, trace_id);
    }
}

// 🚨 遵守铁律 1: 绝对集中在文件末尾导出
export { inject_bypass, execute_fallback };
