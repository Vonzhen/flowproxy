/**
 * FlowProxy | runtime/healthcheck.uc | v1.0
 * 职责：纯只读的运行态物理存活性巡检 (Read-Only Runtime Verifier)
 * 边界：绝不包含修复 (repair)、回滚 (rollback) 或状态决策逻辑。
 */

'use strict';

import { cursor } from 'uci';
import { BIN } from 'flowproxy.core.constants';
import { ExecSafe } from 'flowproxy.core.utils';

// ==========================================
// 原子化探针 (Atomic Probes)
// ==========================================

function verify_pid() {
    // 检查 procd 托管的 sing-box 进程是否存在
    let res = ExecSafe(BIN.SH, ["-c", "pgrep -f 'sing-box.*flowproxy' > /dev/null 2>&1"]);
    return res.ok;
}

function verify_listen(proxy_port) {
    // 检查 mixed_port 是否响应 (拒绝连接返回 code 7)
    let res = ExecSafe(BIN.CURL, ["-s", "-m", "2", sprintf("http://127.0.0.1:%s", proxy_port)]);
    let is_refused = (!res.ok && index(res.detail || "", "code 7") >= 0);
    return !is_refused;
}

function verify_nft() {
    // 检查独立主权防火墙表是否存在
    let res = ExecSafe(BIN.SH, ["-c", "nft list table inet flowproxy > /dev/null 2>&1"]);
    return res.ok;
}

function verify_iprule(mark) {
    // 检查 TProxy 策略路由规则是否存在
    let res = ExecSafe(BIN.SH, ["-c", sprintf("ip rule show | grep -q 'lookup %s'", mark)]);
    return res.ok;
}

function verify_route(mark) {
    // 检查 TProxy 本地路由表是否下发
    let res = ExecSafe(BIN.SH, ["-c", sprintf("ip route show table %s | grep -q 'local'", mark)]);
    return res.ok;
}

// ==========================================
// 主巡检入口 (Main Verifier)
// ==========================================

const HealthCheck = {
    /**
     * 执行全量物理检查，返回严格的 { ok: boolean, failed: string[] } 契约
     */
    verify: function() {
        let u = cursor();
        u.load("flowproxy");
        
        // 提取需校验的特征参数
        let tproxy_mark = u.get("flowproxy", "infra", "tproxy_mark") || "101";
        let proxy_port = u.get("flowproxy", "infra", "mixed_port") || "5330";
        
        let failed_components = [];

        // 1. 进程层检查
        if (!verify_pid()) push(failed_components, "pid");
        if (!verify_listen(proxy_port)) push(failed_components, "listen");

        // 2. 内核数据面检查
        if (!verify_nft()) push(failed_components, "nft");
        if (!verify_iprule(tproxy_mark)) push(failed_components, "iprule");
        if (!verify_route(tproxy_mark)) push(failed_components, "route");

        // 3. 严格输出诊断结果 (不带任何主动行为)
        return {
            ok: (length(failed_components) === 0),
            failed: failed_components
        };
    }
};

export { HealthCheck };
