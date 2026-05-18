/**
 * FlowProxy | runtime/healthcheck.uc | v1.5 Watchdog Edition
 * 分级健康探针与状态收敛守护引擎 (SSOT Aligned Edition)
 * 职责：
 * - L1 (进程存活) 与 L2 (出站通达) 探针
 * - H1 (内核数据面) 状态漂移监测
 * - 具备 Fail Loop Backoff (退避防熔断) 的 Watchdog 自愈机制
 */

'use strict';

// 🚨 铁律 5: 解构导入
import { cursor } from 'uci';
import { readfile, writefile } from 'fs';

// 🚨 铁律 3: 绝对命名空间寻址
import { PATH, BIN } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { ExecSafe } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';

// 引入模块用于灾难告警
import { send_telegram } from 'flowproxy.modules.notifier';

const PROBE_URL = "http://cp.cloudflare.com/generate_204";
const PROBE_TIMEOUT_SEC = 3;
const MAX_FAIL_COUNT = 3;
const FAIL_COUNT_FILE = "/tmp/flowproxy.fail_count";

const HealthCheck = {
    /**
     * H1 探针：检查内核态数据面 (Data Plane) 是否存在漂移
     * @param {string} trace_id 
     */
    verify_kernel: function(trace_id) {
        log(trace_id, "INFO", "HEALTH", "Starting H1 Kernel Data Plane verification...");
        
        let nft_check = ExecSafe(BIN.SH, ["-c", "nft list table inet flowproxy"], null, trace_id);
        if (!nft_check.ok || !nft_check.data.stdout) {
            log(trace_id, "CRIT", "HEALTH", "H1 Check FAILED: nft table 'inet flowproxy' is missing.");
            return false;
        }

        // 🚨 架构修复：仅将 nftables 视为 H1 真相源。不再强制要求 ip rule 存在，兼容各种轻量级路由模式。
        log(trace_id, "INFO", "HEALTH", "H1 Check PASSED: Kernel Data Plane (nftables) is intact.");
        return true;
    },

    /**
     * L1/L2 探针：进程存活与出站通达性检查
     */
    verify_connection: function(trace_id, max_retries) {
        try {
            if (!max_retries) max_retries = 3;

            let u = cursor();
            u.load("flowproxy");
            let proxy_port = u.get("flowproxy", "infra", "mixed_port") || 5330;

            log(trace_id, "INFO", "HEALTH", "Cold start buffer: sleeping 3 seconds...");
            ExecSafe(BIN.SH, ["-c", "sleep 3"], null, trace_id);

            // ==========================================
            // L1 探针：进程存活与端口监听检查
            // ==========================================
            log(trace_id, "INFO", "HEALTH", sprintf("Starting L1 local survival check on port %s...", proxy_port));
            let l1_passed = false;
            
            for (let i = 1; i <= 3; i++) {
                let l1_res = ExecSafe(BIN.CURL, ["-s", "-m", "2", sprintf("http://127.0.0.1:%s", proxy_port)], null, trace_id);
                let is_refused = (!l1_res.ok && index(l1_res.detail, "code 7") >= 0);
                
                if (!is_refused) { 
                    l1_passed = true;
                    break;
                }
                ExecSafe(BIN.SH, ["-c", "sleep 1"], null, trace_id);
            }

            if (!l1_passed) {
                log(trace_id, "ERROR", "HEALTH", "L1 Check FAILED: Proxy port is not listening.");
                return Success({ l1_valid: false, l2_valid: false, error: "L1 Local Port Dead" }, 200, trace_id);
            }

            // ==========================================
            // L2 探针：出站节点网络通达性检查
            // ==========================================
            let l2_passed = false;
            let latency_ms = 0;

            for (let i = 1; i <= max_retries; i++) {
                let args = [
                    "-s", "-o", "/dev/null", "-w", "%{http_code}:%{time_total}",
                    "-m", sprintf("%d", PROBE_TIMEOUT_SEC),
                    "-x", sprintf("socks5h://127.0.0.1:%s", proxy_port),
                    PROBE_URL
                ];

                let res = ExecSafe(BIN.CURL, args, null, trace_id);
                let output = (res.ok && res.data) ? res.data.stdout : "";

                if (res.ok && output) {
                    let parts = split(output, ":");
                    if (parts[0] === "204" || parts[0] === "200") {
                        latency_ms = int(parts[1] * 1000);
                        l2_passed = true;
                        break;
                    }
                }
                ExecSafe(BIN.SH, ["-c", "sleep 2"], null, trace_id);
            }

            return Success({ l1_valid: true, l2_valid: l2_passed, latency: latency_ms }, 200, trace_id);
            
        } catch(e) {
            let err_str = "" + e;
            return Fail(ERR.E_SYSTEM_BUSY, "HealthCheck Exception: " + err_str, trace_id);
        }
    },

    /**
     * 自愈守护引擎 (Watchdog)：由 Cron 周期性调用
     * 具备状态漂移修复与失败退避 (Fail Loop Backoff) 能力
     */
    watchdog: function(trace_id) {
        log(trace_id, "INFO", "HEALTH", "Watchdog routine started.");

        let u = cursor();
        u.load("flowproxy");
        if (u.get("flowproxy", "routing", "default_outbound") === 'disabled') {
            log(trace_id, "INFO", "HEALTH", "System is disabled by user intent. Watchdog sleeping.");
            return Success(true, 200, trace_id);
        }

        // 1. 读取当前失败计数
        let current_fails = 0;
        let fail_content = readfile(FAIL_COUNT_FILE);
        if (fail_content) current_fails = int(trim(fail_content)) || 0;

        // 2. 退避机制拦截 (FAILED_SAFE_MODE)
        if (current_fails >= MAX_FAIL_COUNT) {
            log(trace_id, "CRIT", "HEALTH", "WATCHDOG SUSPENDED: MAX_FAIL_COUNT reached. System is in FAILED_SAFE_MODE.");
            return Fail(ERR.E_SYSTEM_BUSY, "System is in FAILED_SAFE_MODE. Manual intervention required.", trace_id);
        }

        // 3. 组合检查：H1(内核层) + L1(进程层)
        let is_kernel_ok = this.verify_kernel(trace_id);
        
        let conn_res = this.verify_connection(trace_id, 1); // Watchdog 下 L2 只探测 1 次节约资源
        let is_process_ok = (conn_res.ok && conn_res.data && conn_res.data.l1_valid === true);

        // 4. 判定是否发生状态漂移
        if (is_kernel_ok && is_process_ok) {
            if (current_fails > 0) {
                log(trace_id, "INFO", "HEALTH", "System recovered. Clearing fail counters.");
                ExecSafe(BIN.SH, ["-c", sprintf("rm -f %s", FAIL_COUNT_FILE)], null, trace_id);
            }
            log(trace_id, "INFO", "HEALTH", "Watchdog routine complete. System is HEALTHY.");
            return Success(true, 200, trace_id);
        }

        // ==========================================
        // 🚨 触发自愈与退避计数
        // ==========================================
        current_fails++;
        writefile(FAIL_COUNT_FILE, sprintf("%d", current_fails));
        log(trace_id, "WARN", "HEALTH", sprintf("State drift detected! Attempting repair... (Fail Count: %d/%d)", current_fails, MAX_FAIL_COUNT));

        if (current_fails >= MAX_FAIL_COUNT) {
            // ==========================================
            // 🚨 FAILED_SAFE_MODE (熔断模式)
            // ==========================================
            log(trace_id, "CRIT", "HEALTH", "REPAIR LOOP FAILED. ENTERING FAILED_SAFE_MODE.");
            
            // 物理卸载，恢复全家直连畅通
            let td_cmd = sprintf("ucode -S %s/system/network.uc teardown", PATH.BASE);
            ExecSafe(BIN.SH, ["-c", td_cmd], null, trace_id);
            
            // 停用失控进程
            let stop_cmd = sprintf("%s stop", PATH.INIT);
            ExecSafe(BIN.SH, ["-c", stop_cmd], null, trace_id);

            // 发送绝命告警
            let alert_msg = "🚨 <b>系统状态漂移严重，已进入熔断保护模式！</b>%0A" +
                            "━━━━━━━━━━━━━━━━━━%0A" +
                            "诊断：Watchdog 连续修复 " + MAX_FAIL_COUNT + " 次失败。%0A" +
                            "动作：已强制停机并放行所有直连流量。%0A" +
                            "请登录 OpenWrt 检查底层环境与日志！";
            send_telegram("watchdog_panic", "fail", alert_msg, trace_id);

            return Fail(ERR.E_SYSTEM_BUSY, "Entered FAILED_SAFE_MODE due to repeated repair failures.", trace_id);
        }

        // ==========================================
        // 尝试自动修复 (执行重载事务)
        // ==========================================
        let repair_cmd = sprintf("ubus call flowproxy.job start '{\"type\":\"apply_config\"}'");
        ExecSafe(BIN.SH, ["-c", repair_cmd], null, trace_id);

        return Success({ repairing: true }, 200, trace_id);
    }
};

// 🚨 铁律 1
export { HealthCheck };
