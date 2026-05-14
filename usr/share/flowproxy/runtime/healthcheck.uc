/**
 * FlowProxy | runtime/healthcheck.uc | v1.0
 * 分级健康探针 (SSOT Aligned Edition)
 * 职责：L1(进程存活) 与 L2(出站通达) 分级健康检查。
 * 核心对齐：全量接入 Result 协议，摧毁硬编码路径，透传 trace_id。
 */

'use strict';

// 🚨 铁律 5: 解构导入
import { cursor } from 'uci'; 

// 🚨 铁律 3: 绝对命名空间寻址
import { PATH, BIN } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { ExecSafe } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';

const PROBE_URL = "http://cp.cloudflare.com/generate_204";
const PROBE_TIMEOUT_SEC = 3;

const HealthCheck = {
    /**
     * @param {string} trace_id - 贯穿链路的 ID (通常也是 job_id)
     * @param {number} max_retries - 最大重试次数
     */
    verify_connection: function(trace_id, max_retries) {
        try {
            if (!max_retries) max_retries = 3;

            let u = cursor();
            u.load("flowproxy");
            let proxy_port = u.get("flowproxy", "infra", "mixed_port") || 5330;

            log(trace_id, "INFO", "HEALTH", "Cold start buffer: sleeping 3 seconds...");
            // ⭐ 协议对齐：透传 trace_id 给沙箱
            ExecSafe(BIN.SH, ["-c", "sleep 3"], null, trace_id);

            // ==========================================
            // ⭐ L1 探针：进程存活与端口监听检查 (核心防线)
            // ==========================================
            log(trace_id, "INFO", "HEALTH", sprintf("Starting L1 local survival check on port %s...", proxy_port));
            let l1_passed = false;
            
            for (let i = 1; i <= 3; i++) {
                // ⭐ 协议对齐：透传 trace_id
                let l1_res = ExecSafe(BIN.CURL, ["-s", "-m", "2", sprintf("http://127.0.0.1:%s", proxy_port)], null, trace_id);
                
                // 逻辑无损还原：只要不是 curl code 7 (Failed to connect)，就算作存活响应
                let is_refused = (!l1_res.ok && index(l1_res.detail, "code 7") >= 0);
                
                if (!is_refused) { 
                    l1_passed = true;
                    break;
                }
                ExecSafe(BIN.SH, ["-c", "sleep 1"], null, trace_id);
            }

            if (!l1_passed) {
                log(trace_id, "ERROR", "HEALTH", "L1 Check FAILED: Proxy port is not listening. Process dead.");
                // ⭐ 协议对齐：返回标准 Success 包装，携带 code 和 trace_id
                return Success({ l1_valid: false, l2_valid: false, error: "L1 Local Port Dead" }, 200, trace_id);
            }
            log(trace_id, "INFO", "HEALTH", "L1 Check PASSED: Proxy process is alive and listening.");

            // ==========================================
            // ⭐ L2 探针：出站节点网络通达性检查 (弱依赖)
            // ==========================================
            log(trace_id, "INFO", "HEALTH", "Starting L2 outbound connectivity check...");
            let l2_passed = false;
            let latency_ms = 0;

            for (let i = 1; i <= max_retries; i++) {
                let args = [
                    "-s", "-o", "/dev/null",
                    "-w", "%{http_code}:%{time_total}",
                    "-m", sprintf("%d", PROBE_TIMEOUT_SEC),
                    "-x", sprintf("socks5h://127.0.0.1:%s", proxy_port),
                    PROBE_URL
                ];

                // ⭐ 协议对齐：透传 trace_id
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

                log(trace_id, "WARN", "HEALTH", sprintf("L2 Probe attempt %d failed. Output: %s", i, output || "Timeout/Refused"));
                ExecSafe(BIN.SH, ["-c", "sleep 2"], null, trace_id);
            }

            if (l2_passed) {
                log(trace_id, "INFO", "HEALTH", sprintf("L2 Check PASSED. Latency: %d ms", latency_ms));
            } else {
                log(trace_id, "WARN", "HEALTH", "L2 Check FAILED: Outbound restricted, but bypass rollback.");
            }

            // ⭐ 协议对齐：成功执行探针
            return Success({ l1_valid: true, l2_valid: l2_passed, latency: latency_ms }, 200, trace_id);
            
        } catch(e) {
            // 🚨 铁律 6
            let err_str = "" + e;
            return Fail(ERR.E_SYSTEM_BUSY, "HealthCheck Exception: " + err_str, trace_id);
        }
    }
};

// 🚨 铁律 1
export { HealthCheck };
