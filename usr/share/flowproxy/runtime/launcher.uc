/**
 * FlowProxy | runtime/launcher.uc | v1.2 (Sandbox Edition)
 * 职责：只读的内核配置离线校验器 (Sandbox Validator)
 * 边界：剥夺了启停控制权，专职负责在配置应用前使用 sing-box check 进行离线安检。
 */

'use strict';

import { stat } from 'fs';
import { PATH, BIN } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { ExecSafe } from 'flowproxy.core.utils';
import { HealthCheck, dataplane_verify, lifecycle_error_detail } from 'flowproxy.runtime.healthcheck';

function _validate_path(path) {
    if (type(path) !== 'string') return false;
    let runtime_dir = PATH.RUNTIME;
    if (substr(path, 0, length(runtime_dir)) !== runtime_dir) return false;
    if (index(path, '../') >= 0 || index(path, '..\\') >= 0) return false;
    if (!match(path, regexp('\\.json$'))) return false;
    return true;
}

/**
 * 校验配置文件合法性 (由 worker.uc 在事务准备阶段调用)
 */
function check(config_path, ctx, trace_id) {
    try {
        if (!ctx || ctx.caller !== 'runtime.manager') {
            return Fail(ERR.E_AUTH_DENIED, "Caller Unauthorized", trace_id);
        }

        if (!_validate_path(config_path)) {
            return Fail(ERR.E_SYSTEM_BUSY, "Security Violation: Illegal config path", trace_id);
        }

        if (!stat(BIN.SINGBOX)) {
            return Fail(ERR.E_ENV_MISSING, "Binary Missing: sing-box not found", trace_id);
        }

        // 调用内核命令进行离线预检，绝不启动进程
        let res = ExecSafe(BIN.SINGBOX, ["check", "-c", config_path], { timeout: 10 }, trace_id);
        
        if (res.ok) {
            return Success(res.data, 200, trace_id);
        }
        return Fail(ERR.E_CONFIG_FAULT, res.detail, trace_id);

    } catch(e) {
        let err_str = "" + e;
        return Fail(ERR.E_SYSTEM_BUSY, "Launcher Check Exception: " + err_str, trace_id);
    }
}

/**
 * reload/restart 后数据面验收（唯一入口：等待落盘 → 统一 dataplane_verify）
 */
function _recoverable_dataplane_gap(dp) {
    if (!dp) return true;
    if (dp.process_ok === false) return false;
    if (dp.route_ok === false || dp.nft_ok === false || dp.tun_ok === false) return true;
    return false;
}

function verify_after_reload(trace_id, opts) {
    opts = opts || {};
    let min_settle_sec = opts.min_settle_sec != null ? int(opts.min_settle_sec) : 8;
    let timeout_sec = opts.timeout_sec != null ? int(opts.timeout_sec) : 75;
    let stable_samples = opts.stable_samples != null ? int(opts.stable_samples) : 2;
    let allow_transient = opts.allow_transient !== false;

    ExecSafe(BIN.SH, ["-c", "sleep 2"], null, trace_id);

    let settle_until = time() + min_settle_sec;
    let deadline = time() + timeout_sec;
    let last_dp = null;
    let stable_count = 0;

    while (time() < deadline) {
        let health = HealthCheck.verify({ allow_transient: allow_transient });
        last_dp = health.dataplane || dataplane_verify(trace_id);

        if (health.ok && !health.transient && !(last_dp && last_dp.transient)) {
            stable_count++;
            if (stable_count >= stable_samples && time() >= settle_until) {
                return last_dp;
            }
        } else if (health.transient === true || (last_dp && last_dp.transient)) {
            stable_count = 0;
        } else if (allow_transient && time() < settle_until && _recoverable_dataplane_gap(last_dp)) {
            stable_count = 0;
        } else if (!_recoverable_dataplane_gap(last_dp)) {
            last_dp.detail = lifecycle_error_detail(last_dp.detail || "dataplane verify failed");
            return last_dp;
        } else {
            stable_count = 0;
        }

        ExecSafe(BIN.SH, ["-c", "sleep 1"], null, trace_id);
    }

    let dp = last_dp || dataplane_verify(trace_id);
    dp.ok = false;
    dp.error = dp.error || "dataplane_incomplete";
    dp.detail = lifecycle_error_detail("dataplane verify timeout after final settling: " + (dp.detail || "unknown"));
    return dp;
}

export { check, verify_after_reload };
