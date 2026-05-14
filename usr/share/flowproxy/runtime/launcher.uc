/**
 * FlowProxy | runtime/launcher.uc | v1.1
 * 进程控制启动器 (SSOT Aligned Edition)
 * 职责：物理控制 sing-box 进程的校验、启动、重载与停止。
 * 核心对齐：全量接入 Result 协议，清除正则陷阱，引入僵尸进程物理猎杀机制 (Zombie Hunting)。
 */

'use strict';

// 🚨 铁律 5: 原生解构
import { stat, readfile } from 'fs';

// 🚨 铁律 3: 绝对命名空间寻址
import { PATH, BIN } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { ExecSafe } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';

function _validate_path(path) {
    if (type(path) !== 'string') return false;
    let runtime_dir = PATH.RUNTIME;
    if (substr(path, 0, length(runtime_dir)) !== runtime_dir) return false;
    if (index(path, '../') >= 0 || index(path, '..\\') >= 0) return false;
    // 🚨 架构修复：移除正则字面量
    if (!match(path, regexp('\\.json$'))) return false;
    return true;
}

/**
 * 校验配置文件合法性
 */
function check(config_path, ctx, trace_id) {
    try {
        if (!ctx || ctx.caller !== 'runtime.manager') {
            log(trace_id, "ERROR", "LAUNCHER", "Unauthorized execution request rejected.");
            return Fail(ERR.E_AUTH_DENIED, "Caller Unauthorized", trace_id);
        }

        if (!_validate_path(config_path)) {
            return Fail(ERR.E_SYSTEM_BUSY, "Security Violation: Illegal config path", trace_id);
        }

        if (!stat(BIN.SINGBOX)) {
            return Fail(ERR.E_ENV_MISSING, "Binary Missing: sing-box not found", trace_id);
        }

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
 * 重启/重载服务实例
 */
function reload(config_path, ctx, trace_id) {
    try {
        if (!ctx || ctx.caller !== 'runtime.manager') return Fail(ERR.E_AUTH_DENIED, "Caller Unauthorized", trace_id);
        if (!_validate_path(config_path)) return Fail(ERR.E_SYSTEM_BUSY, "Security Violation: Illegal config path", trace_id);

        let res = ExecSafe(BIN.SH, ["-c", "/etc/init.d/flowproxy restart"], { timeout: 15 }, trace_id);
        
        if (res.ok) return Success(res.data, 200, trace_id);
        return Fail(ERR.E_SYSTEM_BUSY, "Service restart failed", trace_id);

    } catch(e) {
        let err_str = "" + e;
        return Fail(ERR.E_SYSTEM_BUSY, "Launcher Reload Exception: " + err_str, trace_id);
    }
}

/**
 * 停止服务实例
 */
function stop(ctx, trace_id) {
    try {
        if (!ctx || ctx.caller !== 'runtime.manager') return Fail(ERR.E_AUTH_DENIED, "Caller Unauthorized", trace_id);

        // 阶段 1: 尝试调用 init 脚本优雅停止
        let res = ExecSafe(BIN.SH, ["-c", "/etc/init.d/flowproxy stop"], { timeout: 10 }, trace_id);
        
        // 阶段 2: 绝对物理猎杀 (Zombie Hunting)
        // 强制读取专属 PID 文件并发送 SIGKILL，防止 init 脚本状态失灵
        let pid_file = sprintf("%s/sing-box.pid", PATH.RUNTIME);
        let pid_str = trim(readfile(pid_file) || "");
        if (length(pid_str) > 0) {
            ExecSafe(BIN.SH, ["-c", sprintf("kill -9 %s 2>/dev/null", pid_str)], null, trace_id);
            ExecSafe(BIN.SH, ["-c", sprintf("rm -f %s", pid_file)], null, trace_id);
        }

        if (res.ok) return Success(res.data, 200, trace_id);
        return Fail(ERR.E_SYSTEM_BUSY, "Service stop failed", trace_id);

    } catch(e) {
        let err_str = "" + e;
        return Fail(ERR.E_SYSTEM_BUSY, "Launcher Stop Exception: " + err_str, trace_id);
    }
}

// 🚨 铁律 1: 文件末尾统一导出
export { check, reload, stop };
