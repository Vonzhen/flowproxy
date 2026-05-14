/**
 * FlowProxy | core/utils.uc | v1.0
 * 系统基础工具箱 (SSOT Aligned Edition)
 * 职责：提供绝对安全的 Shell 执行环境、路径解析与基础辅助工具。
 * 核心纪律：严格遵守基石引用，拔除所有兼容性补丁。返回值严格遵循 Result 1.0。
 */

'use strict';

// 🚨 铁律 5: 原生模块解构导入
import { popen, stat } from 'fs';

// 🚨 铁律 3: 绝对命名空间寻址
import { PATH, BIN } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';

/* ========================= 
 * FS Helpers 
 * ========================= */
function ensure_dir(p) {
    if (!stat(p)) {
        ExecSafe(BIN.MKDIR, ["-p", p], null, "SYS_INIT");
    }
}

/* ========================= 
 * Shell Escape (🚨 铁律 7: 注入防御) 
 * ========================= */
function shell_escape(s) {
    s = (s == null) ? "" : sprintf("%s", s);
    // 将变量用单引号死死包裹，防止任何形式的命令逃逸
    s = replace(s, "'", "'\\''");
    return "'" + s + "'";
}

/* ========================= 
 * Exec Engine (SSOT Strict Safe Exec) 
 * ========================= */
function ExecSafe(cmd, args, opt, trace_id) {
    let start_ts = time();
    let timeout_sec = 5;
    let max_retries = 0;

    if (type(opt) == "object") {
        timeout_sec = opt.timeout || 5;
        max_retries = opt.retries || 0;
    }

    // 契约对齐：强制接入 constants.uc 的 BIN 字典
    let safe_cmd = cmd;
    if (substr(safe_cmd, 0, 1) != "/") {
        safe_cmd = BIN[ucase(cmd)]; 
    }

    if (!safe_cmd || substr(safe_cmd, 0, 1) != "/") {
        return Fail(ERR.E_SYSTEM_BUSY, "Exec Fatal: cmd must be absolute or registered in BIN: " + cmd, trace_id);
    }

    let safe_args = args || [];
    let timeout_cmd = BIN.TIMEOUT;
    let use_timeout = stat(timeout_cmd);

    let attempt = 1;
    let total = max_retries + 1;
    let code = -1;
    let out = "";

    while (attempt <= total) {
        let cmdline = "";

        if (use_timeout) {
            cmdline = shell_escape(timeout_cmd) + " " + timeout_sec;
        }

        cmdline = cmdline + (cmdline ? " " : "") + shell_escape(safe_cmd);

        for (let i = 0; i < length(safe_args); i++) {
            cmdline = cmdline + " " + shell_escape(safe_args[i]);
        }
        
        cmdline = cmdline + " 2>&1"; 

        let p = popen(cmdline, "r");

        if (!p) {
            return Fail(ERR.E_SYSTEM_BUSY, "Execution Fatal: popen failed", trace_id);
        }

        out = p.read("all") || "";
        code = p.close();

        if (code == 0) break;
        attempt++;
    }

    let end_ts = time();
    let data = {
        exit_code: code,
        stdout: out,
        obs: {
            duration: end_ts - start_ts,
            retry_count: attempt - 1
        }
    };

    // ⭐ 协议对齐：彻底接入 1.0 Result，透传 code 和 trace_id
    if (code == 0) {
        return Success(data, 200, trace_id);
    } else {
        return Fail(ERR.E_SYSTEM_BUSY, "Execution Failed with code " + code + ". Output: " + out, trace_id);
    }
}

// 🚨 铁律 1: 必须使用顶级导出
export { ExecSafe, ensure_dir, shell_escape };
