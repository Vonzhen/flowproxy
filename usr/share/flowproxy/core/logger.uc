/**
 * FlowProxy | core/logger.uc | v1.3 SSOT Dual-Sink Stable
 * 职责：统一系统日志入口；写 system.log，同时 WARN/ERROR/CRIT/FATAL 写入 syslog。
 */

'use strict';

import { open, stat } from 'fs';
import { PATH, BIN } from 'flowproxy.core.constants';
import { ExecSafe, shell_escape } from 'flowproxy.core.utils';

function _normalize_level(level) {
    let lvl = level || "INFO";
    if (lvl === "warn") return "WARN";
    if (lvl === "error") return "ERROR";
    if (lvl === "crit") return "CRIT";
    if (lvl === "fatal") return "FATAL";
    if (lvl === "info") return "INFO";
    return lvl;
}

function _should_syslog(level) {
    let lvl = _normalize_level(level);
    return lvl === "WARN" || lvl === "ERROR" || lvl === "CRIT" || lvl === "FATAL";
}

function _syslog_priority(level) {
    let lvl = _normalize_level(level);
    if (lvl === "ERROR") return "user.err";
    if (lvl === "CRIT") return "user.crit";
    if (lvl === "FATAL") return "user.crit";
    if (lvl === "WARN") return "user.warn";
    return "user.info";
}

function _safe_message(msg) {
    let s = sprintf("%s", msg || "");
    s = replace(s, "\n", " ");
    return s;
}

function log(trace_id, level, mod, message) {
    let lvl = _normalize_level(level);
    let tid = trace_id || "system";
    let module_name = mod || "CORE";
    let msg = _safe_message(message);

    let line = sprintf(
        "[%s] [%s] [%s] [%s] %s\n",
        sprintf("%d", time()),
        tid,
        lvl,
        module_name,
        msg
    );

    try {
        ExecSafe(BIN.MKDIR, ["-p", PATH.LOG_DIR], null, tid);

        let fd = open(PATH.LOG_SYS, "a+");
        if (fd) {
            fd.write(line);
            fd.close();
        }

        if (_should_syslog(lvl) && stat(BIN.LOGGER)) {
            let sys_msg = sprintf("[%s] [%s] %s", tid, module_name, msg);
            ExecSafe(
                BIN.SH,
                ["-c", sprintf(
                    "%s -t flowproxy -p %s %s",
                    shell_escape(BIN.LOGGER),
                    shell_escape(_syslog_priority(lvl)),
                    shell_escape(sys_msg)
                )],
                null,
                tid
            );
        }
    } catch (e) {
        ExecSafe(
            BIN.SH,
            ["-c", sprintf(
                "%s -t flowproxy -p user.crit %s",
                shell_escape(BIN.LOGGER),
                shell_escape("logger.uc write failed: " + e)
            )],
            null,
            tid
        );
    }
}

export { log };
