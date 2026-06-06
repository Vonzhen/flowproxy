/**
 * FlowProxy | core/logger.uc | v1.3 SSOT Dual-Sink Stable
 * 职责：统一系统日志入口；写 system.log，同时 WARN/ERROR/CRIT/FATAL 写入 syslog。
 */

'use strict';

import { open, stat, readfile, unlink, opendir } from 'fs';
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

const JOB_KEEP_COUNT = 200;
const CLEANUP_TTL_SEC = 3 * 24 * 60 * 60;
const LOG_MAX_BYTES = 256 * 1024;
const RESOURCE_BACKUP_DIR = sprintf("%s/backup/resources", PATH.RUNTIME);

function _job_id_from_name(name, suffix) {
    if (!name || !suffix) return "";
    if (substr(name, length(name) - length(suffix)) !== suffix) return "";
    let id = substr(name, 0, length(name) - length(suffix));
    return match(id, regexp('^job_[a-zA-Z0-9_-]+$')) ? id : "";
}

function _read_job_state(path) {
    let raw = readfile(path);
    if (!raw) return "";
    try {
        let data = json(raw);
        return data ? (data.state || "") : "";
    } catch (e) {
        return "";
    }
}

function _job_active_state(state) {
    return (
        state === "pending" ||
        state === "running" ||
        state === "validating" ||
        state === "committing" ||
        state === "rollback"
    );
}

function _dir_entry_name(entry) {
    if (entry == null) return "";
    if (type(entry) === "string") return entry;
    if (type(entry) === "object") return entry.name || "";
    return "";
}

function _push_job_sorted(out, item) {
    push(out, item);
    for (let i = length(out) - 1; i > 0; i--) {
        if ((out[i].mtime || 0) <= (out[i - 1].mtime || 0)) break;
        let tmp = out[i - 1];
        out[i - 1] = out[i];
        out[i] = tmp;
    }
}

function _collect_job_jsons() {
    let out = [];
    let dir = opendir(PATH.JOB);
    if (!dir) return out;

    for (let entry = dir.read(); entry != null; entry = dir.read()) {
        let name = _dir_entry_name(entry);
        let job_id = _job_id_from_name(name, ".json");
        if (!job_id) continue;
        let path = sprintf("%s/%s", PATH.JOB, name);
        let st = stat(path);
        if (st && st.type === "file") {
            _push_job_sorted(out, {
                id: job_id,
                path: path,
                log_path: sprintf("%s/%s.log", PATH.JOB, job_id),
                mtime: st.mtime || 0,
                state: _read_job_state(path)
            });
        }
    }
    dir.close();

    return out;
}

function _cleanup_jobs(trace_id) {
    ExecSafe(BIN.MKDIR, ["-p", PATH.JOB], null, trace_id);

    let now = time();
    let deleted = 0;
    let jobs = _collect_job_jsons();
    let keep_map = {};

    for (let i = 0; i < length(jobs); i++) {
        let j = jobs[i];
        let active = _job_active_state(j.state);
        let fresh = (now - j.mtime) <= CLEANUP_TTL_SEC;
        let within_keep = i < JOB_KEEP_COUNT;
        if (active || fresh || within_keep) {
            keep_map[j.id] = true;
            continue;
        }
        unlink(j.path);
        unlink(j.log_path);
        deleted += 2;
    }

    let dir = opendir(PATH.JOB);
    if (!dir) return deleted;
    for (let entry = dir.read(); entry != null; entry = dir.read()) {
        let name = _dir_entry_name(entry);
        let job_id = _job_id_from_name(name, ".log");
        if (!job_id || keep_map[job_id]) continue;
        let path = sprintf("%s/%s", PATH.JOB, name);
        let st = stat(path);
        if (!st || st.type !== "file") continue;
        if ((now - (st.mtime || 0)) > CLEANUP_TTL_SEC) {
            unlink(path);
            deleted++;
        }
    }
    dir.close();
    return deleted;
}

function _cleanup_resource_backups(trace_id) {
    let dir = opendir(RESOURCE_BACKUP_DIR);
    if (!dir) return 0;

    let now = time();
    let deleted = 0;
    for (let entry = dir.read(); entry != null; entry = dir.read()) {
        let name = _dir_entry_name(entry);
        if (name === "." || name === "..") continue;
        let path = sprintf("%s/%s", RESOURCE_BACKUP_DIR, name);
        let st = stat(path);
        if (!st || (now - (st.mtime || 0)) <= CLEANUP_TTL_SEC) continue;
        ExecSafe(BIN.RM, ["-rf", path], null, trace_id);
        deleted++;
    }
    dir.close();
    return deleted;
}

function _truncate_large_log(path) {
    let st = stat(path);
    if (!st || st.type !== "file" || !st.size || st.size <= LOG_MAX_BYTES) return false;

    let fd = open(path, "w");
    if (!fd) return false;
    fd.write("");
    fd.close();
    return true;
}

function _cleanup_runtime_logs() {
    ExecSafe(BIN.MKDIR, ["-p", PATH.LOG_DIR], null, "logrotate");
    let truncated = 0;
    if (_truncate_large_log(PATH.LOG_SYS)) truncated++;
    if (_truncate_large_log(PATH.LOG_RUN)) truncated++;
    return truncated;
}

function logrotate() {
    let trace_id = "logrotate";
    ExecSafe(BIN.MKDIR, ["-p", PATH.LOG_DIR], null, trace_id);
    ExecSafe(BIN.MKDIR, ["-p", PATH.JOB], null, trace_id);

    let jobs_deleted = _cleanup_jobs(trace_id);
    let backups_deleted = _cleanup_resource_backups(trace_id);
    let logs_truncated = _cleanup_runtime_logs();

    log(trace_id, "INFO", "LOGGER", sprintf(
        "maintenance cleanup completed jobs_deleted=%d resource_backups_deleted=%d logs_truncated=%d",
        jobs_deleted,
        backups_deleted,
        logs_truncated
    ));

    return {
        jobs_deleted: jobs_deleted,
        resource_backups_deleted: backups_deleted,
        logs_truncated: logs_truncated
    };
}

export { log, logrotate };
