/**
 * FlowProxy | storage/cleaner.uc
 * Responsibility: runtime storage cleanup only.
 */

'use strict';

import { open, stat, readfile, unlink, opendir } from 'fs';
import { cursor } from 'uci';

import { PATH, BIN } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { ExecSafe } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';
import { Metadata } from 'flowproxy.storage.metadata';

const PREFIX_STAGING = 'fp_fetch_';
const DIR_TMP_STAGING = '/tmp/';

const JOB_KEEP_COUNT = 200;
const CLEANUP_TTL_SEC = 3 * 24 * 60 * 60;
const LOG_MAX_BYTES = 256 * 1024;
const RESOURCE_BACKUP_DIR = sprintf("%s/backup/resources", PATH.RUNTIME);

const JOB_ID_PATTERN = regexp('^job_[a-zA-Z0-9_-]+$');
function _dir_entry_name(entry) {
    if (!entry) return null;
    if (type(entry) === "object" && entry.name != null) return entry.name;
    return sprintf("%s", entry);
}

function _mkdir_runtime_dirs(trace_id) {
    ExecSafe(BIN.MKDIR, ["-p", PATH.JOB], null, trace_id);
    ExecSafe(BIN.MKDIR, ["-p", PATH.LOG_DIR], null, trace_id);
}

function _job_id_from_name(name, suffix) {
    if (length(name) <= length(suffix)) return null;
    if (substr(name, length(name) - length(suffix)) !== suffix) return null;

    let id = substr(name, 0, length(name) - length(suffix));
    if (!match(id, JOB_ID_PATTERN)) return null;
    return id;
}

function _read_job_state(path) {
    try {
        let raw = readfile(path);
        if (!raw) return null;
        let data = json(raw);
        if (type(data) === "object" && data.state) return sprintf("%s", data.state);
    } catch (e) {
    }
    return null;
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

function _job_is_active(job_id) {
    if (!job_id || !match(job_id, JOB_ID_PATTERN)) return false;
    return _job_active_state(_read_job_state(sprintf("%s/%s.json", PATH.JOB, job_id)));
}

function _array_has(items, value) {
    for (let i = 0; i < length(items); i++) {
        if (items[i] === value) return true;
    }
    return false;
}

function _push_unique(items, value) {
    if (!_array_has(items, value)) push(items, value);
}

function _cleanup_jobs(trace_id) {
    let now = time();
    let deleted = 0;
    let ids = [];
    let paths = [];
    let log_paths = [];
    let mtimes = [];
    let states = [];
    let keep_ids = [];

    let dir_json = opendir(PATH.JOB);
    if (dir_json) {
        for (let entry = dir_json.read(); entry != null; entry = dir_json.read()) {
            let name = _dir_entry_name(entry);
            let id = _job_id_from_name(name || "", ".json");
            if (!id) continue;

            let path = sprintf("%s/%s", PATH.JOB, name);
            let st = stat(path);
            if (!st || st.type !== "file") continue;

            push(ids, id);
            push(paths, path);
            push(log_paths, sprintf("%s/%s.log", PATH.JOB, id));
            push(mtimes, st.mtime || 0);
            push(states, _read_job_state(path));
        }
        dir_json.close();
    }

    let selected = [];
    for (let n = 0; n < JOB_KEEP_COUNT; n++) {
        let best_idx = -1;
        let best_mtime = -1;

        for (let i = 0; i < length(ids); i++) {
            if (_array_has(selected, ids[i])) continue;
            if (best_idx < 0 || mtimes[i] > best_mtime) {
                best_idx = i;
                best_mtime = mtimes[i];
            }
        }

        if (best_idx < 0) break;
        _push_unique(selected, ids[best_idx]);
        _push_unique(keep_ids, ids[best_idx]);
    }

    for (let i = 0; i < length(ids); i++) {
        let fresh = (now - mtimes[i]) <= CLEANUP_TTL_SEC;
        let keep = _job_active_state(states[i]) || fresh || _array_has(keep_ids, ids[i]);

        if (keep) {
            _push_unique(keep_ids, ids[i]);
            continue;
        }

        if (unlink(paths[i])) deleted = deleted + 1;
        if (unlink(log_paths[i])) deleted = deleted + 1;
    }

    let dir = opendir(PATH.JOB);
    if (!dir) return deleted;

    for (let entry = dir.read(); entry != null; entry = dir.read()) {
        let name = _dir_entry_name(entry);
        let id = _job_id_from_name(name || "", ".log");
        if (!id || _array_has(keep_ids, id)) continue;

        let path = sprintf("%s/%s", PATH.JOB, name);
        let st = stat(path);
        if (!st || st.type !== "file") continue;
        if ((now - (st.mtime || 0)) <= CLEANUP_TTL_SEC) continue;

        if (unlink(path)) deleted = deleted + 1;
    }

    dir.close();
    return deleted;
}

function _cleanup_resource_backups(trace_id) {
    let now = time();
    let deleted = 0;
    let dir = opendir(RESOURCE_BACKUP_DIR);
    if (!dir) return 0;

    for (let entry = dir.read(); entry != null; entry = dir.read()) {
        let name = _dir_entry_name(entry);
        if (!name || name === "." || name === "..") continue;

        let path = sprintf("%s/%s", RESOURCE_BACKUP_DIR, name);
        let st = stat(path);
        if (!st) continue;
        if ((now - (st.mtime || 0)) <= CLEANUP_TTL_SEC) continue;

        let res = ExecSafe(BIN.RM, ["-rf", path], null, trace_id);
        if (res && res.ok) deleted++;
    }

    dir.close();
    return deleted;
}

function _truncate_large_log(path) {
    let st = stat(path);
    if (!st || st.type !== "file") return false;
    if ((st.size || 0) <= LOG_MAX_BYTES) return false;

    let fd = open(path, "w");
    if (!fd) return false;
    fd.write("");
    fd.close();
    return true;
}

function _cleanup_runtime_logs(trace_id) {
    ExecSafe(BIN.MKDIR, ["-p", PATH.LOG_DIR], null, trace_id);

    let truncated = 0;
    if (_truncate_large_log(PATH.LOG_SYS)) truncated++;
    if (_truncate_large_log(PATH.LOG_RUN)) truncated++;
    return truncated;
}

function _metadata_set(trace_id, key, value) {
    let res = Metadata.set({
        namespace: "maintenance",
        key: key,
        value: value
    }, trace_id);

    if (!res || !res.ok) {
        log(trace_id, "WARN", "CLEANER", sprintf(
            "Maintenance metadata write failed: key=%s detail=%s",
            key,
            (res && res.detail) ? res.detail : "unknown"
        ));
    }
}

function _record_maintenance_metadata(trace_id, result, jobs_deleted, logs_truncated, resource_backups_deleted) {
    _metadata_set(trace_id, "last_cleanup_at", time());
    _metadata_set(trace_id, "last_cleanup_result", result);
    _metadata_set(trace_id, "jobs_deleted", jobs_deleted);
    _metadata_set(trace_id, "logs_truncated", logs_truncated);
    _metadata_set(trace_id, "resource_backups_deleted", resource_backups_deleted);
}

function maintenance_cleanup(trace_id) {
    trace_id = trace_id || "maintenance_cleanup";
    let stage = "mkdir_runtime_dirs";
    let jobs_deleted = 0;
    let resource_backups_deleted = 0;
    let logs_truncated = 0;

    try {
        _mkdir_runtime_dirs(trace_id);

        stage = "jobs";
        jobs_deleted = _cleanup_jobs(trace_id);

        stage = "resource_backups";
        resource_backups_deleted = _cleanup_resource_backups(trace_id);

        stage = "runtime_logs";
        logs_truncated = _cleanup_runtime_logs(trace_id);

        log(trace_id, "INFO", "CLEANER", sprintf(
            "Maintenance cleanup completed. jobs_deleted=%d resource_backups_deleted=%d logs_truncated=%d",
            jobs_deleted, resource_backups_deleted, logs_truncated
        ));
    } catch (e) {
        let err = "" + e;
        log(trace_id, "CRIT", "CLEANER", sprintf("Maintenance cleanup failed at %s: %s", stage, err));
        _record_maintenance_metadata(trace_id, "fail", jobs_deleted, logs_truncated, resource_backups_deleted);
        return {
            ok: false,
            jobs_deleted: jobs_deleted,
            resource_backups_deleted: resource_backups_deleted,
            logs_truncated: logs_truncated,
            error_stage: stage,
            error: err
        };
    }

    _record_maintenance_metadata(trace_id, "success", jobs_deleted, logs_truncated, resource_backups_deleted);

    return {
        ok: true,
        jobs_deleted: jobs_deleted,
        resource_backups_deleted: resource_backups_deleted,
        logs_truncated: logs_truncated,
        error_stage: "",
        error: ""
    };
}

function _build_reference_graph(u) {
    let active_refs = {};

    u.foreach('flowproxy', 'routing_node', function(s) {
        let raw_nodes = s.urltest_nodes || s.nodes || [];
        if (type(raw_nodes) === 'string') raw_nodes = [raw_nodes];
        for (let i = 0; i < length(raw_nodes); i++) active_refs[raw_nodes[i]] = true;
    });

    u.foreach('flowproxy', 'routing_rule', function(s) {
        if (s.outbound) active_refs[s.outbound] = true;
    });

    return active_refs;
}

function sweep_staging(trace_id, ttl_seconds) {
    try {
        if (!ttl_seconds) ttl_seconds = 3600;
        let now = time();
        let dir_entries = opendir(DIR_TMP_STAGING);
        let deleted_bytes = 0;

        if (!dir_entries) return Success({ reclaimed_bytes: 0 }, 200, trace_id);

        for (let entry = dir_entries.read(); entry != null; entry = dir_entries.read()) {
            let name = _dir_entry_name(entry);
            if (index(name, PREFIX_STAGING) === 0) {
                let path = DIR_TMP_STAGING + name;
                let st = stat(path);

                if (st && st.type === 'file') {
                    let age = now - st.mtime;

                    if (age > ttl_seconds) {
                        let parts = split(name, '_');
                        let job_id = length(parts) > 2 ? parts[2] : null;

                        let job_is_running = _job_is_active(job_id);

                        if (!job_id || !job_is_running) {
                            unlink(path);
                            deleted_bytes += st.size;
                        } else {
                            log(trace_id, 'WARN', 'CLEANER', sprintf('Staging file %s exceeded TTL but is locked by active job.', name));
                        }
                    }
                }
            }
        }
        dir_entries.close();

        if (deleted_bytes > 0) {
            log(trace_id, 'INFO', 'CLEANER', sprintf('Staging sweep completed. Reclaimed %d bytes.', deleted_bytes));
        }

        return Success({ reclaimed_bytes: deleted_bytes }, 200, trace_id);

    } catch(e) {
        let err_msg = "" + e;
        log(trace_id, 'CRIT', 'CLEANER', 'Staging sweep failed: ' + err_msg);
        return Fail(ERR.E_SYSTEM_BUSY, err_msg, trace_id);
    }
}

function gc_uci_nodes(trace_id) {
    try {
        let u = cursor();
        u.load('flowproxy');

        let active_refs = _build_reference_graph(u);
        let orphan_nodes = [];
        let active_airports = {};

        u.foreach('flowproxy', 'subscription_airport', function(s) {
            active_airports[s['.name']] = true;
        });

        u.foreach('flowproxy', 'node', function(s) {
            let node_id = s['.name'];
            let is_orphaned = false;

            if (s.airport_id && !active_airports[s.airport_id]) {
                is_orphaned = true;
            }

            if (is_orphaned && !active_refs[node_id]) {
                push(orphan_nodes, node_id);
            }
        });

        if (length(orphan_nodes) > 0) {
            for (let i = 0; i < length(orphan_nodes); i++) {
                u.delete('flowproxy', orphan_nodes[i]);
            }
            u.commit('flowproxy');
            log(trace_id, 'INFO', 'CLEANER', sprintf('UCI GC completed. Removed %d orphaned nodes.', length(orphan_nodes)));
        }

        return Success({ removed_nodes: length(orphan_nodes) }, 200, trace_id);

    } catch(e) {
        let err_msg = "" + e;
        log(trace_id, 'CRIT', 'CLEANER', 'UCI GC failed: ' + err_msg);
        return Fail(ERR.E_SYSTEM_BUSY, err_msg, trace_id);
    }
}

export { maintenance_cleanup, sweep_staging, gc_uci_nodes };
