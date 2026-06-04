/**
 * FlowProxy | core/lock.uc | v1.2
 * VFS 级原子目录锁 (SSOT)
 * 职责：worker / lifecycle 命名锁，替代 shell flock 双轨。
 */

'use strict';

import { readfile, stat, writefile } from 'fs';
import { ExecSafe } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';
import { PATH, BIN } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';

const LOCK_PATHS = {
    worker: sprintf("%s/worker.lock", PATH.RUNTIME)
};

const DEFAULT_WAIT_SEC = 180;
const DEFAULT_STALE_SEC = 900;

const TXN_PHASES = {
    validating: true,
    staging_config: true,
    assembling_tproxy_network: true,
    assembling_tun_device: true,
    restarting: true,
    verifying: true
};

function _lock_owner_path(dir_lock) {
    return sprintf("%s/owner.json", dir_lock);
}

function _lock_age_sec(dir_lock) {
    let st = stat(dir_lock);
    if (!st || !st.mtime) return 0;
    return time() - st.mtime;
}

function _read_owner(dir_lock) {
    let raw = readfile(_lock_owner_path(dir_lock));
    if (!raw) return "";
    return trim(raw);
}

function _write_owner(dir_lock, trace_id, scope) {
    let payload = {
        owner: trace_id || "unknown",
        scope: scope || "worker",
        created_at: time()
    };
    writefile(_lock_owner_path(dir_lock), sprintf("%.J", payload));
}

function acquire(trace_id, scope, opts) {
    let sc = "worker";
    opts = opts || {};
    let wait_sec = opts.wait_sec != null ? int(opts.wait_sec) : DEFAULT_WAIT_SEC;
    let stale_sec = opts.stale_sec != null ? int(opts.stale_sec) : DEFAULT_STALE_SEC;
    let deadline = time() + wait_sec;

    ExecSafe(BIN.MKDIR, ["-p", PATH.RUNTIME], null, trace_id);

    let dir_lock = LOCK_PATHS.worker;
    while (true) {
        let res = ExecSafe(BIN.MKDIR, [dir_lock], null, trace_id);
        if (res.ok) {
            _write_owner(dir_lock, trace_id, sc);
            return Success({
                scope: sc,
                release: function() {
                    ExecSafe(BIN.RM, ["-rf", dir_lock], null, trace_id);
                }
            }, 200, trace_id);
        }

        let age = _lock_age_sec(dir_lock);
        if (stale_sec > 0 && age > stale_sec) {
            log(trace_id, "WARN", "LOCK", sprintf("Stale lock reclaimed: %s age=%d owner=%s", sc, age, _read_owner(dir_lock)));
            ExecSafe(BIN.RM, ["-rf", dir_lock], null, trace_id);
            continue;
        }

        if (time() >= deadline) {
            log(trace_id, "WARN", "LOCK", sprintf("Lock busy timeout: %s owner=%s", sc, _read_owner(dir_lock)));
            return Fail(ERR.E_SYSTEM_BUSY, sprintf("Lock exists: %s", sc), trace_id);
        }

        log(trace_id, "INFO", "LOCK", sprintf("Lock busy: %s; waiting owner=%s", sc, _read_owner(dir_lock)));
        ExecSafe(BIN.SH, ["-c", "sleep 1"], null, trace_id);
    }
}

export { acquire, LOCK_PATHS, TXN_PHASES };
