/**
 * FlowProxy | runtime/worker_launcher.uc
 * Responsibility: launch asynchronous job workers.
 */

'use strict';

import { PATH, BIN } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { ExecSafe } from 'flowproxy.core.utils';

const SCRIPT_WORKER = "/usr/share/flowproxy/runtime/worker.uc";
const JOB_ID_PATTERN = regexp('^job_[a-zA-Z0-9_-]+$');

function _shell_quote(value) {
    if (value == null) return null;

    let s = sprintf("%s", value);
    if (length(s) === 0) return null;

    s = replace(s, "'", "'\\''");
    return "'" + s + "'";
}

function launch_worker(job_id, trace_id) {
    if (type(job_id) !== "string" || !match(job_id, JOB_ID_PATTERN)) {
        return Fail(ERR.E_AUTH_DENIED, "Invalid worker launch job_id", trace_id);
    }

    let safe_worker = _shell_quote(SCRIPT_WORKER);
    let safe_job_id = _shell_quote(job_id);
    let safe_log = _shell_quote(sprintf("%s/%s.log", PATH.JOB, job_id));
    let safe_ucode_path = _shell_quote("/usr/share/ucode");
    let safe_ucode = _shell_quote(BIN.UCODE);

    if (!safe_worker || !safe_job_id || !safe_log || !safe_ucode_path || !safe_ucode) {
        return Fail(ERR.E_SYSTEM_BUSY, "Worker launch quote failed", trace_id);
    }

    let cmd = sprintf(
        "UCODE_PATH=%s %s %s %s >> %s 2>&1 &",
        safe_ucode_path,
        safe_ucode,
        safe_worker,
        safe_job_id,
        safe_log
    );

    let res = ExecSafe(BIN.SH, ["-c", cmd], null, trace_id);
    if (!res || !res.ok) {
        return Fail(ERR.E_SYSTEM_BUSY, "Worker launch failed: " + ((res && res.detail) ? res.detail : "unknown"), trace_id);
    }

    return Success({
        job_id: job_id,
        worker: SCRIPT_WORKER,
        log_path: sprintf("%s/%s.log", PATH.JOB, job_id)
    }, 200, trace_id);
}

export { launch_worker };
