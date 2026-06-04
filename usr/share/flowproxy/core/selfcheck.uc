/**
 * FlowProxy | core/selfcheck.uc | v1.2 SSOT Environment Gate
 * 职责：Worker 启动前扫描核心物理依赖与运行时契约。Fail-Fast，禁止 silent pass。
 */

'use strict';

import { open, stat } from 'fs';
import { PATH, BIN } from 'flowproxy.core.constants';
import { JOB_TYPES } from 'flowproxy.core.contract';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { ExecSafe } from 'flowproxy.core.utils';

const UCODE_SYMLINK = "/usr/share/ucode/flowproxy";

function _log_dir_writable() {
    ExecSafe(BIN.MKDIR, ["-p", PATH.LOG_DIR], null, "SELFCHECK");
    let probe = sprintf("%s/.selfcheck_write_probe", PATH.LOG_DIR);
    let fd = open(probe, "w");
    if (!fd) return false;
    fd.write("ok");
    fd.close();
    ExecSafe(BIN.RM, ["-f", probe], null, "SELFCHECK");
    return true;
}

function run_all_checks(trace_id) {
    let issues = [];

    let required_bins = [BIN.SINGBOX, BIN.CURL, BIN.NFT, BIN.SH];
    for (let i = 0; i < length(required_bins); i++) {
        let b = required_bins[i];
        if (!stat(b)) {
            push(issues, "致命缺失: 找不到二进制核心 -> " + b);
        }
    }

    let required_paths = [PATH.UCI, PATH.INIT];
    for (let i = 0; i < length(required_paths); i++) {
        let p = required_paths[i];
        if (!stat(p)) {
            push(issues, "系统异常: 缺失核心路径 -> " + p);
        }
    }

    if (!stat(UCODE_SYMLINK)) {
        push(issues, "契约违反: ucode 寻址软链缺失 -> " + UCODE_SYMLINK);
    }

    if (!_log_dir_writable()) {
        push(issues, "契约违反: 日志目录不可写 -> " + PATH.LOG_DIR);
    }

    if (!JOB_TYPES || !JOB_TYPES["apply_config"]) {
        push(issues, "契约损坏: 缺失 apply_config 核心定义");
    }
    let required_jobs = [
        "watchdog_report", "maintenance_logrotate",
        "apply_config", "update_subscriptions", "system_rollback"
    ];
    for (let i = 0; i < length(required_jobs); i++) {
        let jt = required_jobs[i];
        if (!JOB_TYPES[jt]) {
            push(issues, "契约损坏: 缺失 Job -> " + jt);
        }
    }

    if (length(issues) > 0) {
        return Fail(ERR.E_ENV_MISSING, join(" | ", issues), trace_id);
    }

    return Success(true, 200, trace_id);
}

export { run_all_checks };
