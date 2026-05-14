/**
 * FlowProxy | core/job.uc | v1.0
 * 异步任务调度与状态机 (SSOT Aligned Edition)
 * 职责：管理异步任务的生命周期、状态持久化与 DFA 跃迁。
 * 核心对齐：
 * 1. 彻底摧毁内部裸 UUID 生成器，接入 Trace ID 引擎。
 * 2. 引入 ExecSafe 与 BIN.SH 安全沙箱包裹后台进程。
 * 3. 彻底接入 Result 协议，所有外部调用必须解析 Success/Fail。
 */

'use strict';

// 🚨 铁律 5: 原生模块解构导入
import { open as fs_open, stat } from 'fs';

// 🚨 铁律 3: 绝对命名空间寻址
import { PATH, BIN } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { JOB_TYPES } from 'flowproxy.core.contract';

import { ExecSafe, shell_escape } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';

// ⭐ 补丁对齐：引入系统的 Trace 引擎代替私有 uuid 生成
import { init as gen_trace_id } from 'flowproxy.core.trace';

const SCRIPT_WORKER = "/usr/share/flowproxy/runtime/worker.uc";

const STATE_ENUM = {
    PENDING: "pending",         
    RUNNING: "running",         
    VALIDATING: "validating",   
    COMMITTING: "committing",   
    ROLLBACK: "rollback",       
    SUCCESS: "success",         
    FAIL: "fail"                
};

const ALLOWED_STATE_MAP = {
    "pending": { "running": true, "fail": true },
    "running": { "running": true, "validating": true, "success": true, "fail": true },
    "validating": { "validating": true, "committing": true, "rollback": true, "fail": true },
    "committing": { "committing": true, "success": true, "rollback": true, "fail": true },
    "rollback": { "rollback": true, "fail": true },
    "success": { "success": true }, 
    "fail": { "fail": true }        
};

function _get_job_path(id) {
    if (!stat(PATH.JOB)) {
        ExecSafe(BIN.MKDIR, ["-p", PATH.JOB], null, id);
    }
    return sprintf("%s/%s.json", PATH.JOB, id);
}

function _write_state(id, data_obj) {
    let path = _get_job_path(id);
    if (!path) return false;
    let fd = fs_open(path, "w");
    if (!fd) return false;
    fd.write(sprintf("%.J", data_obj));
    fd.close();
    return true;
}

function _read_state(id) {
    let path = _get_job_path(id);
    if (!path) return null;
    let fd = fs_open(path, "r");
    if (!fd) return null;
    let content = fd.read("all");
    fd.close();
    try {
        return json(content);
    } catch(e) {
        // 🚨 铁律 6: 隐式异常兼容
        let err = "" + e;
        return null; 
    }
}

const JobManager = {
    dispatch: function(job_type, payload_obj, trace_id) {
        if (!JOB_TYPES[job_type]) {
            return Fail(ERR.E_AUTH_DENIED, "Illegal Job Type dispatch attempt: " + job_type, trace_id);
        }

        // ⭐ 补丁对齐：使用 Trace 引擎统一生成
        let job_id = "job_" + gen_trace_id(); 
        let t_id = trace_id || job_id; 
        
        let initial_state = {
            id: job_id,
            type: job_type,
            state: STATE_ENUM.PENDING,
            progress: 0,
            start_time: time(),
            update_time: time(),
            error: null,
            payload: payload_obj || {}
        };

        if (!_write_state(job_id, initial_state)) {
            return Fail(ERR.E_SYSTEM_BUSY, "Failed to persist initial job state", t_id);
        }
        
        log(t_id, "INFO", "JOB", sprintf("Dispatched, type: %s, job_id: %s", job_type, job_id));

        // 🚨 铁律 7: 彻底防御 Shell 注入
        let safe_worker = shell_escape(SCRIPT_WORKER);
        let safe_job_id = shell_escape(job_id);
        let safe_log    = shell_escape(sprintf("%s/%s.log", PATH.JOB, job_id));
        
        let cmd_str = sprintf("UCODE_PATH=/usr/share/ucode ucode %s %s >> %s 2>&1 &", safe_worker, safe_job_id, safe_log);
        
        // 唤起后台 Worker
        ExecSafe(BIN.SH, ["-c", cmd_str], null, t_id);

        // 返回标准 Success 格式
        return Success({ job_id: job_id }, 200, t_id);
    },

    status: function(job_id, trace_id) {
        let state_obj = _read_state(job_id);
        if (!state_obj) {
            return Fail(ERR.E_SYSTEM_BUSY, "Job state not found for ID: " + job_id, trace_id);
        }
        return Success(state_obj, 200, trace_id);
    },

    is_active: function(job_id, trace_id) {
        let state_obj = _read_state(job_id);
        if (!state_obj) return Success(false, 200, trace_id);

        let s = state_obj.state;
        let active = (
            s === STATE_ENUM.PENDING || 
            s === STATE_ENUM.RUNNING || 
            s === STATE_ENUM.VALIDATING || 
            s === STATE_ENUM.COMMITTING || 
            s === STATE_ENUM.ROLLBACK
        );
        return Success(active, 200, trace_id);
    },

    transition: function(job_id, new_state, progress_int, error_message, trace_id) {
        let t_id = trace_id || job_id;
        let state_obj = _read_state(job_id);
        if (!state_obj) {
            return Fail(ERR.E_SYSTEM_BUSY, "Job state not found for transition", t_id);
        }
        
        let cur_state = state_obj.state;

        if (!ALLOWED_STATE_MAP[cur_state] || !ALLOWED_STATE_MAP[cur_state][new_state]) {
            log(t_id, "WARN", "JOB", sprintf("Illegal DFA transition attempted: [%s] -> [%s]", cur_state, new_state));
            return Fail(ERR.E_SYSTEM_BUSY, "Illegal state transition", t_id);
        }
        
        state_obj.state = new_state;
        if (progress_int != null) state_obj.progress = progress_int;
        state_obj.update_time = time();
        if (error_message) state_obj.error = error_message;

        if (!_write_state(job_id, state_obj)) {
             return Fail(ERR.E_SYSTEM_BUSY, "Failed to persist transitioned job state", t_id);
        }
        
        let log_msg = sprintf("State transition -> [%s] (%d%%)", new_state, state_obj.progress);
        if (error_message) log_msg += " | Err: " + error_message;
        log(t_id, "INFO", "JOB", log_msg);

        return Success(true, 200, t_id);
    }
};

// 包装器暴露，对齐标准契约
function dispatch(type, payload, tid) { return JobManager.dispatch(type, payload, tid); }
function get_status(id, tid) { return JobManager.status(id, tid); }
function get(id, tid) { return JobManager.status(id, tid); }
function transition(id, ns, p, err, tid) { return JobManager.transition(id, ns, p, err, tid); }

// 🚨 铁律 1: 文件末尾统一导出
export { dispatch, get_status, get, transition, JobManager, STATE_ENUM };
