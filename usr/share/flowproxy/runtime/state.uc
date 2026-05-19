/**
 * FlowProxy | runtime/state.uc | v1.1 (Strict Identity Edition)
 * 真相引擎与状态管理器 (SSOT Aligned Edition)
 * 职责：管控执行态配置文件与事务标记，并生成极速无阻塞的系统全景快照。
 * 架构更新：废弃 pidof 模糊探测，引入基于 PID 文件与 /proc/cmdline 的强身份校验。清除正则字面量陷阱。
 */

'use strict';

// 🚨 铁律 5
import { open as fs_open, stat, readfile } from 'fs';
import { cursor } from 'uci';

// 🚨 铁律 3
import { PATH, BIN } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { ExecSafe } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';

import { execute_fallback } from 'flowproxy.system.safety';
import { HealthCheck } from 'flowproxy.runtime.healthcheck';

const PATH_STAGED_CONFIG = sprintf("%s/sing-box-new.json", PATH.RUNTIME);
const PATH_BACKUP_CONFIG = sprintf("%s/sing-box-backup.json", PATH.RUNTIME);
const PATH_TXN_MARKER    = sprintf("%s/txn.marker", PATH.RUNTIME);
const PATH_RUNNING_PID   = PATH.RUNNING_PID;
const PATH_RUNTIME_STATE = sprintf("%s/runtime.state", PATH.RUNTIME); 

const StateManager = {

    /**
     * 写入硬化诊断全息状态 (P3阶段引入)
     * @param {object} payload - { apply_id, desired_generation, actual_generation, last_error, last_repair, degraded_reason }
     */
    record_state: function(payload) {
        let current = {};
        if (stat(PATH_RUNTIME_STATE)) {
            let content = readfile(PATH_RUNTIME_STATE);
            if (content) current = json(content) || {};
        }
        
        for (let k in payload) {
            current[k] = payload[k];
        }
        current.updated_at = time();

        let fd = fs_open(PATH_RUNTIME_STATE, "w");
        if (fd) {
            fd.write(sprintf("%.J", current));
            fd.close();
        }
    },
    
    write_staged: function(json_str, trace_id) {
        let fd = fs_open(PATH_STAGED_CONFIG, "w");
        if (!fd) return Fail(ERR.E_SYSTEM_BUSY, "Cannot write staged config.", trace_id);
        fd.write(json_str); 
        fd.close();
        return Success(true, 200, trace_id);
    },
    
    get_staged_path: function() { return PATH_STAGED_CONFIG; },
    get_run_path: function() { return PATH.RUN_JSON; },
    
    mark_transaction: function(trace_id) {
        let fd = fs_open(PATH_TXN_MARKER, "w");
        if (fd) { 
            let t_id = trace_id || "SYS";
            fd.write(sprintf('{"job_id":"%s","phase":"committing"}', t_id)); 
            fd.close(); 
        }
    },
    
    clear_transaction: function(trace_id) { 
        ExecSafe(BIN.RM, ["-f", PATH_TXN_MARKER], null, trace_id); 
    },
    
    cleanup_staged: function(trace_id) { 
        if (stat(PATH_STAGED_CONFIG)) {
            ExecSafe(BIN.RM, ["-f", PATH_STAGED_CONFIG], null, trace_id); 
        }
    },
    
    commit_staged: function(trace_id) {
        if (stat(PATH.RUN_JSON)) {
            ExecSafe(BIN.CP, ["-f", PATH.RUN_JSON, PATH_BACKUP_CONFIG], null, trace_id);
        }
        let mv_res = ExecSafe(BIN.MV, ["-f", PATH_STAGED_CONFIG, PATH.RUN_JSON], null, trace_id);
        
        if (!mv_res.ok) {
            return Fail(ERR.E_SYSTEM_BUSY, "Atomic file swap failed: " + mv_res.detail, trace_id);
        }
        return Success(true, 200, trace_id);
    },
    
    verify_health: function(job_id, timeout_sec) {
        // 🚨 修正：直接呼叫新版只读体检员
        let hc_res = HealthCheck.verify();
        
        if (!hc_res.ok) {
             let err_detail = "Health check failed on: " + join(", ", hc_res.failed);
             return Fail(ERR.E_SYSTEM_BUSY, err_detail, job_id);
        }
        
        return Success(true, 200, job_id);
    },
    
    rollback_and_fallback: function(trace_id) {
        log(trace_id, "WARN", "STATE", "Triggering state rollback and safety fallback procedures...");
        if (stat(PATH_BACKUP_CONFIG)) { 
            ExecSafe(BIN.MV, ["-f", PATH_BACKUP_CONFIG, PATH.RUN_JSON], null, trace_id); 
        }
        this.cleanup_staged(trace_id); 
        
        return execute_fallback(trace_id);
    },

    sync_uci_nodes: function(airport_id, new_nodes, trace_id) {
        if (!new_nodes || length(new_nodes) === 0) return Success(0, 200, trace_id); 

        let u = cursor();
        u.load("flowproxy");
        let old_nodes_map = {};

        u.foreach("flowproxy", "node", (s) => {
            if (s.airport_id === airport_id) { old_nodes_map[s['.name']] = true; }
        });

        for (let i = 0; i < length(new_nodes); i++) {
            let n = new_nodes[i];
            let sid = n.id;
            
            if (old_nodes_map[sid]) { 
                u.delete("flowproxy", sid); 
                delete old_nodes_map[sid]; 
            }
            
            u.set("flowproxy", sid, "node");
            u.set("flowproxy", sid, "airport_id", airport_id);

            for (let field_name in n) {
                let field_value = n[field_name];
                if (field_name === 'id' || field_name === 'airport_id' || field_name === 'isExisting') continue;
                if (substr(field_name, 0, 1) === '.') continue;
                if (field_value != null && field_value !== "") {
                    u.set("flowproxy", sid, field_name, field_value);
                }
            }
        }

        let to_delete = keys(old_nodes_map);
        for (let j = 0; j < length(to_delete); j++) {
            u.delete("flowproxy", to_delete[j]);
        }

        u.commit("flowproxy");
        log(trace_id, "INFO", "STATE", sprintf("Airport [%s] synced explicitly: %d nodes written.", airport_id, length(new_nodes)));
        
        return Success(length(new_nodes), 200, trace_id);
    },

    snapshot: function(trace_id) {
        try {
            let u = cursor();
            u.load("flowproxy");
            
            let def_out = u.get("flowproxy", "routing", "default_outbound");
            let is_enabled = def_out != null && def_out !== "disabled" && def_out !== "nil";

            // 🚨 彻底抛弃原有的模糊 netstat 扫描，直接呼叫专职的只读质检员
            let health_info = HealthCheck.verify();

            let snap = {
                process: { running: health_info.ok || index(health_info.failed, "pid") === -1 },
                config: { valid: stat(PATH.RUN_JSON) != null },
                // 诚实的三态投射：ok 为 true 就是 healthy，否则就是损坏或降级
                health: { 
                    state: health_info.ok ? "healthy" : (length(health_info.failed) > 2 ? "broken" : "degraded"),
                    failed: health_info.failed 
                },
                ports: { mixed: 5330, dns: 5333 },
                version: { singbox: "1.x-managed" },
                enabled: is_enabled,
                reason: is_enabled ? "Configured" : "Disabled by user intent"
            };

            // 注入持久化诊断
            snap.diagnostic = {};
            if (stat(PATH_RUNTIME_STATE)) {
                let st_content = readfile(PATH_RUNTIME_STATE);
                if (st_content) snap.diagnostic = json(st_content) || {};
            }

            return Success(snap, 200, trace_id);
            
        } catch(e) {
             let err_str = "" + e;
             return Fail(ERR.E_SYSTEM_BUSY, "Snapshot generation failed: " + err_str, trace_id);
        }
    }
};

// 🚨 铁律 1
export { StateManager };
