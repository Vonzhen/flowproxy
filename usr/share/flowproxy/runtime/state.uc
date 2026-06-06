/**
 * FlowProxy | runtime/state.uc | v1.2 SSOT State Edition
 * 真相引擎与状态管理器：HealthCheck 只读镜像 + runtime.state 落盘契约
 */

'use strict';

import { open as fs_open, stat, readfile } from 'fs';
import { cursor } from 'uci';
import { is_service_enabled } from 'flowproxy.core.config_helper';

import { PATH, BIN, DATAPLANE } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { ExecSafe, ensure_dir } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';

import { HealthCheck } from 'flowproxy.runtime.healthcheck';
import { RuntimeOrchestrator } from 'flowproxy.runtime.runtime';

const PATH_STAGED_CONFIG = sprintf("%s/sing-box-new.json", PATH.RUNTIME);
const PATH_BACKUP_CONFIG = sprintf("%s/sing-box-backup.json", PATH.RUNTIME);
const PATH_TXN_MARKER    = sprintf("%s/txn.marker", PATH.RUNTIME);
const PATH_RUNTIME_STATE = DATAPLANE.RUNTIME_STATE; 

const StateManager = {

    read_state: function() {
        if (!stat(PATH_RUNTIME_STATE)) return {};

        let content = readfile(PATH_RUNTIME_STATE);
        if (!content) return {};

        try {
            return json(content) || {};
        } catch (e) {
            log(null, 'WARN', 'STATE', 'runtime.state parse failed: ' + ("" + e));
            return {};
        }
    },

    /**
     * 写入硬化诊断全息状态 (P3阶段引入)
     * @param {object} payload - { apply_id, desired_generation, actual_generation, last_error, last_repair, degraded_reason }
     */
    record_state: function(payload) {
        ensure_dir(PATH.RUNTIME);

        let current = this.read_state();

        for (let k in payload) {
            if (k === "watchdog" && type(payload[k]) === "object") {
                current.watchdog = current.watchdog || {};
                for (let wk in payload[k]) {
                    current.watchdog[wk] = payload[k][wk];
                }
            } else {
                current[k] = payload[k];
            }
        }

        current.watchdog = current.watchdog || {};
        current.watchdog.last_state = current.watchdog.last_state || "healthy";
        current.watchdog.last_notified_state = current.watchdog.last_notified_state || "healthy";
        current.updated_at = time();

        let fd = fs_open(PATH_RUNTIME_STATE, "w");
        if (!fd) {
            log(null, 'CRIT', 'STATE', sprintf(
                'record_state failed: cannot open %s for write', PATH_RUNTIME_STATE
            ));
            return;
        }
        fd.write(sprintf("%.J", current));
        fd.close();
    },

    reset_watchdog_baseline: function(state) {
        this.record_state({
            watchdog: {
                last_state: state || "healthy",
                last_notified_state: state || "healthy"
            }
        });
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
    
    /** @deprecated Phase4：仅 system_rollback Job → Runtime；禁止后台自治调用 */
    rollback_and_fallback: function(trace_id) {
        log(trace_id, "WARN", "STATE", "Delegating rollback to RuntimeOrchestrator...");
        this.cleanup_staged(trace_id);
        let bak = stat(PATH_BACKUP_CONFIG) ? PATH_BACKUP_CONFIG : null;
        return RuntimeOrchestrator.rollback_commit(trace_id, bak);
    },

    sync_uci_nodes: function(airport_id, new_nodes, trace_id, legacy_airport_ids) {
        if (!new_nodes || length(new_nodes) === 0) return Success(0, 200, trace_id); 

        let u = cursor();
        u.load("flowproxy");
        let old_nodes_map = {};
        let incoming_nodes_map = {};
        let legacy_map = {};
        let active_legacy_map = {};

        for (let i = 0; i < length(new_nodes); i++) {
            if (new_nodes[i] && new_nodes[i].id) incoming_nodes_map[new_nodes[i].id] = true;
        }

        if (type(legacy_airport_ids) === 'array') {
            for (let i = 0; i < length(legacy_airport_ids); i++) {
                if (legacy_airport_ids[i]) legacy_map[legacy_airport_ids[i]] = true;
            }
        }

        u.foreach("flowproxy", "subscription_airport", (s) => {
            if (s['.name']) active_legacy_map[s['.name']] = true;
        });

        u.foreach("flowproxy", "node", (s) => {
            let old_airport_id = s.airport_id || "";
            let is_orphan_legacy = match(old_airport_id, regexp('^cfg[0-9a-fA-F]+$')) && !active_legacy_map[old_airport_id];
            if (
                old_airport_id === airport_id ||
                legacy_map[old_airport_id] ||
                incoming_nodes_map[s['.name']] ||
                is_orphan_legacy
            ) {
                old_nodes_map[s['.name']] = true;
            }
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

        let commit_ok = u.commit("flowproxy");
        if (!commit_ok) {
            return Fail(ERR.E_SYSTEM_BUSY, sprintf("uci commit failed while syncing airport [%s]", airport_id), trace_id);
        }
        log(trace_id, "INFO", "STATE", sprintf("Airport [%s] synced explicitly: %d nodes written.", airport_id, length(new_nodes)));
        
        return Success(length(new_nodes), 200, trace_id);
    },

    snapshot: function(trace_id) {
        try {
            let en_res = is_service_enabled(trace_id);
            let is_enabled = en_res.ok && en_res.data;

            // 🚨 彻底抛弃原有的模糊 netstat 扫描，直接呼叫专职的只读质检员
            let health_info = HealthCheck.verify();

            // process 维度：failed 含 "process" 即未运行；index() 未找到返回 -1（与 healthcheck 一致）
            let process_in_failed = index(health_info.failed, "process");
            let process_running = (process_in_failed < 0) ? true : false;
            let health_mode = health_info.mode || (health_info.dataplane ? health_info.dataplane.mode : "unknown");
            let health_mode_source = health_info.mode_source || (health_info.missing ? health_info.missing.mode_source : "unknown");
            let health_mode_warning = health_info.mode_warning || (health_info.missing ? health_info.missing.mode_warning : "");

            let snap = {
                process: { running: process_running },
                config: { valid: stat(PATH.RUN_JSON) != null },
                // 诚实的三态投射：ok 为 true 就是 healthy，否则就是损坏或降级
                health: { 
                    state: health_info.ok ? "healthy" : (length(health_info.failed) > 2 ? "broken" : "degraded"),
                    failed: health_info.failed,
                    failed_mode: health_mode,
                    mode: health_mode,
                    mode_source: health_mode_source,
                    mode_warning: health_mode_warning,
                    missing: health_info.missing || {
                        mode: health_mode,
                        mode_source: health_mode_source,
                        mode_warning: health_mode_warning,
                        failed: health_info.failed,
                        items: []
                    },
                    dataplane: {
                        mode: health_mode,
                        mode_source: health_mode_source,
                        mode_warning: health_mode_warning
                    }
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
                if (st_content) {
                    try {
                        snap.diagnostic = json(st_content) || {};
                    } catch (state_err) {
                        snap.diagnostic = {
                            state_corrupted: true,
                            state_corrupted_detail: "" + state_err
                        };
                        log(trace_id, 'WARN', 'STATE', 'runtime.state corrupted during snapshot: ' + ("" + state_err));
                    }
                }
            }
            snap.diagnostic.current_health_mode = health_mode;
            snap.diagnostic.current_health_mode_source = health_mode_source;

            return Success(snap, 200, trace_id);
            
        } catch(e) {
             let err_str = "" + e;
             return Fail(ERR.E_SYSTEM_BUSY, "Snapshot generation failed: " + err_str, trace_id);
        }
    }
};

// 🚨 铁律 1
export { StateManager };
