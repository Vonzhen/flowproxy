/**
 * FlowProxy | storage/cleaner.uc | v1.0
 * 职责：回收过期的任务日志、清理悬空的临时文件与孤儿配置节点。
 */

'use strict';

// 1. [解构原生库] 遵守铁律 5
import { stat, unlink, opendir } from 'fs';
import { cursor } from 'uci';

// 2. [引入基石法则] 遵守铁律 3
import { PATH } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { log } from 'flowproxy.core.logger';
import { is_active } from 'flowproxy.core.job'; 

const PREFIX_STAGING = 'fp_fetch_';
// 尊重原系统架构警告，暂时保留为文件内静态常量
const DIR_TMP_STAGING = '/tmp/';

/**
 * 内部私有函数：构建节点被引用的关系图
 */
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

/**
 * 模块对外导出的主接口：回收过期日志
 */
function rotate_logs(trace_id, max_keep) {
    try {
        if (!max_keep) max_keep = 50;
        let files = [];
        
        let dir_entries = opendir(PATH.JOB);
        if (!dir_entries) return Success({ deleted: 0 }, 200, trace_id); // ⭐ 协议对齐

        for (let entry = dir_entries.read(); entry != null; entry = dir_entries.read()) {
            if (entry.name !== '.' && entry.name !== '..') {
                let path = sprintf("%s/%s", PATH.JOB, entry.name);
                let st = stat(path);
                if (st && st.type === 'file') {
                    push(files, { path: path, mtime: st.mtime });
                }
            }
        }
        dir_entries.close();

        files.sort((a, b) => b.mtime - a.mtime);

        let deleted_count = 0;
        if (length(files) > max_keep) {
            let targets = slice(files, max_keep);
            for (let i = 0; i < length(targets); i++) {
                unlink(targets[i].path);
                deleted_count++;
            }
            log(trace_id, 'INFO', 'CLEANER', sprintf('Log rotation completed. Removed %d stale logs.', deleted_count));
        }

        return Success({ deleted: deleted_count }, 200, trace_id);

    } catch(e) {
        // 🚨 遵守铁律 6
        let err_msg = "" + e;
        log(trace_id, 'CRIT', 'CLEANER', 'Log rotation failed: ' + err_msg);
        return Fail(ERR.E_SYSTEM_BUSY, err_msg, trace_id);
    }
}

/**
 * 模块对外导出的主接口：清扫悬空临时文件
 */
function sweep_staging(trace_id, ttl_seconds) {
    try {
        if (!ttl_seconds) ttl_seconds = 3600;
        let now = time();
        let dir_entries = opendir(DIR_TMP_STAGING);
        let deleted_bytes = 0;

        if (!dir_entries) return Success({ reclaimed_bytes: 0 }, 200, trace_id); // ⭐ 协议对齐

        for (let entry = dir_entries.read(); entry != null; entry = dir_entries.read()) {
            if (index(entry.name, PREFIX_STAGING) === 0) {
                let path = DIR_TMP_STAGING + entry.name;
                let st = stat(path);

                if (st && st.type === 'file') {
                    let age = now - st.mtime;

                    if (age > ttl_seconds) {
                        let parts = split(entry.name, '_');
                        let job_id = length(parts) > 2 ? parts[2] : null;

                        // 透传内部检查
                        let active_res = is_active(job_id, trace_id);
                        let job_is_running = active_res.ok && active_res.data === true;

                        if (!job_id || !job_is_running) {
                            unlink(path);
                            deleted_bytes += st.size;
                        } else {
                            log(trace_id, 'WARN', 'CLEANER', sprintf('Staging file %s exceeded TTL but is locked by active job.', entry.name));
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

/**
 * 模块对外导出的主接口：UCI 孤儿节点垃圾回收
 */
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

// 🚨 遵守铁律 1: 绝对集中在文件末尾导出
export { rotate_logs, sweep_staging, gc_uci_nodes };
