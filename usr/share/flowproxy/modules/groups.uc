/**
 * FlowProxy | modules/groups.uc | v1.0
 * 职责：负责根据用户规则，动态重组并生成策略组配置文件。
 */

'use strict';

// 1. [解构原生库] 遵守铁律 5
import { cursor } from 'uci';

// 2. [引入基石法则] 遵守铁律 3
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { log } from 'flowproxy.core.logger';

const UCICONFIG = 'flowproxy';

/**
 * 模块对外导出的主接口
 * @param {string} trace_id - 贯穿始终的链路 ID
 */
function task_rebuild_groups(trace_id) {
    log(trace_id, 'INFO', 'GROUPS', 'Starting Dynamic Node Groups Generation...');
    
    try {
        let uci = cursor(); 
        uci.load(UCICONFIG);

        let removed = 0;
        uci.foreach(UCICONFIG, 'routing_node', (cfg) => {
            if (cfg.auto_generated === '1' && cfg['.name'] !== 'manual_global') {
                uci.delete(UCICONFIG, cfg['.name']);
                removed++;
            }
        });

        let airports = [];
        let all_regions = {};
        let top_level_nodes = {}; 

        uci.foreach(UCICONFIG, 'subscription_airport', (cfg) => {
            if (cfg.enabled !== '1') return;
            let rules = [];
            let r_group = type(cfg.region_group) === 'array' ? cfg.region_group : [cfg.region_group];
            
            for (let i = 0; i < length(r_group); i++) {
                let r = r_group[i];
                let p = split(r, '|');
                if (length(p) >= 1) {
                    let reg = trim(p[0]);
                    let kw = (length(p) >= 2) ? replace(trim(p[1]), /,/g, '|') : reg;
                    push(rules, { region: reg, pattern: regexp(kw, 'i') });
                    all_regions[reg] = true;
                }
            }
            
            let wl = type(cfg.top_level_whitelist) === 'array' ? cfg.top_level_whitelist : [cfg.top_level_whitelist || ""];
            push(airports, { id: cfg['.name'], name: cfg.name || 'Unnamed', rules: rules, whitelist: wl, nodes: {} });
        });

        if (length(airports) === 0) {
            return Fail(ERR.E_SYSTEM_BUSY, "没有找到启用的订阅配置", trace_id);
        }

        let valid_nodes_set = {};
        let fallback_node = null;

        uci.foreach(UCICONFIG, 'node', (node) => {
            if (!node.airport_id || !node.label) return;
            
            for (let i = 0; i < length(airports); i++) {
                let ap = airports[i];
                if (ap.id !== node.airport_id) continue;
                
                for (let j = 0; j < length(ap.rules); j++) {
                    let r = ap.rules[j];
                    if (match(node.label, r.pattern)) {
                        if (!ap.nodes[r.region]) ap.nodes[r.region] = [];
                        push(ap.nodes[r.region], node['.name']);
                        valid_nodes_set[node['.name']] = true;
                        if (!fallback_node) fallback_node = node['.name'];
                        break;
                    }
                }
            }
        });

        for (let i = 0; i < length(airports); i++) {
            let ap = airports[i];
            let ap_idx = sprintf('%02d', i + 1);
            
            let reg_keys = keys(ap.nodes);
            for (let j = 0; j < length(reg_keys); j++) {
                let region = reg_keys[j];
                let n_list = ap.nodes[region];
                let group_id = sprintf("%s%s", lc(region), ap_idx);
                
                uci.set(UCICONFIG, group_id, 'routing_node');
                uci.set(UCICONFIG, group_id, 'enabled', '1');
                uci.set(UCICONFIG, group_id, 'label', sprintf("[%s] %s - %s", ap_idx, region, ap.name));
                uci.set(UCICONFIG, group_id, 'node', 'urltest');
                uci.set(UCICONFIG, group_id, 'auto_generated', '1');
                uci.set(UCICONFIG, group_id, 'urltest_nodes', n_list);

                let allowed = false;
                for (let k = 0; k < length(ap.whitelist); k++) {
                    let w = ap.whitelist[k];
                    if (w === '*' || lc(w) === lc(region)) { allowed = true; break; }
                }
                if (allowed) {
                    if (!top_level_nodes[region]) top_level_nodes[region] = [];
                    for (let k = 0; k < length(n_list); k++) {
                        push(top_level_nodes[region], n_list[k]);
                    }
                }
            }
        }

        let top_keys = keys(top_level_nodes);
        for (let i = 0; i < length(top_keys); i++) {
            let reg = top_keys[i];
            let top_id = sprintf("auto_%s", lc(reg));
            uci.set(UCICONFIG, top_id, 'routing_node');
            uci.set(UCICONFIG, top_id, 'enabled', '1');
            uci.set(UCICONFIG, top_id, 'label', sprintf("⚡ Auto - %s", reg));
            uci.set(UCICONFIG, top_id, 'node', 'urltest');
            uci.set(UCICONFIG, top_id, 'auto_generated', '1');
            uci.set(UCICONFIG, top_id, 'urltest_nodes', top_level_nodes[reg]);
        }

        if (fallback_node) {
            let m_id = 'manual_global';
            let old_node = uci.get(UCICONFIG, m_id, 'node');
            let target = (old_node && valid_nodes_set[old_node]) ? old_node : fallback_node;

            uci.set(UCICONFIG, m_id, 'routing_node');
            uci.set(UCICONFIG, m_id, 'enabled', '1');
            if (!uci.get(UCICONFIG, m_id, 'label')) uci.set(UCICONFIG, m_id, 'label', '🖐️ Manual - Global');
            uci.set(UCICONFIG, m_id, 'node', target);
            uci.set(UCICONFIG, m_id, 'auto_generated', '1');
        }

        uci.commit(UCICONFIG);
        log(trace_id, 'INFO', 'GROUPS', 'Dynamic Node Groups Generation completed successfully.');
        
        return Success(true, 200, trace_id);

    } catch(e) {
        // 🚨 遵守铁律 6：隐式捕获防崩溃
        let err_msg = "" + e;
        log(trace_id, 'CRIT', 'GROUPS', 'Fatal Crash: ' + err_msg);
        return Fail(ERR.E_SYSTEM_BUSY, err_msg, trace_id);
    }
}

// 🚨 遵守铁律 1: 绝对集中在文件末尾导出
export { task_rebuild_groups };
