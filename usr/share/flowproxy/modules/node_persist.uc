/**
 * FlowProxy | modules/node_persist.uc
 * Role: persist parsed subscription nodes into UCI node sections.
 */

'use strict';

import { cursor } from 'uci';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { log } from 'flowproxy.core.logger';

function sync_uci_nodes(airport_id, new_nodes, trace_id, legacy_airport_ids) {
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
    log(trace_id, "INFO", "NODE_PERSIST", sprintf("Airport [%s] synced explicitly: %d nodes written.", airport_id, length(new_nodes)));

    return Success(length(new_nodes), 200, trace_id);
}

export { sync_uci_nodes };
