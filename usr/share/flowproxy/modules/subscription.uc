/**
 * FlowProxy | modules/subscription.uc | v1.2 (Ultimate Syntax & Padding Safe Edition)
 * Role: download subscription content, parse protocol URIs, and persist UCI nodes.
 */
'use strict';

import { open as fs_open, stat } from 'fs';
import { PATH, BIN } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { with_changed } from 'flowproxy.core.module_result';
import { ExecSafe, shell_escape } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';
import { NetExec } from 'flowproxy.core.netexec';
import { LIMIT } from 'flowproxy.core.constants';
import { acquire } from 'flowproxy.core.lock';
import {
    list_enabled_airports,
    build_subscription_opts
} from 'flowproxy.core.config_helper';
import {
    _decode_base64_str,
    _generate_stable_id
} from 'flowproxy.modules.protocols.common';
import { parse as parse_protocol_node } from 'flowproxy.modules.protocols.registry';
import { parse as parse_legacy_node } from 'flowproxy.modules.protocols.legacy';
import { _rebuild_groups_unlocked } from 'flowproxy.modules.groups';
import { sync_uci_nodes } from 'flowproxy.modules.node_persist';

const MIN_PAYLOAD_BYTES = 16;
const STAGE_FETCH = "fetch";

function _net_fetch_fail(error, mode, proxy_port, extra) {
    let out = {
        ok: false,
        error: error,
        detail: "",
        mode: mode || "",
        stage: STAGE_FETCH
    };
    if (proxy_port) out.proxy_port = proxy_port;
    if (extra) {
        for (let k in extra) out[k] = extra[k];
        if (extra.detail) out.detail = extra.detail;
        else if (extra.http_code != null) {
            out.detail = sprintf("http_code=%s exit=%s", extra.http_code, extra.exit_code != null ? extra.exit_code : (extra.curl_exit != null ? extra.curl_exit : "-"));
        } else if (extra.exit_code != null) {
            out.detail = sprintf("exit=%d", extra.exit_code);
        } else if (extra.curl_exit != null) {
            out.detail = sprintf("exit=%d", extra.curl_exit);
        } else if (extra.file_size != null) {
            out.detail = sprintf("file_size=%d", extra.file_size);
        }
    }
    return out;
}

function _net_fetch_ok(content, mode, proxy_port, meta) {
    let out = {
        ok: true,
        content: content,
        error: "",
        detail: "",
        mode: mode || "",
        stage: STAGE_FETCH
    };
    if (proxy_port) out.proxy_port = proxy_port;
    if (meta) {
        for (let k in meta) out[k] = meta[k];
        if (meta.http_code != null && meta.file_size != null) {
            out.detail = sprintf("http_code=%s size=%d", meta.http_code, meta.file_size);
        }
    }
    return out;
}

function _http_code_valid(code_str) {
    let c = int(trim(code_str || ""));
    return (c >= 200 && c < 300);
}

function _net_fetch(url, global_opts, trace_id) {
    let tmp_file = sprintf("%s/fp_sub_dl_%d.txt", PATH.RUNTIME, time());
    let opts = global_opts || {};
    let use_proxy = (opts.update_via_proxy === '1' || opts.update_via_proxy === 1 || opts.update_via_proxy === true);
    let mode = use_proxy ? "proxy" : "direct";
    let proxy_port = null;

    if (use_proxy) {
        proxy_port = opts.proxy_port ? trim(sprintf("%s", opts.proxy_port)) : null;
        if (!proxy_port || length(proxy_port) === 0) {
            log(trace_id, 'WARN', 'SUBSCRIPTION', 'update_via_proxy=1 but no mixed/socks port (proxy_unavailable)');
            return _net_fetch_fail("proxy_unavailable", "proxy", null, {
                detail: "no mixed/socks inbound port",
                exit_code: 127
            });
        }
    }

    let nx = NetExec.fetch({
        url: url,
        dest_file: tmp_file,
        effective_mode: mode,
        proxy_port: proxy_port,
        timeout_sec: 15,
        connect_timeout: LIMIT.NET_CONNECT_TIMEOUT,
        retry: LIMIT.NET_RETRY,
        retry_delay: LIMIT.NET_RETRY_DELAY,
        insecure: true,
        ipv4: true,
        user_agent: opts.user_agent,
        trace_id: trace_id
    });

    let curl_exit = nx.exit_code;
    let http_code = nx.http_code || "";

    if (!nx.ok) {
        ExecSafe(BIN.RM, ["-f", tmp_file], null, trace_id);
        log(trace_id, 'WARN', 'SUBSCRIPTION', sprintf(
            "curl_failed mode=%s port=%s exit=%d http=%s stderr=%s",
            mode, proxy_port || "-", curl_exit, http_code || "-", nx.stderr || ""
        ));
        return _net_fetch_fail("curl_failed", mode, proxy_port, {
            exit_code: curl_exit,
            curl_exit: curl_exit,
            http_code: http_code,
            detail: nx.stderr || sprintf("curl exit %d", curl_exit)
        });
    }

    if (!_http_code_valid(http_code)) {
        ExecSafe(BIN.RM, ["-f", tmp_file], null, trace_id);
        log(trace_id, 'WARN', 'SUBSCRIPTION', sprintf(
            "http_error mode=%s port=%s exit=%d http=%s",
            mode, proxy_port || "-", curl_exit, http_code || "-"
        ));
        return _net_fetch_fail("http_error", mode, proxy_port, {
            exit_code: curl_exit,
            curl_exit: curl_exit,
            http_code: http_code,
            detail: sprintf("HTTP %s", http_code || "unknown")
        });
    }

    let st = stat(tmp_file);
    let file_size = (st && st.size) ? st.size : 0;
    if (!st || file_size < MIN_PAYLOAD_BYTES) {
        ExecSafe(BIN.RM, ["-f", tmp_file], null, trace_id);
        log(trace_id, 'WARN', 'SUBSCRIPTION', sprintf(
            "empty_payload mode=%s exit=%d http=%s size=%d",
            mode, curl_exit, http_code, file_size
        ));
        return _net_fetch_fail("empty_payload", mode, proxy_port, {
            exit_code: curl_exit,
            curl_exit: curl_exit,
            http_code: http_code,
            file_size: file_size,
            detail: sprintf("payload size %d < %d", file_size, MIN_PAYLOAD_BYTES)
        });
    }

    let content = null;
    let fd = fs_open(tmp_file, "r");
    if (fd) {
        content = fd.read("all");
        fd.close();
    }
    ExecSafe(BIN.RM, ["-f", tmp_file], null, trace_id);

    if (!content || length(content) < MIN_PAYLOAD_BYTES) {
        return _net_fetch_fail("empty_payload", mode, proxy_port, {
            exit_code: curl_exit,
            curl_exit: curl_exit,
            http_code: http_code,
            file_size: length(content || ""),
            detail: sprintf("body length %d < %d", length(content || ""), MIN_PAYLOAD_BYTES)
        });
    }

    return _net_fetch_ok(content, mode, proxy_port, {
        exit_code: curl_exit,
        curl_exit: curl_exit,
        http_code: http_code,
        file_size: file_size
    });
}

function _parse_node_uri(uri, global_opts, trace_id) {
    let registry_node = parse_protocol_node(uri, global_opts, trace_id);
    if (registry_node) return registry_node;

    let raw_uri = trim(uri || "");
    let parts = split(raw_uri, '://');
    let scheme = (length(parts) >= 2) ? parts[0] : "-";
    log(trace_id, 'WARN', 'SUBSCRIPTION', sprintf("protocol registry miss, using legacy fallback: scheme=%s", scheme || "-"));
    return parse_legacy_node(uri, global_opts, trace_id);
}
function fetch_and_parse(airport_cfg, global_opts, trace_id) {
    log(trace_id, 'INFO', 'SUBSCRIPTION', 'Starting network fetch and parse sequence...');

    try {
        let fetch_res = _net_fetch(airport_cfg.url, global_opts, trace_id);

        if (!fetch_res || !fetch_res.ok) {
            let err_code = (fetch_res && fetch_res.error) ? fetch_res.error : "network_fetch_failed";
            let err_mode = (fetch_res && fetch_res.mode) ? fetch_res.mode : "unknown";
            let err_stage = (fetch_res && fetch_res.stage) ? fetch_res.stage : STAGE_FETCH;
            let err_port = (fetch_res && fetch_res.proxy_port) ? fetch_res.proxy_port : "";
            let curl_exit = (fetch_res && fetch_res.curl_exit != null) ? fetch_res.curl_exit : -1;
            let http_code = (fetch_res && fetch_res.http_code) ? fetch_res.http_code : "";
            let file_size = (fetch_res && fetch_res.file_size != null) ? fetch_res.file_size : -1;
            let err_detail = sprintf(
                "fetch failed: error=%s stage=%s mode=%s curl_exit=%d http_code=%s size=%s detail=%s",
                err_code, err_stage, err_mode, curl_exit, http_code || "-",
                (file_size >= 0) ? sprintf("%d", file_size) : "-",
                (fetch_res && fetch_res.detail) ? fetch_res.detail : ""
            );
            if (length(err_port) > 0) err_detail += sprintf(" proxy_port=%s", err_port);
            if (err_code === "proxy_unavailable") {
                err_detail = "fetch failed: proxy_unavailable (no mixed/socks port configured)";
            }
            log(trace_id, 'WARN', 'SUBSCRIPTION', err_detail);
            return Fail(ERR.E_NETWORK_FAULT, err_detail, trace_id);
        }

        let res = fetch_res.content;
        let lines = [];
        try { 
            let j_data = json(res);
            lines = j_data.servers || j_data; 
        } catch(json_err) { 
            let d = _decode_base64_str(res); 
            lines = d ? split(trim(d), '\n') : []; 
        }

        let nodes = [];
        let fp_cache = {};
        let collision_idx = 0;

        for (let i = 0; i < length(lines); i++) {
            let n = _parse_node_uri(lines[i], global_opts, trace_id);
            if (n) {
                n.airport_id = airport_cfg.id;
                while (fp_cache[n.id]) { 
                    collision_idx++;
                    n.id = _generate_stable_id(n.id + "|" + collision_idx); 
                }
                fp_cache[n.id] = true;
                push(nodes, n);
            }
        }

        log(trace_id, 'INFO', 'SUBSCRIPTION', sprintf('Successfully parsed %d nodes.', length(nodes)));
        return Success(with_changed(length(nodes) > 0, { nodes: nodes }), 200, trace_id);

    } catch (e) {
        let err_msg = "" + e;
        log(trace_id, 'CRIT', 'SUBSCRIPTION', 'Fatal Crash during parsing: ' + err_msg);
        return Fail(ERR.E_SYSTEM_BUSY, err_msg, trace_id);
    }
}

function task_update_subscriptions(trace_id, payload) {
    payload = payload || {};
    let start_time = time();
    let total_nodes = 0;
    let failed_airports = [];
    let success_airports = [];
    let airport_stats = [];

    let scope = payload.scope === 'all' ? 'all' : null;
    let ap_res = list_enabled_airports(trace_id, scope, payload.airport_id);
    if (!ap_res.ok) return Fail(ERR.E_SYSTEM_BUSY, ap_res.detail, trace_id);

    let target_airports = ap_res.data;
    if (length(target_airports) === 0) {
        return Fail(ERR.E_SYSTEM_BUSY, "no enabled subscription airports", trace_id);
    }

    let opts_res = build_subscription_opts(trace_id, payload);
    if (!opts_res.ok) return Fail(ERR.E_SYSTEM_BUSY, opts_res.detail, trace_id);
    let global_opts = opts_res.data;

    log(trace_id, 'INFO', 'SUBSCRIPTION', sprintf("Subscription fetch mode: %s, proxy_port: %s",
        (global_opts.update_via_proxy === '1' || global_opts.update_via_proxy === 1 || global_opts.update_via_proxy === true) ? "proxy" : "direct",
        global_opts.proxy_port || "(none)"));

    let pending_syncs = [];
    for (let i = 0; i < length(target_airports); i++) {
        let ap = target_airports[i];
        ap.id = ap.stable_airport_id || ap.name || ap['.name'];
        let res = fetch_and_parse(ap, global_opts, trace_id);
        let valid_nodes = (res.ok && res.data && type(res.data.nodes) === 'array') ? res.data.nodes : [];
        let ap_name = ap.name || ap.id;

        if (!res.ok || length(valid_nodes) === 0) {
            let fail_reason = res.ok ? "parse yielded 0 nodes" : (res.detail || "unknown");
            log(trace_id, 'ERROR', 'SUBSCRIPTION', sprintf("Airport [%s] fetch failed: %s", ap_name, fail_reason));
            push(failed_airports, ap_name);
        } else {
            push(pending_syncs, {
                ap: ap,
                ap_name: ap_name,
                nodes: valid_nodes
            });
        }
    }

    if (length(pending_syncs) === 0) {
        let fail_msg = "all subscription fetches failed";
        if (length(failed_airports) > 0) {
            fail_msg += ": " + join(", ", failed_airports);
        }
        return Fail(ERR.E_SYSTEM_BUSY, fail_msg, trace_id);
    }

    let success_count = 0;
    let lock_res = acquire(trace_id, "worker");
    if (!lock_res.ok) return lock_res;
    let lock_handle = lock_res.data;

    try {
        for (let i = 0; i < length(pending_syncs); i++) {
            let item = pending_syncs[i];
            let sync_res = sync_uci_nodes(item.ap.id, item.nodes, trace_id, [item.ap.legacy_airport_id]);
            if (!sync_res.ok) {
                log(trace_id, 'ERROR', 'SUBSCRIPTION', sprintf("Airport [%s] UCI write failed: %s", item.ap_name, sync_res.detail || "unknown"));
                lock_handle.release();
                return Fail(ERR.E_SYSTEM_BUSY, "subscription uci write failed: " + (sync_res.detail || "unknown"), trace_id);
            }
            log(trace_id, 'INFO', 'SUBSCRIPTION', sprintf("Airport [%s] subscription_success=true uci_write_success=true nodes=%d", item.ap_name, length(item.nodes)));
            success_count++;
            total_nodes += length(item.nodes);
            push(airport_stats, {
                name: item.ap_name,
                nodes: length(item.nodes)
            });
            push(success_airports, sprintf("<b>%s:</b> %d nodes", item.ap_name, length(item.nodes)));
        }

        if (success_count > 0) {
            let group_res = _rebuild_groups_unlocked(trace_id);
            if (!group_res.ok) {
                lock_handle.release();
                return Fail(ERR.E_SYSTEM_BUSY, "subscription rebuild groups failed: " + group_res.detail, trace_id);
            }
        }

        lock_handle.release();
    } catch (e) {
        lock_handle.release();
        return Fail(ERR.E_SYSTEM_BUSY, "Subscription UCI write crashed: " + ("" + e), trace_id);
    }

    if (success_count === 0) {
        let fail_msg = "no subscription nodes synced";
        if (length(failed_airports) > 0) {
            fail_msg += ": " + join(", ", failed_airports);
        }
        return Fail(ERR.E_SYSTEM_BUSY, fail_msg, trace_id);
    }


    log(trace_id, 'INFO', 'SUBSCRIPTION', 'Subscription business phase completed: subscription_success=true uci_write_success=true group_rebuild_success=true');
    let duration = time() - start_time;
    let summary_msg = (length(failed_airports) > 0)
        ? "<b>Subscription update completed with failures</b>%0A"
        : "<b>Subscription update completed</b>%0A";
    summary_msg += "--------------------------------%0A";
    summary_msg += sprintf("<b>Duration:</b> %d sec | <b>Total nodes:</b> %d%0A%0A", duration, total_nodes);
    summary_msg += "<b>Successful airports:</b>%0A" + join("%0A", success_airports) + "%0A";
    if (length(failed_airports) > 0) {
        summary_msg += "%0A<b>Failed airports:</b>%0A" + join(", ", failed_airports) + "%0A";
    }
    summary_msg += "%0A[RESTART_PENDING]";

    return Success(with_changed(true, {
        msg: summary_msg,
        subscription_success: true,
        uci_write_success: true,
        group_rebuild_success: true,
        dataplane_success: null,
        success_count: success_count,
        failed_count: length(failed_airports),
        failed_airports: failed_airports,
        airport_stats: airport_stats,
        duration_sec: duration,
        total_nodes: total_nodes
    }), 200, trace_id);
}

export { fetch_and_parse, task_update_subscriptions };
