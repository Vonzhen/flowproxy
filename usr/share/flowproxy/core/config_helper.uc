/**
 * FlowProxy | core/config_helper.uc | v1.2 (SSOT Freeze)
 * 运行态只读配置快照唯一来源。load_snapshot / load_uci_context 为读路径；
 * 写路径由各 Module 自行 cursor（不经本快照缓存）。
 */

'use strict';

import { cursor } from 'uci';
import { access, readfile } from 'fs';
import { PATH } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';

const U_CONFIG = 'flowproxy';

let _snap_cache = null;

function invalidate_snapshot() {
    _snap_cache = null;
}

function _trim_port(val) {
    if (val == null || val === "") return null;
    let p = trim(sprintf("%s", val));
    return (length(p) > 0) ? p : null;
}

function _resolve_mixed_port_from_u(u) {
    let port = _trim_port(u.get(U_CONFIG, "infra", "mixed_port"));
    if (port) return port;
    let found = null;
    u.foreach(U_CONFIG, "server", function(s) {
        if (s.enabled === '1' && (s.type === 'mixed' || s.type === 'socks')) {
            found = _trim_port(s.port);
            return false;
        }
    });
    return found;
}

function _run_json_has_proxy_inbound() {
    if (!access(PATH.RUN_JSON)) return false;
    let raw = readfile(PATH.RUN_JSON);
    if (!raw || length(raw) === 0) return false;
    try {
        let cfg = json(raw);
        let inbounds = (cfg && type(cfg.inbounds) === 'array') ? cfg.inbounds : [];
        for (let i = 0; i < length(inbounds); i++) {
            let t = inbounds[i].type;
            if (t === 'mixed' || t === 'socks') return true;
        }
    } catch (e) {}
    return false;
}

function _build_snap(u) {
    let def_out = u.get(U_CONFIG, "routing", "default_outbound");
    let sub = u.get_all(U_CONFIG, 'subscription') || {};

    return {
        mixed_port: _resolve_mixed_port_from_u(u),
        proxy_inbound_ok: (function() {
            let port = _resolve_mixed_port_from_u(u);
            if (!port) return false;
            if (access(PATH.RUN_JSON) && !_run_json_has_proxy_inbound()) return false;
            return true;
        })(),
        service_enabled: (def_out != null && def_out !== "disabled" && def_out !== "nil"),
        default_outbound: def_out,
        subscription: {
            allow_insecure: sub.allow_insecure,
            packet_encoding: sub.packet_encoding,
            user_agent: sub.user_agent,
            update_via_proxy: sub.update_via_proxy
        },
        github_token: trim(u.get(U_CONFIG, "config", "github_token") || "")
    };
}

/**
 * 单次 UCI load + 快照（schema / 机场列表等复用同一 cursor）
 */
function load_uci_context(trace_id) {
    try {
        _snap_cache = null;
        let u = cursor();
        u.load(U_CONFIG);
        let snap = _build_snap(u);
        _snap_cache = snap;
        return Success({ u: u, snap: snap }, 200, trace_id);
    } catch (e) {
        return Fail(ERR.E_CONFIG_FAULT, "uci context failed: " + e, trace_id);
    }
}

function load_snapshot(trace_id) {
    if (_snap_cache) {
        return Success(_snap_cache, 200, trace_id);
    }
    let ctx = load_uci_context(trace_id);
    if (!ctx.ok) return ctx;
    return Success(ctx.data.snap, 200, trace_id);
}

function get_mixed_port(trace_id) {
    let res = load_snapshot(trace_id);
    if (!res.ok) return res;
    return Success(res.data.mixed_port, 200, trace_id);
}

function is_service_enabled(trace_id) {
    let res = load_snapshot(trace_id);
    if (!res.ok) return res;
    return Success(res.data.service_enabled, 200, trace_id);
}

function stable_airport_id(ap) {
    ap = ap || {};
    return ap['.name'] || "";
}

function legacy_airport_id(ap) {
    ap = ap || {};
    let raw = trim(sprintf("%s", ap.name || ap.url || ap['.name'] || ""));
    let sid = replace(lc(raw), regexp('[^a-z0-9_@.-]', 'g'), "_");
    sid = replace(sid, regexp('_+', 'g'), "_");
    sid = replace(sid, regexp('^_+|_+$', 'g'), "");
    return sid || ap['.name'] || "";
}

function _decorate_airport(ap) {
    if (!ap) return ap;
    ap.legacy_airport_id = legacy_airport_id(ap);
    ap.stable_airport_id = stable_airport_id(ap);
    return ap;
}

function list_enabled_airports(trace_id, scope, airport_id) {
    let ctx_res = load_uci_context(trace_id);
    if (!ctx_res.ok) return ctx_res;

    let u = ctx_res.data.u;
    let list = [];

    if (scope === 'all') {
        u.foreach(U_CONFIG, "subscription_airport", (s) => {
            if (s.enabled === '1') push(list, _decorate_airport(s));
        });
    } else if (airport_id) {
        let ap = u.get_all(U_CONFIG, airport_id);
        if (ap && ap.enabled === '1') {
            push(list, _decorate_airport(ap));
        } else {
            u.foreach(U_CONFIG, "subscription_airport", (s) => {
                if (s.enabled === '1' && (stable_airport_id(s) === airport_id || legacy_airport_id(s) === airport_id)) {
                    push(list, _decorate_airport(s));
                    return false;
                }
            });
        }
    }

    return Success(list, 200, trace_id);
}

function build_subscription_opts(trace_id, payload) {
    let snap_res = load_snapshot(trace_id);
    if (!snap_res.ok) return snap_res;

    let snap = snap_res.data;
    let via_proxy = snap.subscription.update_via_proxy;
    if (payload && payload.update_via_proxy != null && payload.update_via_proxy !== '') {
        via_proxy = payload.update_via_proxy;
    }

    return Success({
        allow_insecure: snap.subscription.allow_insecure,
        packet_encoding: snap.subscription.packet_encoding,
        user_agent: snap.subscription.user_agent,
        update_via_proxy: via_proxy,
        proxy_port: snap.mixed_port
    }, 200, trace_id);
}

function proxy_inbound_available(trace_id) {
    let snap_res = load_snapshot(trace_id);
    if (!snap_res.ok) return snap_res;
    let snap = snap_res.data;
    if (!snap.mixed_port || !snap.proxy_inbound_ok) {
        return Success({ ok: false }, 200, trace_id);
    }
    return Success({ ok: true, port: snap.mixed_port }, 200, trace_id);
}

export {
    invalidate_snapshot,
    load_snapshot,
    load_uci_context,
    get_mixed_port,
    is_service_enabled,
    list_enabled_airports,
    stable_airport_id,
    legacy_airport_id,
    build_subscription_opts,
    proxy_inbound_available
};
