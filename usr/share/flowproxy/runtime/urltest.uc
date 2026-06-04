/**
 * FlowProxy | runtime/urltest.uc
 * Read-only sing-box Clash API observer for existing URLTest/outbound status.
 */

'use strict';

import { readfile } from 'fs';
import { cursor } from 'uci';

import { PATH, BIN } from 'flowproxy.core.constants';
import { ExecSafe } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';

const CACHE_TTL = 4;
const STATUS_API_UNAVAILABLE = "api_unavailable";

let _cache = {
    updated_at: 0,
    payload: null
};

function _empty_status(status, detail) {
    return {
        updated_at: time(),
        status: status || STATUS_API_UNAVAILABLE,
        detail: detail || "",
        items: {}
    };
}

function _read_run_json_controller() {
    let raw = readfile(PATH.RUN_JSON);
    if (!raw) return null;

    try {
        let cfg = json(raw);
        let ca = cfg && cfg.experimental && cfg.experimental.clash_api;
        return ca && ca.external_controller ? {
            external_controller: ca.external_controller,
            secret: ca.secret || ""
        } : null;
    } catch (e) {
        return null;
    }
}

function _read_uci_controller() {
    let u = cursor();
    u.load("flowproxy");

    let host = u.get("flowproxy", "infra", "clash_api_host") || "127.0.0.1";
    let port = int(u.get("flowproxy", "infra", "clash_api_port") || 0);
    if (!port) return null;

    return {
        external_controller: sprintf("%s:%d", host, port),
        secret: u.get("flowproxy", "infra", "clash_api_secret") || ""
    };
}

function _controller_to_url(controller) {
    if (!controller || !controller.external_controller) return null;

    let endpoint = sprintf("%s", controller.external_controller);
    if (index(endpoint, "://") < 0)
        endpoint = "http://" + endpoint;

    let parts = split(endpoint, "://");
    let scheme = parts[0] || "http";
    let rest = parts[1] || "";
    let slash = index(rest, "/");
    if (slash >= 0)
        rest = substr(rest, 0, slash);

    let hp = split(rest, ":");
    let host = hp[0] || "127.0.0.1";
    let port = length(hp) > 1 ? hp[1] : "";

    if (host === "0.0.0.0" || host === "::" || host === "[::]")
        host = "127.0.0.1";

    if (!port)
        return null;

    if (index(host, ":") >= 0 && substr(host, 0, 1) !== "[")
        host = "[" + host + "]";

    return sprintf("%s://%s:%s/proxies", scheme, host, port);
}

function _latest_latency(proxy) {
    let history = proxy && proxy.history;
    if (type(history) !== "array" || length(history) === 0)
        return null;

    for (let i = length(history) - 1; i >= 0; i--) {
        let h = history[i];
        if (h && h.delay != null) {
            let delay = int(h.delay);
            if (delay > 0)
                return delay;
            return null;
        }
    }

    return null;
}

function _normalize_status(proxy, latency) {
    if (!proxy)
        return "unknown";

    let type_name = sprintf("%s", proxy.type || "");
    if (
        type_name !== "urltest" && type_name !== "URLTest" &&
        type_name !== "selector" && type_name !== "Selector" &&
        type_name !== "fallback" && type_name !== "Fallback" &&
        type_name !== "loadbalance" && type_name !== "LoadBalance"
    )
        return "unsupported";

    if (latency != null && latency > 0)
        return "ok";

    let history = proxy.history;
    if (type(history) === "array" && length(history) > 0)
        return "timeout";

    return "unknown";
}

function _normalize_type(proxy) {
    let raw = sprintf("%s", proxy && proxy.type ? proxy.type : "");
    if (raw === "urltest" || raw === "URLTest") return "urltest";
    if (raw === "selector" || raw === "Selector") return "selector";
    if (raw === "fallback" || raw === "Fallback") return "fallback";
    if (raw === "loadbalance" || raw === "LoadBalance") return "loadbalance";
    return raw || "unknown";
}

function _parse_proxies(body) {
    let root = json(body);
    let proxies = root && root.proxies ? root.proxies : root;
    let now = time();
    let items = {};

    if (type(proxies) !== "object")
        return _empty_status("unknown", "invalid proxies payload");

    for (let tag in proxies) {
        let proxy = proxies[tag];
        if (type(proxy) !== "object")
            continue;

        let latency = _latest_latency(proxy);
        let status = _normalize_status(proxy, latency);

        let safe_tag = sprintf("%s", proxy.name || proxy.tag || tag);
        items[safe_tag] = {
            tag: safe_tag,
            type: _normalize_type(proxy),
            latency: latency,
            status: status,
            updated_at: now
        };

        if (proxy.now)
            items[safe_tag].now = sprintf("%s", proxy.now);
        if (proxy.all)
            items[safe_tag].all = proxy.all;
    }

    return {
        updated_at: now,
        status: "ok",
        items: items
    };
}

function _fetch_proxies(controller, trace_id) {
    let url = _controller_to_url(controller);
    if (!url)
        return _empty_status(STATUS_API_UNAVAILABLE, "clash api external_controller unavailable");

    let args = [
        "-sS",
        "--connect-timeout", "1",
        "--max-time", "2"
    ];

    if (controller.secret) {
        push(args, "-H");
        push(args, "Authorization: Bearer " + controller.secret);
    }

    push(args, url);

    let res = ExecSafe(BIN.CURL, args, { timeout: 3 }, trace_id);
    if (!res.ok || !res.data || !res.data.stdout)
        return _empty_status(STATUS_API_UNAVAILABLE, res.detail || "clash api request failed");

    try {
        return _parse_proxies(res.data.stdout);
    } catch (e) {
        log(trace_id, "WARN", "URLTEST", "Failed to parse Clash API /proxies response: " + ("" + e));
        return _empty_status(STATUS_API_UNAVAILABLE, "invalid clash api response");
    }
}

function get_urltest_status(trace_id) {
    let now = time();
    if (_cache.payload && _cache.updated_at && (now - _cache.updated_at) <= CACHE_TTL)
        return _cache.payload;

    let controller = _read_run_json_controller() || _read_uci_controller();
    let payload = _fetch_proxies(controller, trace_id);

    _cache.updated_at = now;
    _cache.payload = payload;
    return payload;
}

export { get_urltest_status };
