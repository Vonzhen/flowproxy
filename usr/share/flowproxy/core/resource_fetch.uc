/**
 * FlowProxy | core/resource_fetch.uc | v1.1
 * 资源拉取网络策略 SSOT：policy selection + fallback → NetExec.fetch()
 */

'use strict';

import { RESOURCE_FETCH_POLICY, LIMIT } from 'flowproxy.core.constants';
import { log } from 'flowproxy.core.logger';
import { verify_process } from 'flowproxy.runtime.healthcheck';
import { proxy_inbound_available } from 'flowproxy.core.config_helper';
import { NetExec } from 'flowproxy.core.netexec';

function _proxy_ready(trace_id) {
    if (!verify_process()) return false;
    let px = proxy_inbound_available(trace_id);
    return px.ok && px.data && px.data.ok;
}

function _proxy_port(trace_id) {
    let px = proxy_inbound_available(trace_id);
    if (px.ok && px.data && px.data.ok) return px.data.port;
    return null;
}

function _log_fetch_policy(trace_id, policy_key, policy, effective, note) {
    log(trace_id, 'INFO', 'RESOURCES', sprintf(
        "[RESOURCES] fetch policy: key=%s mode=%s fallback=%s effective=%s%s",
        policy_key,
        policy.mode || "unknown",
        policy.fallback || "none",
        effective,
        note ? (" " + note) : ""
    ));
}

function _build_attempts(policy_key, trace_id) {
    let policy = RESOURCE_FETCH_POLICY[policy_key];
    if (!policy) {
        policy = RESOURCE_FETCH_POLICY.asset_download;
    }

    let attempts = [];
    if (policy.mode === "proxy_preferred") {
        if (_proxy_ready(trace_id)) {
            push(attempts, "proxy");
        } else {
            log(trace_id, 'WARN', 'RESOURCES',
                "[RESOURCES] fetch policy: verify_process=false or proxy unavailable, skipping proxy attempt");
        }
        if (policy.fallback === "direct") {
            push(attempts, "direct");
        }
    } else {
        push(attempts, policy.mode || "direct");
    }

    if (length(attempts) === 0) {
        push(attempts, "direct");
    }
    return { policy: policy, attempts: attempts };
}

function _map_netexec(nx, effective) {
    return {
        ok: nx.ok,
        error: nx.error || (nx.ok ? "" : "curl_failed"),
        exit_code: nx.exit_code,
        curl_exit: nx.exit_code,
        http_code: nx.http_code,
        stderr: nx.stderr,
        stdout: nx.stdout,
        response_body: nx.response_body || "",
        effective: nx.effective_mode || effective,
        effective_mode: nx.effective_mode || effective,
        duration_ms: nx.duration_ms,
        dns_ok: nx.dns_ok,
        tls_ok: nx.tls_ok,
        connect_ok: nx.connect_ok,
        file_size: nx.file_size || 0
    };
}

function _netexec_attempt(url, dest_file, effective, opts, trace_id) {
    let proxy_port = null;
    if (effective === "proxy") {
        proxy_port = _proxy_port(trace_id);
    }

    let nx = NetExec.fetch({
        url: url,
        dest_file: dest_file,
        effective_mode: effective,
        proxy_port: proxy_port,
        timeout_sec: opts.timeout_sec || LIMIT.DL_TIMEOUT,
        connect_timeout: LIMIT.NET_CONNECT_TIMEOUT,
        retry: LIMIT.NET_RETRY,
        retry_delay: LIMIT.NET_RETRY_DELAY,
        trace_id: trace_id,
        extra_args: opts.extra_args,
        method: opts.method,
        form_data: opts.form_data,
        fail_on_http: opts.fail_on_http,
        insecure: opts.insecure,
        ipv4: opts.ipv4,
        user_agent: opts.user_agent
    });

    return _map_netexec(nx, effective);
}

/**
 * 按 RESOURCE_FETCH_POLICY 拉取 URL
 */
function fetch_with_policy(url, dest_file, policy_key, trace_id, opts) {
    opts = opts || {};
    let plan = _build_attempts(policy_key, trace_id);
    let policy = plan.policy;
    let attempts = plan.attempts;
    let last_err = null;

    for (let i = 0; i < length(attempts); i++) {
        let effective = attempts[i];
        _log_fetch_policy(trace_id, policy_key, policy, effective,
            i > 0 ? "(retry)" : "");

        let res = _netexec_attempt(url, dest_file, effective, opts, trace_id);
        if (res.ok) {
            _log_fetch_policy(trace_id, policy_key, policy, effective, "(success)");
            return res;
        }

        last_err = res;
        log(trace_id, 'WARN', 'RESOURCES', sprintf(
            "[RESOURCES] fetch failed: effective=%s exit=%d http=%s stderr=%s",
            effective, res.exit_code, res.http_code || "-", res.stderr || ""
        ));
    }

    _log_fetch_policy(trace_id, policy_key, policy, "none", "(all attempts failed)");
    if (last_err) {
        last_err.effective = "none";
        last_err.effective_mode = "none";
        return last_err;
    }

    return {
        ok: false,
        error: "fetch_failed",
        exit_code: 127,
        curl_exit: 127,
        http_code: "000",
        stderr: "no attempts",
        stdout: "",
        effective: "none",
        effective_mode: "none",
        duration_ms: 0,
        dns_ok: false,
        tls_ok: false,
        connect_ok: false,
        file_size: 0
    };
}

export { fetch_with_policy };
