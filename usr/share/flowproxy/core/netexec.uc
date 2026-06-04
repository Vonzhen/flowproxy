/**
 * FlowProxy | core/netexec.uc | v1.0
 * 唯一网络执行层 SSOT：统一 curl runtime、stderr 捕获、归一化 ABI。
 */

'use strict';

import { popen, stat, readfile } from 'fs';
import { PATH, BIN, LIMIT } from 'flowproxy.core.constants';
import { log } from 'flowproxy.core.logger';
import { shell_escape, ExecSafe } from 'flowproxy.core.utils';

const LOCAL_EXIT_POPEN_FAILED = 126;
const LOCAL_EXIT_PROXY_UNAVAILABLE = 127;

function _stderr_summary(stderr, max_len) {
    let s = trim(stderr || "");
    if (length(s) === 0) return "(empty)";
    max_len = max_len || 120;
    if (length(s) > max_len) {
        return substr(s, 0, max_len) + "...";
    }
    return replace(s, "\n", " ");
}

function _classify_curl_exit(exit_code, stderr) {
    let dns_ok = true;
    let tls_ok = true;
    let connect_ok = true;
    let code = int(exit_code);

    if (code === 0) {
        return { dns_ok: dns_ok, tls_ok: tls_ok, connect_ok: connect_ok };
    }

    if (code === 6) {
        dns_ok = false;
    } else if (code === 7 || code === 28) {
        connect_ok = false;
    } else if (code === 35 || code === 51 || code === 53 || code === 54 || code === 58 || code === 60 || code === 66 || code === 77 || code === 83) {
        tls_ok = false;
    }

    let sl = lc(stderr || "");
    if (match(sl, regexp('resolve|resolution|host|getaddrinfo'))) dns_ok = false;
    if (match(sl, regexp('ssl|tls|certificate'))) tls_ok = false;
    if (match(sl, regexp('connect|connection refused|timed out'))) connect_ok = false;

    return { dns_ok: dns_ok, tls_ok: tls_ok, connect_ok: connect_ok };
}

function _mk_result(ok, exit_code, http_code, stderr, stdout, effective_mode, duration_ms, extra) {
    let cls = _classify_curl_exit(exit_code, stderr);
    let res = {
        ok: !!ok,
        exit_code: int(exit_code),
        http_code: (http_code != null && http_code !== "") ? sprintf("%s", http_code) : "000",
        stderr: stderr || "",
        stdout: stdout || "",
        effective_mode: effective_mode || "direct",
        duration_ms: int(duration_ms || 0),
        dns_ok: cls.dns_ok,
        tls_ok: cls.tls_ok,
        connect_ok: cls.connect_ok
    };
    if (extra) {
        for (let k in extra) res[k] = extra[k];
    }
    return res;
}

function _log_result(trace_id, res, note) {
    let suffix = note ? (" " + note) : "";
    if (res.ok) {
        log(trace_id, 'INFO', 'NETEXEC', sprintf(
            "[NETEXEC] curl ok: mode=%s exit=%d http=%s duration=%dms%s",
            res.effective_mode, res.exit_code, res.http_code, res.duration_ms, suffix
        ));
        return;
    }
    log(trace_id, 'WARN', 'NETEXEC', sprintf(
        "[NETEXEC] curl failed: mode=%s exit=%d http=%s stderr=%s duration=%dms%s",
        res.effective_mode, res.exit_code, res.http_code,
        _stderr_summary(res.stderr), res.duration_ms, suffix
    ));
}

function _build_curl_args(opts) {
    let connect_timeout = opts.connect_timeout || LIMIT.NET_CONNECT_TIMEOUT;
    let max_time = opts.max_time || opts.timeout_sec || LIMIT.DL_TIMEOUT;
    let retry_n = (opts.retry != null) ? opts.retry : LIMIT.NET_RETRY;
    let retry_delay = (opts.retry_delay != null) ? opts.retry_delay : LIMIT.NET_RETRY_DELAY;

    let args = [
        "-sS", "-L",
        "--connect-timeout", sprintf("%d", connect_timeout),
        "--max-time", sprintf("%d", max_time),
        "--retry", sprintf("%d", retry_n),
        "--retry-delay", sprintf("%d", retry_delay)
    ];

    if (opts.fail_on_http !== false) {
        push(args, "-f");
    }

    if (opts.insecure === true) {
        push(args, "-k");
    }

    if (opts.ipv4 === true) {
        push(args, "-4");
    }

    let mode = opts.effective_mode || "direct";
    if (mode === "proxy") {
        let port = opts.proxy_port;
        if (!port) {
            return { error: "proxy_unavailable: no proxy port", args: null };
        }
        push(args, "-x", sprintf("socks5h://127.0.0.1:%s", port));
    }

    if (opts.user_agent && length(opts.user_agent) > 0) {
        push(args, "-A", opts.user_agent);
    }

    if (type(opts.extra_args) === "array") {
        for (let i = 0; i < length(opts.extra_args); i++) {
            push(args, opts.extra_args[i]);
        }
    }

    let method = lc(opts.method || "GET");
    if (method === "POST") {
        push(args, "-X", "POST");
        if (type(opts.form_data) === "array") {
            for (let j = 0; j < length(opts.form_data); j++) {
                push(args, "-d", opts.form_data[j]);
            }
        }
    }

    return { error: null, args: args };
}

function _args_to_cmdline(args, url) {
    let cmdline = shell_escape(BIN.CURL);
    for (let i = 0; i < length(args); i++) {
        cmdline = cmdline + " " + shell_escape(args[i]);
    }
    cmdline = cmdline + " " + shell_escape(url);
    return cmdline;
}

/**
 * 唯一网络拉取入口
 * @param {object} opts - url, dest_file, effective_mode, proxy_port, timeout_sec, trace_id, extra_args, method, form_data
 */
function NetExec_fetch(opts) {
    opts = opts || {};
    let trace_id = opts.trace_id || "NETEXEC";
    let effective_mode = opts.effective_mode || "direct";
    let start_ts = time();

    if (!opts.url || length(opts.url) === 0) {
        let dur0 = (time() - start_ts) * 1000;
        let bad = _mk_result(false, LOCAL_EXIT_POPEN_FAILED, "000", "missing url", "", effective_mode, dur0, { error: "invalid_url" });
        _log_result(trace_id, bad, "(precheck)");
        return bad;
    }

    let built = _build_curl_args(opts);
    if (built.error) {
        let dur = (time() - start_ts) * 1000;
        let res = _mk_result(false, LOCAL_EXIT_PROXY_UNAVAILABLE, "000", built.error, "", effective_mode, dur, { error: "proxy_unavailable" });
        _log_result(trace_id, res, "(precheck)");
        return res;
    }

    let tag = sprintf("%d", time());
    let stderr_path = sprintf("%s/netexec_%s.err", PATH.RUNTIME, tag);
    let body_path = opts.dest_file || sprintf("%s/netexec_%s.body", PATH.RUNTIME, tag);
    let temp_body = !opts.dest_file;

    ExecSafe(BIN.RM, ["-f", stderr_path, body_path], null, trace_id);

    let curl_args = built.args;
    push(curl_args, "-o", body_path);
    push(curl_args, "-w", "%{http_code}");

    let cmdline = _args_to_cmdline(curl_args, opts.url);
    cmdline = cmdline + " 2>" + shell_escape(stderr_path);

    let p = popen(cmdline, "r");
    if (!p) {
        let dur = (time() - start_ts) * 1000;
        let res = _mk_result(false, LOCAL_EXIT_POPEN_FAILED, "000", "popen failed", "", effective_mode, dur, { error: "popen_failed" });
        _log_result(trace_id, res, null);
        return res;
    }

    let http_stdout = trim(p.read("all") || "");
    let exit_code = p.close();
    if (exit_code == null) {
        exit_code = LOCAL_EXIT_POPEN_FAILED;
    }

    let stderr = readfile(stderr_path) || "";
    let duration_ms = (time() - start_ts) * 1000;

    let file_size = 0;
    let st = stat(body_path);
    if (st && st.size) {
        file_size = st.size;
    }
    let response_body = readfile(body_path) || "";

    if (temp_body) {
        ExecSafe(BIN.RM, ["-f", body_path], null, trace_id);
    }
    ExecSafe(BIN.RM, ["-f", stderr_path], null, trace_id);

    let http_code = http_stdout || "000";
    let ok = (int(exit_code) === 0);

    if (!ok && opts.dest_file) {
        ExecSafe(BIN.RM, ["-f", opts.dest_file], null, trace_id);
    }

    let res = _mk_result(ok, exit_code, http_code, stderr, http_stdout, effective_mode, duration_ms, {
        error: ok ? "" : "curl_failed",
        file_size: file_size,
        response_body: response_body
    });

    _log_result(trace_id, res, null);
    return res;
}

const NetExec = {
    fetch: NetExec_fetch
};

export { NetExec, NetExec_fetch };
