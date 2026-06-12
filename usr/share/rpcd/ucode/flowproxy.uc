/**
 * FlowProxy | API Gateway & Query Kernel | v1.2 (Hardened Edition)
 * 职责：Ubus 接口暴露，领域查询分发，边界安全拦截。全链路 Trace ID 始发地。
 * 环境适配：全面加装 try-catch 边界防爆装甲，剥离 export，恢复扁平字典结构。
 * 架构更新：彻底抹除所有正则表达式字面量，接入 regexp() 安全沙箱。
 * 终极修复：填补 API 鉴权漏网之鱼，修复内核输出空指针异常，解决 JSON 弱类型隐性拦截。
 */

'use strict';

// 🚨 宪法修正：强制注入库搜索路径，防御 rpcd 守护进程环境变量漂移
push(REQUIRE_SEARCH_PATH, "/usr/share/ucode/*.uc");
push(REQUIRE_SEARCH_PATH, "/usr/share/ucode/*/init.uc");

// 1. [解构原生库] 遵守铁律 5
import { open as fs_open, readfile, writefile, lstat, access } from 'fs';
import { cursor } from 'uci';

// 2. [引入基石法则] 遵守铁律 3
import { PATH, BIN, LIMIT } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { JOB_TYPES, SYSTEM_METHODS } from 'flowproxy.core.contract';
import { log } from 'flowproxy.core.logger';
import { init as gen_trace_id } from 'flowproxy.core.trace';

// 3. [引入系统模块]
import { dispatch, get_status, parse_job_start_envelope, parse_job_query_envelope } from 'flowproxy.core.job';
import { ExecSafe } from 'flowproxy.core.utils';
import { StateManager } from 'flowproxy.runtime.state';
import { get_urltest_status } from 'flowproxy.runtime.urltest';
import { proxy_inbound_available } from 'flowproxy.core.config_helper';

/**
 * =========================================================
 * 🧩 L2: Domain Queries (领域隔离对象)
 * =========================================================
 */
const CONN_CHECK_TARGET = "https://www.gstatic.com/generate_204";
const DIAG_MAX_TEXT = 24000;
const DIAG_MAX_FILE = 32000;

function _diag_truncate(text, max_len) {
    text = text || "";
    max_len = max_len || DIAG_MAX_TEXT;
    if (length(text) > max_len)
        return substr(text, 0, max_len) + "\n...[truncated]";
    return text;
}

function _diag_file(path) {
    let exists = access(path);
    if (!exists) {
        return {
            exists: false,
            path: path,
            size: 0,
            truncated: false,
            raw: "",
            parse_error: ""
        };
    }

    let raw = readfile(path) || "";
    let truncated = length(raw) > DIAG_MAX_FILE;
    let out = truncated ? substr(raw, 0, DIAG_MAX_FILE) + "\n...[truncated]" : raw;

    return {
        exists: true,
        path: path,
        size: length(raw),
        truncated: truncated,
        raw: out,
        parse_error: ""
    };
}

function _diag_exec(cmd, args, trace_id) {
    let res = ExecSafe(cmd, args, { timeout: 4 }, trace_id);
    return {
        ok: !!res.ok,
        stdout: _diag_truncate((res.data && res.data.stdout) ? res.data.stdout : ""),
        stderr: _diag_truncate((res.data && res.data.stderr) ? res.data.stderr : ""),
        exit_code: (res.data && res.data.exit_code != null) ? res.data.exit_code : -1,
        error: res.ok ? "" : (res.detail || "command failed")
    };
}

function _diag_exec_sh(command, trace_id) {
    let res = ExecSafe(BIN.SH, ["-c", command], { timeout: 4 }, trace_id);
    return {
        ok: !!res.ok,
        stdout: _diag_truncate((res.data && res.data.stdout) ? res.data.stdout : ""),
        stderr: "",
        exit_code: (res.data && res.data.exit_code != null) ? res.data.exit_code : -1,
        error: res.ok ? "" : (res.detail || "command failed")
    };
}

function _gateway_curl(args, trace_id) {
    return ExecSafe(BIN.CURL, args, null, trace_id);
}

function _conn_site_to_path(site) {
    if (site === 'baidu' || site === 'direct') return 'direct';
    if (site === 'google' || site === 'proxy') return 'proxy';
    return null;
}

const NetworkQuery = {
    connection_check: function(args, trace_id) {
        let site = args.site;
        let path = _conn_site_to_path(site);
        if (!path) return Fail(ERR.E_SYSTEM_BUSY, 'Invalid target', trace_id);

        let curl_args = ["-s", "-m", "3", "-o", "/dev/null", "-w", "%{http_code}", CONN_CHECK_TARGET];
        if (path === 'proxy') {
            let px_res = proxy_inbound_available(trace_id);
            let px = (px_res.ok && px_res.data) ? px_res.data : { ok: false };
            if (!px.ok) {
                return Success({
                    result: false,
                    error: "proxy_unavailable",
                    path: "proxy",
                    target: CONN_CHECK_TARGET
                }, 200, trace_id);
            }
            push(curl_args, "-x", "socks5h://127.0.0.1:" + px.port);
        }

        let res = _gateway_curl(curl_args, trace_id);
        let code_str = (res.ok && res.data) ? trim(res.data.stdout || "") : "";
        let ok = (index(["200", "204"], code_str) !== -1);
        let payload = {
            result: ok,
            http_code: code_str || "Timeout",
            path: path,
            target: CONN_CHECK_TARGET
        };
        if (res.ok && res.data && res.data.exit_code != null) {
            payload.curl_exit = res.data.exit_code;
        }
        if (!ok && !res.ok) {
            payload.curl_exit = (res.data && res.data.exit_code != null) ? res.data.exit_code : -1;
        }
        return Success(payload, 200, trace_id);
    }
};

const SystemQuery = {
    _has_kmod: function(kmod, trace_id) {
        let uname_res = ExecSafe(BIN.SH, ["-c", "uname -r"], null, trace_id);
        let uname = (uname_res.ok && uname_res.data) ? trim(uname_res.data.stdout || "") : "";
        return access("/lib/modules/" + uname + "/" + kmod);
    },

    get_features: function(trace_id) {
        let features = { version: "unknown" };
        let res = ExecSafe(BIN.SINGBOX, ["version"], { timeout: 3 }, trace_id);
        
        if (res.ok && res.data && res.data.stdout) {
            let lines = split(res.data.stdout || "", "\n");
            for (let i = 0; i < length(lines); i++) {
                let v = match(lines[i], regexp('^sing-box version (.*)'));
                if (v) features.version = v[1];
                let t = match(lines[i], regexp('^Tags: (.*)'));
                if (t) {
                    let tags = split(t[1], ',');
                    for (let j = 0; j < length(tags); j++) features[trim(tags[j])] = true;
                }
            }
        }
        
        features.fp_has_ip_full = access('/usr/libexec/ip-full');
        features.fp_has_tcp_brutal = this._has_kmod('brutal.ko', trace_id);
        features.fp_has_tproxy = this._has_kmod('nft_tproxy.ko', trace_id) || access('/etc/modules.d/nft-tproxy');
        features.fp_has_tun = this._has_kmod('tun.ko', trace_id) || access('/etc/modules.d/30-tun');
        
        return Success(features, 200, trace_id);
    },

    get_uci_proxy_mode: function(args, trace_id) {
        let u = cursor();
        u.load("flowproxy");
        let mode = u.get("flowproxy", "config", "proxy_mode") || u.get("flowproxy", "routing", "proxy_mode") || "redirect_tproxy";
        if (mode === "redirect" || mode === "redirect_tproxy") mode = "redirect_tproxy";
        else if (mode === "redirect_tun" || mode === "tun") mode = "tun";

        return Success({ proxy_mode: mode }, 200, trace_id);
    },

    get_urltest_status: function(args, trace_id) {
        return Success(get_urltest_status(trace_id), 200, trace_id);
    },

    get_runtime_artifacts: function(args, trace_id) {
        return Success({
            updated_at: time(),
            run: _diag_file(PATH.RUN_JSON),
            candidate: _diag_file(sprintf("%s/sing-box-run.candidate.json", PATH.RUNTIME)),
            prev: _diag_file(sprintf("%s/sing-box-run.prev.json", PATH.RUNTIME))
        }, 200, trace_id);
    },

    get_network_state: function(args, trace_id) {
        return Success({
            updated_at: time(),
            nft: _diag_exec(BIN.NFT, ["list", "ruleset"], trace_id),
            ip_rule: _diag_exec_sh("ip rule show", trace_id),
            route: _diag_exec_sh("ip route show table all", trace_id),
            route6: _diag_exec_sh("ip -6 route show table all", trace_id),
            link: _diag_exec_sh("ip link show", trace_id)
        }, 200, trace_id);
    },

    singbox_check_readonly: function(args, trace_id) {
        let target = PATH.RUN_JSON;
        if (!access(target)) {
            return Success({
                valid: false,
                status: "not_available",
                path: target,
                output: "",
                error: "run.json missing"
            }, 200, trace_id);
        }

        let res = _diag_exec(BIN.SINGBOX, ["check", "-c", target], trace_id);
        return Success({
            valid: !!res.ok,
            status: res.ok ? "ok" : "failed",
            path: target,
            output: res.stdout,
            stderr: res.stderr,
            exit_code: res.exit_code,
            error: res.error
        }, 200, trace_id);
    },

    version_check: function(trace_id) {
        let local_res = this.get_features(trace_id);
        let local = local_res.ok ? local_res.data.version : "unknown";
        let stable = "unknown";
        let beta = "unknown";

        let u = cursor();
        u.load("flowproxy");
        let token = u.get("flowproxy", "config", "github_token") || "";

        let build_curl_args = function(target_url) {
            let args = ["-sSLf", "--connect-timeout", "5"];
            push(args, "-H");
            push(args, "User-Agent: FlowProxy-OpenWrt-Gateway/1.0");
            if (token) {
                push(args, "-H");
                push(args, "Authorization: token " + token);
            }
            push(args, target_url);
            return args;
        };

        let url_stable = "https://api.github.com/repos/SagerNet/sing-box/releases/latest";
        let res_stable = _gateway_curl(build_curl_args(url_stable), trace_id);
        
        if (res_stable.ok && res_stable.data && res_stable.data.stdout) {
            try {
                let d = json(res_stable.data.stdout);
                if (d && d.tag_name) stable = replace(d.tag_name, regexp('^v'), "");
            } catch(e) {
                log(trace_id, 'WARN', 'SYSTEM', 'Stable release JSON parse failed: ' + e);
            }
        } else {
            log(trace_id, 'WARN', 'SYSTEM', 'Failed to fetch Stable API. Check network or token validity.');
        }

        let url_beta = "https://api.github.com/repos/SagerNet/sing-box/releases?per_page=5";
        let res_beta = _gateway_curl(build_curl_args(url_beta), trace_id);
        
        if (res_beta.ok && res_beta.data && res_beta.data.stdout) {
            try {
                let d2 = json(res_beta.data.stdout);
                if (type(d2) === "array") {
                    for (let i = 0; i < length(d2); i++) {
                        if (d2[i] && d2[i].prerelease === true && d2[i].tag_name) {
                            beta = replace(d2[i].tag_name, regexp('^v'), "");
                            break; 
                        }
                    }
                }
            } catch(e) {
                log(trace_id, 'WARN', 'SYSTEM', 'Beta release JSON parse failed: ' + e);
            }
        } else {
            log(trace_id, 'WARN', 'SYSTEM', 'Failed to fetch Beta API. Check network or token validity.');
        }
        
        return Success({ local: local, stable: stable, beta: beta }, 200, trace_id);
    }
};

const CryptoQuery = {
    generate: function(args, trace_id) {
        let t = args.type;
        if (t === 'uuid') {
            let res = ExecSafe(BIN.SH, ["-c", "uuidgen"], { timeout: 2 }, trace_id);
            let out = (res.ok && res.data) ? res.data.stdout : "";
            return Success({ result: trim(out) }, 200, trace_id);
        } 
        if (t === 'reality-keypair') {
            let res = ExecSafe(BIN.SINGBOX, ["generate", "reality-keypair"], { timeout: 3 }, trace_id);
            if (res.ok && res.data) {
                // 🚨 终极修复 2: 强行赋予默认空字符串，彻底免疫 Null Pointer Exception (空指针地雷)
                let safe_stdout = res.data.stdout || "";
                let priv = match(safe_stdout, regexp('PrivateKey: ([a-zA-Z0-9_-]+)'));
                let pub = match(safe_stdout, regexp('PublicKey: ([a-zA-Z0-9_-]+)'));
                if (priv && pub) return Success({ result: { private_key: priv[1], public_key: pub[1] } }, 200, trace_id);
            }
            return Fail(ERR.E_SYSTEM_BUSY, "Gen reality-keypair failed", trace_id);
        } 
        if (t === 'ech-keypair') {
            let raw_domain = args.params || 'example.com';
            let res = ExecSafe(BIN.SINGBOX, ["generate", "ech-keypair", raw_domain], { timeout: 3 }, trace_id);
            if (res.ok && res.data) {
                // 🚨 终极修复 2: 强行赋予默认空字符串，免疫空指针崩溃
                let safe_stdout = res.data.stdout || "";
                let parts = split(safe_stdout, "\n\n");
                if (length(parts) >= 2) return Success({ result: { ech_key: trim(parts[0]), ech_cfg: trim(parts[1]) } }, 200, trace_id);
            }
            return Fail(ERR.E_SYSTEM_BUSY, "Gen ech-keypair failed", trace_id);
        }
        return Fail(ERR.E_SYSTEM_BUSY, "Unsupported type", trace_id);
    }
};

const FileQuery = {
    acllist_read: function(args, trace_id) {
        if (index(['direct_list', 'proxy_list'], args.type) === -1) return Fail(ERR.E_SYSTEM_BUSY, 'illegal type', trace_id);
        return Success({ content: readfile(sprintf("%s/%s.txt", PATH.ASSETS, args.type)) }, 200, trace_id);
    },

    acllist_write: function(args, trace_id) {
        if (index(['direct_list', 'proxy_list'], args.type) === -1) return Fail(ERR.E_SYSTEM_BUSY, 'illegal type', trace_id);
        let content = replace(trim(args.content || ""), regexp('\\r\\n?', 'g'), '\n');
        if (length(content) > 0 && !match(content, regexp('\\n$'))) content += '\n';
        ExecSafe(BIN.MKDIR, ["-p", PATH.ASSETS], null, trace_id);
        let is_ok = writefile(sprintf("%s/%s.txt", PATH.ASSETS, args.type), content);
        return Success({ result: is_ok }, 200, trace_id);
    },

    get_res_version: function(args, trace_id) {
        if (!match(args.type, regexp('^[a-z0-9_]+$'))) return Fail(ERR.E_SYSTEM_BUSY, 'invalid type', trace_id);
        let v = readfile(sprintf("%s/%s.ver", PATH.ASSETS, args.type));
        return Success({ version: trim(v || "Unknown") }, 200, trace_id);
    },

    log_read_runtime: function(args, trace_id) {
        let t = args.type || "system";
        let path = "";

        if (t === "system" || t === "flowproxy" || t === "main") {
            path = PATH.LOG_SYS;
        } else if (t === "sing-box") {
            path = PATH.LOG_RUN;
        } else if (t === "job") {
            path = sprintf("%s/worker.log", PATH.JOB);
        } else if (match(t, regexp('^job_[a-zA-Z0-9_-]+$'))) {
            path = sprintf("%s/%s.log", PATH.JOB, t);
        } else {
            return Success({
                type: t,
                exists: false,
                content: "",
                error: "unsupported log type"
            }, 200, trace_id);
        }

        let file = _diag_file(path);
        return Success({
            type: t,
            exists: file.exists,
            path: file.path,
            size: file.size,
            truncated: file.truncated,
            content: file.raw,
            error: file.exists ? "" : "not found"
        }, 200, trace_id);
    },

    log_clean: function(args, trace_id) {
        try {
            let t = args.type;
            let path = "";

            if (index(['system', 'sing-box', 'flowproxy', 'main'], t) !== -1) {
                let filename = (t === 'sing-box') ? 'sing-box.log' : 'system.log';
                path = sprintf("%s/%s", PATH.LOG_DIR, filename); 
            } else if (match(t, regexp('^[a-zA-Z0-9_-]+$'))) { 
                path = sprintf("%s/%s.log", PATH.JOB, t);
            }

            if (path && lstat(path)) { 
                let fd = fs_open(path, "w");
                if (!fd) {
                    log(trace_id, 'ERROR', 'GATEWAY', 'Failed to open log file fd for truncation: ' + path);
                    return Success({ result: false }, 200, trace_id);
                }
                fd.write(""); 
                fd.close(); 
                
                log(trace_id, 'INFO', 'GATEWAY', sprintf('Log file at [%s] atomically truncated via RPC.', path));
                return Success({ result: true }, 200, trace_id); 
            }
            return Success({ result: false }, 200, trace_id);
        } catch(e) {
            let err_msg = "" + e;
            log(trace_id, 'CRIT', 'GATEWAY', 'Log clean RPC action crashed: ' + err_msg);
            return Success({ result: false, error: err_msg }, 200, trace_id);
        }
    }
};

const JobQuery = {
    log_read: function(args, trace_id) {
        let q = parse_job_query_envelope(args, trace_id);
        if (!q.ok) return q;
        let job_id = q.data.job_id;
        let cursor_pos = int(args.cursor) || 0;

        if (type(cursor_pos) !== 'int') return Success({ lines: [], next_cursor: cursor_pos, eof: true }, 200, trace_id);

        let fd = fs_open(sprintf("%s/%s.log", PATH.JOB, job_id), 'r');
        if (!fd) {
            let stat_res = get_status(job_id, trace_id);
            let is_eof = !!(stat_res.ok && stat_res.data && index(['success', 'fail', 'rollback'], stat_res.data.state) !== -1);
            return Success({ lines: [], next_cursor: cursor_pos, eof: is_eof }, 200, trace_id);
        }

        fd.seek(cursor_pos, 'set');
        let chunk = fd.read(LIMIT.MAX_READ);
        let pos = fd.tell();
        fd.close();

        if (!chunk || length(chunk) === 0) {
            let stat_res = get_status(job_id, trace_id);
            let is_eof = !!(stat_res.ok && stat_res.data && index(['success', 'fail', 'rollback'], stat_res.data.state) !== -1);
            return Success({ lines: [], next_cursor: pos, eof: is_eof }, 200, trace_id);
        }

        return Success({ lines: split(chunk, '\n'), next_cursor: pos, eof: false }, 200, trace_id);
    }
};

const QueryService = {
    handle: function(domain_name, action, args, trace_id) {
        try {
            let targetDomain;
            switch (domain_name) {
                case "network": targetDomain = NetworkQuery; break;
                case "system":  targetDomain = SystemQuery; break;
                case "crypto":  targetDomain = CryptoQuery; break;
                case "file":    targetDomain = FileQuery; break;
                case "job":     targetDomain = JobQuery; break;
                default: return Fail(ERR.E_SYSTEM_BUSY, "Unknown domain", trace_id);
            }

            if (type(targetDomain[action]) !== 'function') {
                return Fail(ERR.E_SYSTEM_BUSY, "Invalid action or boundary violation", trace_id);
            }

            return targetDomain[action](args, trace_id);
        } catch (e) {
            let err_msg = "" + e;
            log(trace_id, 'CRIT', 'GATEWAY', 'Kernel Error: ' + err_msg);
            return Fail(ERR.E_SYSTEM_BUSY, "Kernel Error: " + err_msg, trace_id);
        }
    }
};

/**
 * =========================================================
 * 📡 L4: RPC Gateway (API 透传暴露)
 * 🚨 核心防线：全量包裹 try...catch，杜绝任何底层崩溃引发 C 层 Unknown Error
 * =========================================================
 */
const job_methods = {
    start: { 
        args: { type: "", payload: {} }, 
        call: function(req) { 
            let trace_id = "pending_req";
            try {
                trace_id = gen_trace_id();
                let env = parse_job_start_envelope(req, trace_id);
                if (!env.ok) return env;
                let job_type = env.data.type;
                if (!JOB_TYPES[job_type]) {
                    log(trace_id, 'WARN', 'GATEWAY', 'Auth Denied: Invalid Job Type - ' + job_type);
                    return Fail(ERR.E_AUTH_DENIED, "Invalid Job Type: " + job_type, trace_id);
                }
                return dispatch(job_type, env.data.payload, trace_id); 
            } catch(e) {
                return Fail(ERR.E_SYSTEM_BUSY, "Gateway Crash: " + ("" + e), trace_id);
            }
        } 
    },
    status: { 
        args: { job_id: "" }, 
        call: function(req) { 
            let trace_id = "pending_req";
            try {
                trace_id = gen_trace_id();
                return get_status(req, trace_id); 
            } catch(e) {
                return Fail(ERR.E_SYSTEM_BUSY, "Gateway Crash: " + ("" + e), trace_id);
            }
        } 
    },
    log: { 
        args: { job_id: "", cursor: 32 }, 
        call: function(req) { 
            let trace_id = "pending_req";
            try {
                trace_id = gen_trace_id();
                return QueryService.handle("job", "log_read", req.args || req, trace_id); 
            } catch(e) {
                return Fail(ERR.E_SYSTEM_BUSY, "Gateway Crash: " + ("" + e), trace_id);
            }
        } 
    }
};

const system_methods = {
    status: { 
        call: function() { 
            let trace_id = "pending_req";
            try {
                trace_id = gen_trace_id();
                if (!SYSTEM_METHODS["status"]) return Fail(ERR.E_AUTH_DENIED, "E_INVALID_API: status", trace_id);
                return StateManager.snapshot(trace_id); 
            } catch(e) {
                return Fail(ERR.E_SYSTEM_BUSY, "Gateway Crash: " + ("" + e), trace_id);
            }
        } 
    },
    connection_check: { 
        args: { site: "" }, 
        call: function(req) { 
            let trace_id = "pending_req";
            try {
                trace_id = gen_trace_id();
                if (!SYSTEM_METHODS["connection_check"]) return Fail(ERR.E_AUTH_DENIED, "E_INVALID_API: connection_check", trace_id);
                return QueryService.handle("network", "connection_check", req.args || req, trace_id); 
            } catch(e) {
                return Fail(ERR.E_SYSTEM_BUSY, "Gateway Crash: " + ("" + e), trace_id);
            }
        } 
    },
    singbox_get_features: { 
        call: function() { 
            let trace_id = "pending_req";
            try {
                trace_id = gen_trace_id();
                if (!SYSTEM_METHODS["singbox_get_features"]) return Fail(ERR.E_AUTH_DENIED, "E_INVALID_API", trace_id);
                return QueryService.handle("system", "get_features", {}, trace_id); 
            } catch(e) {
                return Fail(ERR.E_SYSTEM_BUSY, "Gateway Crash: " + ("" + e), trace_id);
            }
        } 
    },
    kernel_version_check: { 
        call: function() { 
            let trace_id = "pending_req";
            try {
                trace_id = gen_trace_id();
                if (!SYSTEM_METHODS["kernel_version_check"]) return Fail(ERR.E_AUTH_DENIED, "E_INVALID_API", trace_id);
                return QueryService.handle("system", "version_check", {}, trace_id); 
            } catch(e) {
                return Fail(ERR.E_SYSTEM_BUSY, "Gateway Crash: " + ("" + e), trace_id);
            }
        } 
    },
    get_uci_proxy_mode: {
        call: function() {
            let trace_id = "pending_req";
            try {
                trace_id = gen_trace_id();
                if (!SYSTEM_METHODS["get_uci_proxy_mode"]) return Fail(ERR.E_AUTH_DENIED, "E_INVALID_API: get_uci_proxy_mode", trace_id);
                return QueryService.handle("system", "get_uci_proxy_mode", {}, trace_id);
            } catch(e) {
                return Fail(ERR.E_SYSTEM_BUSY, "Gateway Crash: " + ("" + e), trace_id);
            }
        }
    },
    get_urltest_status: {
        call: function() {
            let trace_id = "pending_req";
            try {
                trace_id = gen_trace_id();
                if (!SYSTEM_METHODS["get_urltest_status"]) return Fail(ERR.E_AUTH_DENIED, "E_INVALID_API: get_urltest_status", trace_id);
                return QueryService.handle("system", "get_urltest_status", {}, trace_id);
            } catch(e) {
                return Success({
                    updated_at: time(),
                    status: "api_unavailable",
                    detail: "Gateway Crash: " + ("" + e),
                    items: {}
                }, 200, trace_id);
            }
        }
    },
    get_runtime_artifacts: {
        call: function() {
            let trace_id = "pending_req";
            try {
                trace_id = gen_trace_id();
                if (!SYSTEM_METHODS["get_runtime_artifacts"]) return Fail(ERR.E_AUTH_DENIED, "E_INVALID_API: get_runtime_artifacts", trace_id);
                return QueryService.handle("system", "get_runtime_artifacts", {}, trace_id);
            } catch(e) {
                return Fail(ERR.E_SYSTEM_BUSY, "Gateway Crash: " + ("" + e), trace_id);
            }
        }
    },
    log_read_runtime: {
        args: { type: "" },
        call: function(req) {
            let trace_id = "pending_req";
            try {
                trace_id = gen_trace_id();
                if (!SYSTEM_METHODS["log_read_runtime"]) return Fail(ERR.E_AUTH_DENIED, "E_INVALID_API: log_read_runtime", trace_id);
                return QueryService.handle("file", "log_read_runtime", req.args || req, trace_id);
            } catch(e) {
                return Fail(ERR.E_SYSTEM_BUSY, "Gateway Crash: " + ("" + e), trace_id);
            }
        }
    },
    get_network_state: {
        call: function() {
            let trace_id = "pending_req";
            try {
                trace_id = gen_trace_id();
                if (!SYSTEM_METHODS["get_network_state"]) return Fail(ERR.E_AUTH_DENIED, "E_INVALID_API: get_network_state", trace_id);
                return QueryService.handle("system", "get_network_state", {}, trace_id);
            } catch(e) {
                return Fail(ERR.E_SYSTEM_BUSY, "Gateway Crash: " + ("" + e), trace_id);
            }
        }
    },
    singbox_check_readonly: {
        call: function() {
            let trace_id = "pending_req";
            try {
                trace_id = gen_trace_id();
                if (!SYSTEM_METHODS["singbox_check_readonly"]) return Fail(ERR.E_AUTH_DENIED, "E_INVALID_API: singbox_check_readonly", trace_id);
                return QueryService.handle("system", "singbox_check_readonly", {}, trace_id);
            } catch(e) {
                return Fail(ERR.E_SYSTEM_BUSY, "Gateway Crash: " + ("" + e), trace_id);
            }
        }
    },
    singbox_generator: { 
        args: { type: "", params: "" }, 
        call: function(req) { 
            let trace_id = "pending_req";
            try {
                trace_id = gen_trace_id();
                if (!SYSTEM_METHODS["singbox_generator"]) return Fail(ERR.E_AUTH_DENIED, "E_INVALID_API", trace_id);
                return QueryService.handle("crypto", "generate", req.args || req, trace_id); 
            } catch(e) {
                return Fail(ERR.E_SYSTEM_BUSY, "Gateway Crash: " + ("" + e), trace_id);
            }
        } 
    },
    acllist_read: { 
        args: { type: "" }, 
        call: function(req) { 
            let trace_id = "pending_req";
            try {
                trace_id = gen_trace_id();
                if (!SYSTEM_METHODS["acllist_read"]) return Fail(ERR.E_AUTH_DENIED, "E_INVALID_API", trace_id);
                return QueryService.handle("file", "acllist_read", req.args || req, trace_id); 
            } catch(e) {
                return Fail(ERR.E_SYSTEM_BUSY, "Gateway Crash: " + ("" + e), trace_id);
            }
        } 
    },
    acllist_write: { 
        args: { type: "", content: "" }, 
        call: function(req) { 
            let trace_id = "pending_req";
            try {
                trace_id = gen_trace_id();
                if (!SYSTEM_METHODS["acllist_write"]) return Fail(ERR.E_AUTH_DENIED, "E_INVALID_API", trace_id);
                return QueryService.handle("file", "acllist_write", req.args || req, trace_id); 
            } catch(e) {
                return Fail(ERR.E_SYSTEM_BUSY, "Gateway Crash: " + ("" + e), trace_id);
            }
        } 
    },

    resources_get_version: {
        args: { type: "" }, 
        call: function(req) {
            let trace_id = "pending_req";
            try {
                trace_id = gen_trace_id();
                // 🚨 终极修复 1: 填补漏网之鱼，补齐契约鉴权拦截，保障系统绝对安全
                if (!SYSTEM_METHODS["resources_get_version"]) return Fail(ERR.E_AUTH_DENIED, "E_INVALID_API: resources_get_version", trace_id);
                return QueryService.handle("file", "get_res_version", req.args || req, trace_id);
            } catch(e) {
                return Fail(ERR.E_SYSTEM_BUSY, "Gateway Crash: " + ("" + e), trace_id);
            }
        }
    },

    log_clean: {
        args: { type: "" },
        call: function(req) {
            let trace_id = "pending_req";
            try {
                trace_id = gen_trace_id();
                // 🚨 终极修复 1: 填补契约鉴权
                if (!SYSTEM_METHODS["log_clean"]) return Fail(ERR.E_AUTH_DENIED, "E_INVALID_API: log_clean", trace_id);
                return QueryService.handle("file", "log_clean", req.args || req, trace_id);
            } catch(e) {
                return Fail(ERR.E_SYSTEM_BUSY, "Gateway Crash: " + ("" + e), trace_id);
            }
        }
    }
};

/**
 * 🚨 宪法修正：彻底剥离包装，回归最原始的扁平 Ubus 方法字典映射。
 * 严禁使用 export。
 */
return {
    'flowproxy.job': job_methods,
    'flowproxy.system': system_methods
};
