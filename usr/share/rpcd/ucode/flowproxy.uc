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
import { dispatch, get_status } from 'flowproxy.core.job';
import { ExecSafe } from 'flowproxy.core.utils';
import { StateManager } from 'flowproxy.runtime.state';

/**
 * =========================================================
 * 🧩 L2: Domain Queries (领域隔离对象)
 * =========================================================
 */
const NetworkQuery = {
    connection_check: function(args, trace_id) {
        let site = args.site;
        if (site !== 'baidu' && site !== 'google') return Fail(ERR.E_SYSTEM_BUSY, 'Invalid target', trace_id);

        let res;
        if (site === 'baidu') {
            res = ExecSafe(BIN.CURL, ["-I", "-s", "-m", "3", "-o", "/dev/null", "-w", "%{http_code}", "https://www.baidu.com"], null, trace_id);
        } else {
            let proxy_port = "5330";
            let u = cursor();
            u.load("flowproxy");
            u.foreach("flowproxy", "server", function(s) {
                if (s.enabled === '1' && (s.type === 'mixed' || s.type === 'socks')) {
                    proxy_port = s.port || "5330";
                    return false; 
                }
            });
            let proxy_url = "socks5h://127.0.0.1:" + proxy_port;
            res = ExecSafe(BIN.CURL, ["-I", "-s", "-m", "3", "-o", "/dev/null", "-w", "%{http_code}", "-x", proxy_url, "https://www.google.com"], null, trace_id);
        }

        let code_str = (res.ok && res.data) ? trim(res.data.stdout || "") : "";
        let ok = (index(["200", "204", "301", "302"], code_str) !== -1);
        return Success({ result: ok, http_code: code_str || "Timeout" }, 200, trace_id);
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
        let res_stable = ExecSafe(BIN.CURL, build_curl_args(url_stable), null, trace_id);
        
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
        let res_beta = ExecSafe(BIN.CURL, build_curl_args(url_beta), null, trace_id);
        
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
        let job_id = args.job_id;
        // 🚨 终极修复 3: 显式进行 int() 强转，粉碎 JSON 反序列化带来的隐性类型陷阱 (Type Casting Trap)
        let cursor_pos = int(args.cursor) || 0;

        if (type(job_id) !== 'string' || type(cursor_pos) !== 'int') return Success({ lines: [], next_cursor: cursor_pos, eof: true }, 200, trace_id);
        if (!match(job_id, regexp('^[a-zA-Z0-9_-]+$'))) return Success({ lines: [], next_cursor: cursor_pos, eof: true }, 200, trace_id);

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
                let r = req.args || req;
                if (!JOB_TYPES[r.type]) {
                    log(trace_id, 'WARN', 'GATEWAY', 'Auth Denied: Invalid Job Type - ' + r.type);
                    return Fail(ERR.E_AUTH_DENIED, "Invalid Job Type Dispatch Attempt", trace_id);
                }
                return dispatch(r.type, r.payload, trace_id); 
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
                return get_status((req.args || req).job_id, trace_id); 
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
                if (!SYSTEM_METHODS["singbox_features"]) return Fail(ERR.E_AUTH_DENIED, "E_INVALID_API", trace_id);
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
                if (!SYSTEM_METHODS["kernel_version"]) return Fail(ERR.E_AUTH_DENIED, "E_INVALID_API", trace_id);
                return QueryService.handle("system", "version_check", {}, trace_id); 
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
