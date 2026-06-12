/**
 * FlowProxy | modules/protocols/common.uc
 * Protocol parsing common helpers.
 *
 * Phase 1 baseline extraction only: implementations are copied from
 * modules/subscription.uc without behavior changes.
 */

'use strict';

function _generate_stable_id(str) {
    let h1 = 0x12345678, h2 = 0x87654321, h3 = 0x9abcdef0, h4 = 0x0fedcba9;
    for (let i = 0; i < length(str); i++) {
        let c = ord(substr(str, i, 1));
        h1 = ((h1 * 33) + c) % 4294967296;
        h2 = ((h2 * 65599) + c) % 4294967296;
        h3 = ((h3 * 31) + c) % 4294967296;
        h4 = ((h4 * 17) + c) % 4294967296;
    }
    return sprintf("%08x%08x%08x%08x", h1, h2, h3, h4);
}

function _decode_base64_str(str) {
    if (!str) return null;
    
    // 1. Normalize URL-safe base64 alphabet.
    let s = replace(replace(str, regexp('-', 'g'), '+'), regexp('_', 'g'), '/');
    
    // 2. Strip non-base64 characters.
    s = replace(s, regexp('[^A-Za-z0-9+/=]', 'g'), ""); 
    
    // 3. Add missing padding for ucode b64dec().
    let mod = length(s) % 4;
    if (mod === 2) {
        s += "==";
    } else if (mod === 3) {
        s += "=";
    }
    
    try { 
        return b64dec(s); 
    } catch(e) { 
        return null; 
    }
}

function _urldecode(str) {
    if (type(str) !== 'string') return "";
    let res = replace(str, '+', ' ');
    let hex_map = { '0':0, '1':1, '2':2, '3':3, '4':4, '5':5, '6':6, '7':7, '8':8, '9':9, 'A':10, 'B':11, 'C':12, 'D':13, 'E':14, 'F':15, 'a':10, 'b':11, 'c':12, 'd':13, 'e':14, 'f':15 };
    return replace(res, regexp('%([0-9a-fA-F]{2})', 'g'), function(m, h) {
        let d = hex_map[substr(h, 0, 1)] * 16 + hex_map[substr(h, 1, 1)];
        return sprintf("%c", d);
    });
}

function _parse_url(url_string) {
    let res = { protocol: "", username: "", password: "", hostname: "", port: "", searchParams: {}, hash: "" };
    let idx = index(url_string, "://");
    if (idx < 0) return null;
    res.protocol = substr(url_string, 0, idx);
    let payload = substr(url_string, idx + 3);
    
    // 1. Normalize URL-safe base64 alphabet.
    let hash_idx = index(payload, "#");
    if (hash_idx >= 0) {
        res.hash = _urldecode(substr(payload, hash_idx + 1));
        payload = substr(payload, 0, hash_idx);
    }
    
    // 2. Strip non-base64 characters.
    let qs_idx = index(payload, "?");
    if (qs_idx >= 0) {
        let qs = substr(payload, qs_idx + 1);
        payload = substr(payload, 0, qs_idx);
        let pairs = split(qs, "&");
        for (let i = 0; i < length(pairs); i++) {
            let kv = split(pairs[i], "=");
            if (length(kv) == 2) res.searchParams[_urldecode(kv[0])] = _urldecode(kv[1]);
        }
    }
    
    // 3. Add missing padding for ucode b64dec().
    if (substr(payload, length(payload) - 1, 1) === "/") {
        payload = substr(payload, 0, length(payload) - 1);
    }
    
    let auth_idx = index(payload, "@");
    let host_port = payload;
    if (auth_idx >= 0) {
        let auth = substr(payload, 0, auth_idx);
        host_port = substr(payload, auth_idx + 1);
        let up_idx = index(auth, ":");
        if (up_idx >= 0) {
            res.username = _urldecode(substr(auth, 0, up_idx));
            res.password = _urldecode(substr(auth, up_idx + 1));
        } else {
            res.username = _urldecode(auth);
        }
    }
    
    if (substr(host_port, 0, 1) === "[") {
        let close_idx = index(host_port, "]");
        if (close_idx > 0) {
            res.hostname = substr(host_port, 1, close_idx - 1);
            let remainder = substr(host_port, close_idx + 1);
            if (substr(remainder, 0, 1) === ":") res.port = substr(remainder, 1);
        }
    } else {
        let colon_idx = index(host_port, ":");
        if (colon_idx >= 0) {
            res.hostname = substr(host_port, 0, colon_idx);
            res.port = substr(host_port, colon_idx + 1);
        } else {
            res.hostname = host_port;
        }
    }
    
    if (!res.port) res.port = "80"; 
    // 濞撳懐鎮婄粩顖氬經娑擃厼褰查懗鑺ョ暙閻ｆ瑧娈戦崹鍐ㄦ簢鐎涙顑?
    res.port = replace(res.port, regexp('[^0-9]', 'g'), '');
    return res;
}

function _first_param(params, keys) {
    params = params || {};
    for (let i = 0; i < length(keys); i++) {
        let v = params[keys[i]];
        if (v != null && length(trim(sprintf("%s", v))) > 0) return trim(sprintf("%s", v));
    }
    return "";
}

function _split_host_port(raw_host, fallback_port) {
    let out = {
        host: trim(sprintf("%s", raw_host || "")),
        port: fallback_port || ""
    };

    if (length(out.host) === 0) return out;

    if (substr(out.host, 0, 1) === "[") {
        let close_idx = index(out.host, "]");
        if (close_idx > 0) {
            let inner_host = substr(out.host, 1, close_idx - 1);
            let remainder = substr(out.host, close_idx + 1);
            if (substr(remainder, 0, 1) === ":") {
                let p = replace(substr(remainder, 1), regexp('[^0-9]', 'g'), '');
                if (length(p) > 0) out.port = p;
            }
            out.host = inner_host;
        }
        return out;
    }

    let colon_idx = index(out.host, ":");
    if (colon_idx >= 0 && index(substr(out.host, colon_idx + 1), ":") < 0) {
        let tail = substr(out.host, colon_idx + 1);
        let p = replace(tail, regexp('[^0-9]', 'g'), '');
        if (length(p) > 0 && length(p) === length(tail)) {
            out.host = substr(out.host, 0, colon_idx);
            out.port = p;
        }
    }

    return out;
}

function _resolve_server_target(url, params, scheme, transport) {
    let raw = _first_param(params, [ "server", "address", "add", "remote", "endpoint" ]);
    let source = "explicit";

    /*
     * Some converters put the real dial target in host for URI-style AnyTLS or
     * plain TCP links. Do not use host for WS/HTTP transports by default,
     * because there it normally means the HTTP Host header.
     */
    if (!raw) {
        let allow_host = (scheme === "anytls" || scheme === "tuic" || scheme === "hysteria2" || scheme === "hy2");
        if ((scheme === "trojan" || scheme === "vless") && (!transport || transport === "tcp")) {
            allow_host = true;
        }
        if (allow_host) {
            raw = _first_param(params, [ "host" ]);
            source = "host";
        }
    }

    if (!raw) {
        return {
            host: url ? (url.hostname || "") : "",
            port: url ? (url.port || "") : "",
            source: "authority"
        };
    }

    let hp = _split_host_port(raw, url ? (url.port || "") : "");
    hp.source = source;
    return hp;
}

export {
    _urldecode,
    _decode_base64_str,
    _parse_url,
    _first_param,
    _split_host_port,
    _resolve_server_target,
    _generate_stable_id
};
