/**
 * FlowProxy | modules/protocols/shadowsocks.uc
 * Shadowsocks subscription URI parser.
 */

'use strict';

import {
    _decode_base64_str,
    _parse_url,
    _urldecode
} from 'flowproxy.modules.protocols.common';

function parse(ctx) {
    let raw_uri = ctx.raw_uri || "";
    let url = ctx.url;
    let parts = split(raw_uri, '://');
    let ss_parts, full_dec, full_url, up, dec;
    let config = null;

    dec = _decode_base64_str(url.username);
    if (!dec && length(url.hostname) > 20) {
        full_dec = _decode_base64_str(url.hostname);
        if (full_dec) {
            full_url = _parse_url("ss://" + full_dec);
            if (full_url) {
                up = split(full_url.username, ':');
                config = {
                    label: "",
                    type: 'shadowsocks',
                    address: full_url.hostname,
                    port: full_url.port,
                    shadowsocks_encrypt_method: up[0] || "",
                    password: up[1] || ""
                };
            }
        }
    } else if (dec) {
        up = split(dec, ':');
        config = {
            label: "",
            type: 'shadowsocks',
            address: url.hostname,
            port: url.port,
            shadowsocks_encrypt_method: up[0] || "",
            password: up[1] || ""
        };
    }

    if (config) {
        ss_parts = split(parts[1], '#');
        config.label = (length(ss_parts) >= 2) ? _urldecode(ss_parts[1]) : "";
    }

    return config ? { config: config, probe_stage: "", target: null } : null;
}

export { parse };
