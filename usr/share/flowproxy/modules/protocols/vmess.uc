/**
 * FlowProxy | modules/protocols/vmess.uc
 * VMess subscription URI parser.
 */

'use strict';

import {
    _decode_base64_str,
    _urldecode
} from 'flowproxy.modules.protocols.common';

function parse(ctx) {
    let raw_uri = ctx.raw_uri || "";
    let parts = split(raw_uri, '://');
    let v_json = null;
    let config = null;

    try { v_json = json(_decode_base64_str(parts[1])); } catch(e) {}
    if (v_json && v_json.v == '2') {
        config = {
            label: v_json.ps ? _urldecode(v_json.ps) : "",
            type: 'vmess',
            address: v_json.add,
            port: v_json.port + "",
            uuid: v_json.id,
            vmess_alterid: v_json.aid + "",
            vmess_encrypt: v_json.scy || 'auto',
            transport: (v_json.net !== 'tcp') ? (v_json.net || "") : "",
            tls: (v_json.tls === 'tls') ? '1' : '0',
            tls_sni: v_json.sni || v_json.host || "",
            tls_utls: v_json.fp || ""
        };

        if (v_json.net === 'ws') {
            config.ws_host = v_json.host || "";
            config.ws_path = v_json.path || "";
            let ed_idx = index(config.ws_path, "?ed=");
            if (ed_idx >= 0) {
                config.websocket_early_data_header = 'Sec-WebSocket-Protocol';
                config.websocket_early_data = substr(config.ws_path, ed_idx + 4);
                config.ws_path = substr(config.ws_path, 0, ed_idx);
            }
        } else if (v_json.net === 'grpc') {
            config.grpc_servicename = v_json.path || "";
        }
    }

    return config ? { config: config, probe_stage: "", target: null } : null;
}

export { parse };
