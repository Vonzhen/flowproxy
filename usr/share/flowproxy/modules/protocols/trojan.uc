/**
 * FlowProxy | modules/protocols/trojan.uc
 * Trojan subscription URI parser.
 */

'use strict';

import { _resolve_server_target } from 'flowproxy.modules.protocols.common';

function parse(ctx) {
    let url = ctx.url;
    let params = ctx.params || {};
    let scheme = ctx.scheme || "trojan";
    let transport = (params.type && params.type !== 'tcp') ? params.type : "";
    let server_target = _resolve_server_target(url, params, scheme, params.type || "");
    let config = {
        label: ctx.default_label || "",
        type: 'trojan',
        address: server_target.host,
        port: server_target.port,
        password: url.username,
        transport: transport,
        tls: '1',
        tls_sni: params.sni || "",
        tls_utls: params.fp || "",
        tls_insecure: ctx.is_insec || "0"
    };

    if (params.type === 'ws') {
        config.ws_host = params.host || "";
        config.ws_path = params.path || "";
        let ed_idx = index(config.ws_path, "?ed=");
        if (ed_idx >= 0) {
            config.websocket_early_data_header = 'Sec-WebSocket-Protocol';
            config.websocket_early_data = substr(config.ws_path, ed_idx + 4);
            config.ws_path = substr(config.ws_path, 0, ed_idx);
        }
    } else if (params.type === 'grpc') {
        config.grpc_servicename = params.serviceName || "";
    }

    return {
        config: config,
        probe_stage: "trojan-after-target",
        target: server_target
    };
}

export { parse };
