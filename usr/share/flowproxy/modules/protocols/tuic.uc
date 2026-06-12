/**
 * FlowProxy | modules/protocols/tuic.uc
 * TUIC subscription URI parser.
 */

'use strict';

import { _resolve_server_target } from 'flowproxy.modules.protocols.common';

function parse(ctx) {
    let url = ctx.url;
    let params = ctx.params || {};
    let scheme = ctx.scheme || "tuic";
    let server_target = _resolve_server_target(url, params, scheme, "");
    let config = {
        label: ctx.default_label || "",
        type: 'tuic',
        address: server_target.host,
        port: server_target.port,
        uuid: url.username,
        password: url.password || "",
        tls: '1',
        tls_sni: params.sni || "",
        tuic_congestion_control: params.congestion_control || "",
        tuic_udp_relay_mode: params.udp_relay_mode || "",
        tls_alpn: params.alpn || "",
        tls_insecure: ctx.is_insec || "0"
    };

    return {
        config: config,
        probe_stage: "tuic-after-target",
        target: server_target
    };
}

export { parse };
