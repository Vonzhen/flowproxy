/**
 * FlowProxy | modules/protocols/anytls.uc
 * AnyTLS subscription URI parser.
 */

'use strict';

import { _resolve_server_target } from 'flowproxy.modules.protocols.common';

function parse(ctx) {
    let url = ctx.url;
    let params = ctx.params || {};
    let scheme = ctx.scheme || "anytls";
    let server_target = _resolve_server_target(url, params, scheme, "");
    let config = {
        label: ctx.default_label || "",
        type: 'anytls',
        address: server_target.host,
        port: server_target.port,
        password: url.username,
        tls: '1',
        tls_sni: params.sni || "",
        tls_insecure: ctx.is_insec || "0"
    };

    return {
        config: config,
        probe_stage: "anytls-after-target",
        target: server_target
    };
}

export { parse };
