/**
 * FlowProxy | modules/protocols/hysteria2.uc
 * Hysteria2 / hy2 subscription URI parser.
 */

'use strict';

import { _resolve_server_target } from 'flowproxy.modules.protocols.common';

function parse(ctx) {
    let url = ctx.url;
    let params = ctx.params || {};
    let scheme = ctx.scheme || "hysteria2";
    let server_target = _resolve_server_target(url, params, scheme, "");
    let hy2_pass = url.username || "";
    if (url.password) hy2_pass += ":" + url.password;

    let config = {
        label: ctx.default_label || "",
        type: 'hysteria2',
        address: server_target.host,
        port: server_target.port,
        password: hy2_pass,
        hysteria_obfs_type: params.obfs || "",
        hysteria_obfs_password: params['obfs-password'] || "",
        tls: '1',
        tls_insecure: ctx.is_insec || "0",
        tls_sni: params.sni || ""
    };

    return {
        config: config,
        probe_stage: "hy2-after-target",
        target: server_target
    };
}

export { parse };
