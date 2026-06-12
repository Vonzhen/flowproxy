/**
 * FlowProxy | adapter/singbox/outbounds/vless.uc
 * VLESS outbound adapter.
 */

'use strict';

function normalize_uuid(u) {
    if (!u || type(u) !== 'string') return u;
    if (length(u) === 32 && index(u, '-') < 0) {
        return sprintf("%s-%s-%s-%s-%s", substr(u,0,8), substr(u,8,4), substr(u,12,4), substr(u,16,4), substr(u,20,12));
    }
    return u;
}

function apply(node, ep) {
    ep.uuid = normalize_uuid(node.uuid); ep.flow = node.vless_flow; ep.packet_encoding = node.packet_encoding;
    return true;
}

export { apply };
