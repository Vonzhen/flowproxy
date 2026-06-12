/**
 * FlowProxy | adapter/singbox/outbounds/vmess.uc
 * VMess outbound adapter.
 */

'use strict';

function strToInt(val) { return (val != null && val !== "") ? int(val) : null; }
function strToBool(val) { return (val != null && val !== "") ? (val === '1' || val === 'true') : null; }

function normalize_uuid(u) {
    if (!u || type(u) !== 'string') return u;
    if (length(u) === 32 && index(u, '-') < 0) {
        return sprintf("%s-%s-%s-%s-%s", substr(u,0,8), substr(u,8,4), substr(u,12,4), substr(u,16,4), substr(u,20,12));
    }
    return u;
}

function apply(node, ep) {
    ep.uuid = normalize_uuid(node.uuid); ep.alter_id = strToInt(node.vmess_alterid); ep.security = node.vmess_encrypt;
    ep.global_padding = strToBool(node.vmess_global_padding); ep.authenticated_length = strToBool(node.vmess_authenticated_length);
    ep.packet_encoding = node.packet_encoding;
    return true;
}

export { apply };
