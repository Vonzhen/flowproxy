/**
 * FlowProxy | adapter/singbox/outbounds/tuic.uc
 * TUIC outbound adapter.
 */

'use strict';

function strToBool(val) { return (val != null && val !== "") ? (val === '1' || val === 'true') : null; }

function strToTime(val) {
    if (val !=null && val !=="") {
       return match(val,/^[0-9]+$/) ? val + "s" : val;
    }
    return null;
}

function normalize_uuid(u) {
    if (!u || type(u) !== 'string') return u;
    if (length(u) === 32 && index(u, '-') < 0) {
        return sprintf("%s-%s-%s-%s-%s", substr(u,0,8), substr(u,8,4), substr(u,12,4), substr(u,16,4), substr(u,20,12));
    }
    return u;
}

function apply(node, ep) {
    ep.uuid = normalize_uuid(node.uuid); ep.password = node.password; ep.congestion_control = node.tuic_congestion_control;
    ep.udp_relay_mode = node.tuic_udp_relay_mode; ep.udp_over_stream = strToBool(node.tuic_udp_over_stream);
    ep.zero_rtt_handshake = strToBool(node.tuic_enable_zero_rtt); ep.heartbeat = strToTime(node.tuic_heartbeat);
    return true;
}

export { apply };
