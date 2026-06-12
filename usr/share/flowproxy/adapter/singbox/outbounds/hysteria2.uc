/**
 * FlowProxy | adapter/singbox/outbounds/hysteria2.uc
 * Hysteria2 outbound adapter.
 */

'use strict';

function strToInt(val) { return (val != null && val !== "") ? int(val) : null; }
function strToBool(val) { return (val != null && val !== "") ? (val === '1' || val === 'true') : null; }

function apply(node, ep) {
    ep.password = node.password;
    ep.up_mbps = strToInt(node.hysteria_up_mbps); ep.down_mbps = strToInt(node.hysteria_down_mbps);
    ep.obfs = node.hysteria_obfs_type ? { type: node.hysteria_obfs_type, password: node.hysteria_obfs_password } : node.hysteria_obfs_password;
    ep.auth = (node.hysteria_auth_type === 'base64') ? node.hysteria_auth_payload : null;
    ep.auth_str = (node.hysteria_auth_type === 'string') ? node.hysteria_auth_payload : null;
    ep.recv_window_conn = strToInt(node.hysteria_recv_window_conn);
    ep.recv_window = strToInt(node.hysteria_recv_window || node.hysteria_revc_window);
    ep.disable_mtu_discovery = strToBool(node.hysteria_disable_mtu_discovery);
    return true;
}

export { apply };
