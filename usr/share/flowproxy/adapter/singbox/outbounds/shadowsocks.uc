/**
 * FlowProxy | adapter/singbox/outbounds/shadowsocks.uc
 * Shadowsocks outbound adapter.
 */

'use strict';

function apply(node, ep) {
    ep.method = node.shadowsocks_encrypt_method; ep.password = node.password;
    ep.plugin = node.shadowsocks_plugin; ep.plugin_opts = node.shadowsocks_plugin_opts;
    return true;
}

export { apply };
