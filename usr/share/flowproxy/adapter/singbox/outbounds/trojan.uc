/**
 * FlowProxy | adapter/singbox/outbounds/trojan.uc
 * Trojan outbound adapter.
 */

'use strict';

function apply(node, ep) {
    ep.password = node.password;
    return true;
}

export { apply };
