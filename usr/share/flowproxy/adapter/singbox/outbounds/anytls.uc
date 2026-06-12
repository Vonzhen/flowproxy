/**
 * FlowProxy | adapter/singbox/outbounds/anytls.uc
 * AnyTLS outbound adapter.
 */

'use strict';

function apply(node, ep) {
    ep.password = node.password;
    return true;
}

export { apply };
