/**
 * FlowProxy | adapter/singbox/inbounds.uc
 * sing-box inbound JSON adapter.
 *
 * Phase 6.5: boundary extraction only. Capabilities are accepted for
 * observation, but must not affect output yet.
 */

'use strict';

import { log } from 'flowproxy.core.logger';

function build_inbounds(inbounds_model, caps, trace_id, safe_listen_addr) {
    log(trace_id, 'INFO', 'ADAPTER', sprintf('[SINGBOX_CAPS] inbounds adapter version=%s caps=%s', caps.version, sprintf("%.J", caps.capabilities)));

    let inbounds = (type(inbounds_model) === 'array') ? inbounds_model : [];

    for (let i = 0; i < length(inbounds); i++) {
        if (inbounds[i].tag === 'mixed-in') {
            log(trace_id, 'INFO', 'ADAPTER', sprintf('Hardening mixed-in exposure: binding to %s', safe_listen_addr));
            inbounds[i].listen = safe_listen_addr;
        }
    }

    return inbounds;
}

export { build_inbounds };
