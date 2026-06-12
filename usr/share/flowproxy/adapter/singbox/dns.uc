/**
 * FlowProxy | adapter/singbox/dns.uc
 * sing-box DNS JSON adapter.
 *
 * Phase 6.3: boundary extraction only. Capabilities are accepted for
 * observation, but must not affect output yet.
 */

'use strict';

import { log } from 'flowproxy.core.logger';

function build_dns(dns_model, caps, trace_id) {
    log(trace_id, 'INFO', 'ADAPTER', sprintf('[SINGBOX_CAPS] dns adapter version=%s caps=%s', caps.version, sprintf("%.J", caps.capabilities)));

    return {
        servers: dns_model.servers || [],
        rules: dns_model.rules || [],
        final: dns_model.final || 'default-dns',
        strategy: dns_model.strategy,
        disable_cache: dns_model.disable_cache || false,
        disable_expire: dns_model.disable_expire || false,
        client_subnet: dns_model.client_subnet
    };
}

export { build_dns };
