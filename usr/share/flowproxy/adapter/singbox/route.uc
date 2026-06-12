/**
 * FlowProxy | adapter/singbox/route.uc
 * sing-box route JSON adapter.
 *
 * Phase 6.4: boundary extraction only. Capabilities are accepted for
 * observation, but must not affect output yet.
 */

'use strict';

import { log } from 'flowproxy.core.logger';

function build_route(route_model, caps, trace_id) {
    log(trace_id, 'INFO', 'ADAPTER', sprintf('[SINGBOX_CAPS] route adapter version=%s caps=%s', caps.version, sprintf("%.J", caps.capabilities)));

    let route = {
        rules: route_model.rules || [],
        rule_set: route_model.rule_set || [],
        auto_detect_interface: route_model.auto_detect_interface,
        final: route_model.final || 'direct-out'
    };
    if (route_model.default_domain_resolver) {
        route.default_domain_resolver = route_model.default_domain_resolver;
    }

    return route;
}

export { build_route };
