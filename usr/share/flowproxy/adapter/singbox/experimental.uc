/**
 * FlowProxy | adapter/singbox/experimental.uc
 * sing-box experimental JSON adapter.
 *
 * Phase 6.5.6: boundary extraction only. Capabilities are accepted for
 * observation, but must not affect output yet.
 */

'use strict';

import { log } from 'flowproxy.core.logger';

function build_experimental(experimental_model, caps, trace_id) {
    log(trace_id, 'INFO', 'ADAPTER', sprintf('[SINGBOX_CAPS] experimental adapter version=%s caps=%s', caps.version, sprintf("%.J", caps.capabilities)));

    return experimental_model;
}

export { build_experimental };
