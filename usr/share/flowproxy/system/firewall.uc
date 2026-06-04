/**
 * FlowProxy | system/firewall.uc | v2.0 compatibility wrapper
 * Redirect+TProxy firewall compilation now lives in system/network/firewall_tproxy.uc.
 */

'use strict';

import { build_tproxy_firewall } from 'flowproxy.system.network.firewall_tproxy';

function build_firewall(trace_id) {
    return build_tproxy_firewall(trace_id);
}

export { build_firewall };
