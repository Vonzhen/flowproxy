/**
 * FlowProxy | system/safety.uc | v2.0 SSOT Delegate Edition
 * 职责：紧急回滚时委托 network.teardown；不拥有 nft，不操作 inet fw4。
 */

'use strict';

import { stat } from 'fs';

import { BIN } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { ExecSafe } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';
import { teardown } from 'flowproxy.system.network';

const DNSMASQ_CONF_DIR = '/tmp/dnsmasq.d/dnsmasq-flowproxy.d';
const DNSMASQ_INC_FILE = '/tmp/dnsmasq.d/dnsmasq-flowproxy.conf';

/**
 * Bypass 由 network.uc 在 setup 阶段装配；safety 不直接变更 nft。
 */
function inject_bypass(trace_id) {
    log(trace_id, 'INFO', 'SAFETY', 'Bypass is owned by system.network; safety layer is observe-only.');
    return Success(true, 200, trace_id);
}

/**
 * 灾难回滚：清理 dnsmasq 侧车 + 委托 network.teardown 抹除数据面
 */
function _reason(opts) {
    opts = (type(opts) === 'object') ? opts : {};
    return opts.reason || "fallback";
}

function execute_fallback(trace_id, opts) {
    try {
        let reason = _reason(opts);
        log(trace_id, 'INFO', 'SAFETY', 'Executing physical fallback (delegating nft to network.teardown) reason=' + reason);

        let dns_dirty = false;

        if (stat(DNSMASQ_CONF_DIR)) {
            ExecSafe(BIN.RM, ["-rf", DNSMASQ_CONF_DIR], null, trace_id);
            dns_dirty = true;
        }
        if (stat(DNSMASQ_INC_FILE)) {
            ExecSafe(BIN.RM, ["-f", DNSMASQ_INC_FILE], null, trace_id);
            dns_dirty = true;
        }
        if (dns_dirty) {
            ExecSafe(BIN.SH, ["-c", "/etc/init.d/dnsmasq restart"], null, trace_id);
        }

        let teardown_res = teardown(trace_id, { reason: reason });
        if (!teardown_res || !teardown_res.ok) {
            let detail = (teardown_res && teardown_res.detail) ? teardown_res.detail : "network.teardown failed";
            log(trace_id, 'CRIT', 'SAFETY', 'Fallback teardown failed: ' + detail);
            return Fail(ERR.E_SYSTEM_BUSY, detail, trace_id);
        }

        log(trace_id, 'INFO', 'SAFETY', 'Fallback execution completed (network.teardown).');
        return Success(true, 200, trace_id);

    } catch (e) {
        let err_msg = "" + e;
        log(trace_id, 'CRIT', 'SAFETY', 'Fallback Execution Exception: ' + err_msg);
        return Fail(ERR.E_SYSTEM_BUSY, "Fallback Execution Exception: " + err_msg, trace_id);
    }
}

export { inject_bypass, execute_fallback };
