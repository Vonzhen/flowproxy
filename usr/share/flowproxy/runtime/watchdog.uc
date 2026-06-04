/**
 * FlowProxy | runtime/watchdog.uc | v2.1 (Phase5 Frozen Observer)
 * 职责：health check + fail counter + 由 Worker 写入 state。禁止一切数据面/控制面动作。
 */

'use strict';

import { readfile, writefile } from 'fs';
import { log } from 'flowproxy.core.logger';
import { is_service_enabled } from 'flowproxy.core.config_helper';
import { HealthCheck } from 'flowproxy.runtime.healthcheck';
import { StateManager } from 'flowproxy.runtime.state';

const FAIL_COUNT_FILE = "/tmp/flowproxy.fail_count";
const BROKEN_THRESHOLD = 2;

function _edge_state(current_state, message) {
    let runtime_state = StateManager.read_state();
    let wd = runtime_state.watchdog || {};
    let last_notified = wd.last_notified_state || wd.last_state || "healthy";
    let edge = "none";
    let notify = false;
    let next_notified = last_notified;

    if (current_state === "healthy" && last_notified === "broken") {
        edge = "up";
        notify = true;
        next_notified = "healthy";
    } else if (current_state === "broken" && last_notified === "healthy") {
        edge = "down";
        notify = true;
        next_notified = "broken";
    }

    return {
        healthy: current_state === "healthy",
        notify: notify,
        edge: edge,
        message: message,
        last_state: current_state,
        last_notified_state: last_notified,
        next_notified_state: next_notified
    };
}

/**
 * 被动观测（唯一对外能力）
 * @returns { ok, skipped, health, consecutive_fails }
 */
function observe(trace_id) {
    log(trace_id, "INFO", "WATCHDOG", "Passive observation started.");

    let en_res = is_service_enabled(trace_id);
    if (en_res.ok && !en_res.data) {
        log(trace_id, "INFO", "WATCHDOG", "Service disabled by user intent. Skipping.");
        let edge = _edge_state("healthy", "Watchdog skipped (service disabled)");
        return {
            ok: true,
            skipped: true,
            health: null,
            consecutive_fails: 0,
            healthy: true,
            notify: false,
            edge: "none",
            message: edge.message,
            last_state: "healthy",
            last_notified_state: edge.last_notified_state,
            next_notified_state: edge.last_notified_state
        };
    }

    let health = HealthCheck.verify({ allow_transient: true });

    if (health.ok) {
        writefile(FAIL_COUNT_FILE, "0");
        if (health.transient === true) {
            log(trace_id, "INFO", "WATCHDOG", sprintf(
                "Lifecycle grace active (%s). Drift counter suspended.",
                health.grace_reason || "transaction"
            ));
            let edge_grace = _edge_state("healthy", "Watchdog: lifecycle grace window active");
            return {
                ok: true,
                skipped: false,
                health: health,
                consecutive_fails: 0,
                healthy: true,
                notify: false,
                edge: "none",
                message: edge_grace.message,
                last_state: "healthy",
                last_notified_state: edge_grace.last_notified_state,
                next_notified_state: edge_grace.last_notified_state
            };
        }
        log(trace_id, "INFO", "WATCHDOG", "System healthy.");
        let edge = _edge_state("healthy", "Watchdog: system healthy");
        return {
            ok: true,
            skipped: false,
            health: health,
            consecutive_fails: 0,
            healthy: true,
            notify: edge.notify,
            edge: edge.edge,
            message: edge.message,
            last_state: edge.last_state,
            last_notified_state: edge.last_notified_state,
            next_notified_state: edge.next_notified_state
        };
    }

    let current_fails = 0;
    let fail_content = readfile(FAIL_COUNT_FILE);
    if (fail_content) current_fails = int(trim(fail_content)) || 0;
    current_fails++;
    writefile(FAIL_COUNT_FILE, sprintf("%d", current_fails));

    log(trace_id, "WARN", "WATCHDOG", sprintf(
        "Drift detected in: %s (consecutive=%d)",
        join(", ", health.failed), current_fails
    ));

    let broken = current_fails >= BROKEN_THRESHOLD;
    let current_state = broken ? "broken" : "healthy";
    let msg = sprintf(
        "Drift observed: %s (fail_count=%d). No auto-repair; use apply_config if needed.",
        join(", ", health.failed), current_fails
    );
    let edge = _edge_state(current_state, msg);

    return {
        ok: !broken,
        skipped: false,
        health: health,
        consecutive_fails: current_fails,
        healthy: !broken,
        notify: edge.notify,
        edge: edge.edge,
        message: edge.message,
        last_state: edge.last_state,
        last_notified_state: edge.last_notified_state,
        next_notified_state: edge.next_notified_state
    };
}

export { observe };
