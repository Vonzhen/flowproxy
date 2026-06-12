/**
 * FlowProxy | runtime/state.uc
 * Role: runtime.state persistence and system snapshot aggregation.
 */

'use strict';

import { open as fs_open, stat, readfile } from 'fs';
import { is_service_enabled } from 'flowproxy.core.config_helper';
import { PATH, DATAPLANE } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { ensure_dir } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';
import { HealthCheck } from 'flowproxy.runtime.healthcheck';

const PATH_RUNTIME_STATE = DATAPLANE.RUNTIME_STATE;

const StateManager = {

    read_state: function() {
        if (!stat(PATH_RUNTIME_STATE)) return {};

        let content = readfile(PATH_RUNTIME_STATE);
        if (!content) return {};

        try {
            return json(content) || {};
        } catch (e) {
            log(null, 'WARN', 'STATE', 'runtime.state parse failed: ' + ("" + e));
            return {};
        }
    },

    record_state: function(payload) {
        ensure_dir(PATH.RUNTIME);

        let current = this.read_state();

        for (let k in payload) {
            if (k === "watchdog" && type(payload[k]) === "object") {
                current.watchdog = current.watchdog || {};
                for (let wk in payload[k]) {
                    current.watchdog[wk] = payload[k][wk];
                }
            } else {
                current[k] = payload[k];
            }
        }

        current.watchdog = current.watchdog || {};
        current.watchdog.last_state = current.watchdog.last_state || "healthy";
        current.watchdog.last_notified_state = current.watchdog.last_notified_state || "healthy";
        current.updated_at = time();

        let fd = fs_open(PATH_RUNTIME_STATE, "w");
        if (!fd) {
            log(null, 'CRIT', 'STATE', sprintf(
                'record_state failed: cannot open %s for write', PATH_RUNTIME_STATE
            ));
            return;
        }
        fd.write(sprintf("%.J", current));
        fd.close();
    },

    reset_watchdog_baseline: function(state) {
        this.record_state({
            watchdog: {
                last_state: state || "healthy",
                last_notified_state: state || "healthy"
            }
        });
    },

    snapshot: function(trace_id) {
        try {
            let en_res = is_service_enabled(trace_id);
            let is_enabled = en_res.ok && en_res.data;
            let health_info = HealthCheck.verify();

            let process_in_failed = index(health_info.failed, "process");
            let process_running = (process_in_failed < 0) ? true : false;
            let health_mode = health_info.mode || (health_info.dataplane ? health_info.dataplane.mode : "unknown");
            let health_mode_source = health_info.mode_source || (health_info.missing ? health_info.missing.mode_source : "unknown");
            let health_mode_warning = health_info.mode_warning || (health_info.missing ? health_info.missing.mode_warning : "");

            let snap = {
                process: { running: process_running },
                config: { valid: stat(PATH.RUN_JSON) != null },
                health: {
                    state: health_info.ok ? "healthy" : (length(health_info.failed) > 2 ? "broken" : "degraded"),
                    failed: health_info.failed,
                    failed_mode: health_mode,
                    mode: health_mode,
                    mode_source: health_mode_source,
                    mode_warning: health_mode_warning,
                    missing: health_info.missing || {
                        mode: health_mode,
                        mode_source: health_mode_source,
                        mode_warning: health_mode_warning,
                        failed: health_info.failed,
                        items: []
                    },
                    dataplane: {
                        mode: health_mode,
                        mode_source: health_mode_source,
                        mode_warning: health_mode_warning
                    }
                },
                ports: { mixed: 5330, dns: 5333 },
                version: { singbox: "1.x-managed" },
                enabled: is_enabled,
                reason: is_enabled ? "Configured" : "Disabled by user intent"
            };

            snap.diagnostic = {};
            if (stat(PATH_RUNTIME_STATE)) {
                let st_content = readfile(PATH_RUNTIME_STATE);
                if (st_content) {
                    try {
                        snap.diagnostic = json(st_content) || {};
                    } catch (state_err) {
                        snap.diagnostic = {
                            state_corrupted: true,
                            state_corrupted_detail: "" + state_err
                        };
                        log(trace_id, 'WARN', 'STATE', 'runtime.state corrupted during snapshot: ' + ("" + state_err));
                    }
                }
            }
            snap.diagnostic.current_health_mode = health_mode;
            snap.diagnostic.current_health_mode_source = health_mode_source;

            return Success(snap, 200, trace_id);

        } catch (e) {
            let err_str = "" + e;
            return Fail(ERR.E_SYSTEM_BUSY, "Snapshot generation failed: " + err_str, trace_id);
        }
    }
};

export { StateManager };
