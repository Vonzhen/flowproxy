/**
 * FlowProxy | runtime/watchdog.uc | v1.2
 * 职责：系统运行态定时巡检与自愈触发器
 */
'use strict';

import { readfile, writefile } from 'fs';
import { cursor } from 'uci';
import { BIN } from 'flowproxy.core.constants';
import { ExecSafe } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';
import { HealthCheck } from 'flowproxy.runtime.healthcheck';
import { send_telegram } from 'flowproxy.modules.notifier';

const FAIL_COUNT_FILE = "/tmp/flowproxy.fail_count";
const MAX_FAIL_COUNT = 3;

function run_watchdog(trace_id) {
    log(trace_id, "INFO", "WATCHDOG", "Watchdog routine started.");

    // 1. 检查用户配置意图
    let u = cursor();
    u.load("flowproxy");
    if (u.get("flowproxy", "routing", "default_outbound") === 'disabled') {
        log(trace_id, "INFO", "WATCHDOG", "System is disabled by user intent. Watchdog sleeping.");
        return;
    }

    // 2. 执行运行态健康检查
    let health = HealthCheck.verify();

    // 3. 状态健康时，清空历史失败计数并退出
    if (health.ok) {
        ExecSafe(BIN.SH, ["-c", sprintf("rm -f %s", FAIL_COUNT_FILE)]);
        log(trace_id, "INFO", "WATCHDOG", "System is HEALTHY. Routine complete.");
        return;
    }

    // 4. 状态异常时，累加失败计数
    let current_fails = 0;
    let fail_content = readfile(FAIL_COUNT_FILE);
    if (fail_content) current_fails = int(trim(fail_content)) || 0;
    current_fails++;
    writefile(FAIL_COUNT_FILE, sprintf("%d", current_fails));

    log(trace_id, "WARN", "WATCHDOG", sprintf("Detected drift in: %s. Attempt %d/%d", join(", ", health.failed), current_fails, MAX_FAIL_COUNT));

    // 5. 失败次数达到阈值，触发熔断保护 (安全回退并告警)
    if (current_fails >= MAX_FAIL_COUNT) {
        log(trace_id, "CRIT", "WATCHDOG", "System Broken. Triggering panic notification!");
        let alert_msg = "⚠️ <b>系统状态漂移严重，已进入熔断保护！</b>%0A" +
                        "━━━━━━━━━━━━━━━━━━%0A" +
                        "异常组件：" + join(", ", health.failed) + "%0A" +
                        "动作：已强制停机并恢复直连网络。";
                        
        // 发送告警通知
        send_telegram("watchdog_panic", "fail", alert_msg, trace_id);
        
        // 物理卸载网络栈，恢复直连
        ExecSafe(BIN.SH, ["-c", "/etc/init.d/flowproxy stop"]);
        return;
    }

    // 6. 在重试阈值内，通过 UBUS 异步调用 Worker 执行完整的配置重载与环境自愈
    log(trace_id, "INFO", "WATCHDOG", "Attempting recovery via Worker UBUS task...");
    let repair_cmd = sprintf("ubus call flowproxy.job start '{\"type\":\"apply_config\"}'");
    ExecSafe(BIN.SH, ["-c", repair_cmd], null, trace_id);
}

export { run_watchdog };
