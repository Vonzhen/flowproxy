/**
 * FlowProxy | core/contract.uc | v1.2 (Control Plane Freeze)
 * 唯一行为契约：Job / System API / 数据面门闸的 SSOT。禁止在其它文件重复白名单。
 */

'use strict';

const CONTRACT_VERSION = "1.2";

// Phase A: apply_config is the only normal UI apply entry. mode_switch_apply is maintenance/debug/emergency only.

/**
 * [ IMMUTABLE CONTRACT TABLE ]
 * [ DO NOT MODIFY AT RUNTIME ]
 * 唯一合法的 Job 集合（异步长任务）
 */
const JOB_TYPES = {
    "repair_current_mode": true,   // Phase 3E: repair current dataplane mode only; no GC/restart/config change
    "mode_switch_apply": true,     // maintenance/debug/emergency mode switch lifecycle; not normal UI flow
    "apply_config": true,          // generate/check/apply runtime config
    "update_subscriptions": true,  // update subscriptions
    "rebuild_groups": true,        // rebuild node groups
    "update_assets": true,         // update rule assets
    "system_rollback": true,       // emergency rollback
    "update_kernel": true,         // read-only kernel version check
    "deploy_panels": true,         // deploy frontend panel assets
    "update_resources": true,      // update IP/domain resources
    "watchdog_report": true,       // passive runtime observation
    "maintenance_logrotate": true  // log archive maintenance
};

/** 禁止进入 RuntimeOrchestrator.run_dataplane_reload 的 Job（观察 / 维护） */
const JOB_NO_DATAPLANE = {
    "repair_current_mode": true,
    "update_kernel": true,
    "watchdog_report": true,
    "maintenance_logrotate": true
};

/* Phase E: business jobs must use payload.source + payload.auto_apply.
 * manual/false stays in business data only and returns manual_apply_required.
 * cron/true may auto-apply through apply_config semantics, but cron mode switch
 * is denied by default. payload.allow_cron_mode_switch=true is honored only for
 * internal maintenance/debug/emergency requests carrying an explicit
 * cron_mode_switch_scope/mode_switch_scope marker. Normal UI and generated cron
 * entries must not expose or enable it.
 */
function job_allows_dataplane_reload(job_type) {
    return !!(JOB_TYPES[job_type] && !JOB_NO_DATAPLANE[job_type]);
}

/**
 * [ IMMUTABLE CONTRACT TABLE ]
 * [ DO NOT MODIFY AT RUNTIME ]
 * 唯一合法的 System API 集合（同步轻查询）
 * 键名与 flowproxy.system ubus 方法一一对应
 */
const SYSTEM_METHODS = {
    "status": true,                    // 获取真相引擎快照 (Snapshot)
    "connection_check": true,          // 连通性测试 (direct/proxy)
    "resources_get_version": true,     // 获取资源版本
    "kernel_version_check": true,      // 获取内核版本
    "singbox_get_features": true,      // 获取内核能力
    "get_uci_proxy_mode": true,        // read committed UCI config.proxy_mode
    "get_urltest_status": true,        // read existing sing-box Clash API outbound/urltest state
    "get_runtime_artifacts": true,     // read whitelisted runtime JSON artifacts
    "log_read_runtime": true,          // read whitelisted runtime logs
    "get_network_state": true,         // read current nft/ip route state
    "singbox_check_readonly": true,    // check existing run.json without apply/restart
    "singbox_generator": true,         // 生成密钥
    "acllist_read": true,              // 读取 ACL
    "acllist_write": true,             // 写入 ACL
    "log_clean": true                  // 临时清理日志
};

// 🚨 铁律 1: 文件末尾统一导出
export { CONTRACT_VERSION, JOB_TYPES, JOB_NO_DATAPLANE, SYSTEM_METHODS, job_allows_dataplane_reload };
