/**
 * FlowProxy | core/contract.uc | v1.0
 * 唯一行为契约 (Strict Immutable Edition)
 * 职责：锁死合法的 Job 与 System API 名录，作为网关拦截和 Worker 执行的唯一宪法。
 * 核心规则：采用 O(1) 字典结构，纯静态数据源，无行为逻辑。
 */

'use strict';

// 契约版本号：用于 Worker/Adapter 判定是否需要拦截旧版漂移请求
const CONTRACT_VERSION = "1.0";

/**
 * [ IMMUTABLE CONTRACT TABLE ]
 * [ DO NOT MODIFY AT RUNTIME ]
 * 唯一合法的 Job 集合 (异步长任务)
 */
const JOB_TYPES = {
    "apply_config": true,          // 生成配置 + 校验 + 部署 + 重启 (配置驱动核心)
    "stop_service": true,          // 物理撤收逻辑 (意志禁用)
    "update_subscriptions": true,  // 更新订阅节点
    "rebuild_groups": true,        // 重建节点组
    "update_assets": true,         // 更新规则资源
    "system_rollback": true,       // 紧急安全回滚 (容灾恢复)
    "update_kernel": true,         // 内核二进制更新
    "deploy_panels": true,         // 部署前端面板资源
    "update_resources": true       // 更新IP域名资源 
};

/**
 * [ IMMUTABLE CONTRACT TABLE ]
 * [ DO NOT MODIFY AT RUNTIME ]
 * 唯一合法的 System API 集合 (同步轻查询)
 */
const SYSTEM_METHODS = {
    "status": true,                // 获取真相引擎快照 (Snapshot)
    "connection_check": true,      // 连通性测试 (含百度/谷歌探测)
    "resources_version": true,     // 获取资源版本
    "kernel_version": true,        // 获取内核版本
    "singbox_features": true,      // 获取内核能力
    "singbox_generator": true,     // 生成密钥
    "acllist_read": true,          // 读取 ACL
    "acllist_write": true,         // 写入 ACL
    "log_read": true,              // 持续读取日志流
    "log_clean": true              // 瞬时清理日志
};

// 🚨 铁律 1: 文件末尾统一导出
export { CONTRACT_VERSION, JOB_TYPES, SYSTEM_METHODS };
