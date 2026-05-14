/**
 * FlowProxy | core/error.uc | v1.0
 * 唯一错误字典 (Strict Immutable Edition)
 * 职责：定义标准错误码、错误域与严重程度，提供系统级故障解释权。
 * 核心规则：纯静态数据源。严禁手写 error 字符串，严禁在运行时动态拼接错误码。
 */

'use strict';

/**
 * [ IMMUTABLE ENUM ]
 * 严重等级 (决定 UI 渲染颜色与是否触发 TG 告警)
 */
const SEVERITY = { 
    CRIT: "CRIT",   // 致命故障 (红灯，停止运行)
    WARN: "WARN",   // 警告级故障 (黄灯，可重试)
    INFO: "INFO"    // 信息级状态 (灰/绿灯，状态变更)
};

/**
 * [ IMMUTABLE ENUM ]
 * 故障领域 (用于精准定位责任模块)
 */
const CATEGORY = {
    CORE: "CORE", 
    CONFIG: "CONFIG", 
    RUNTIME: "RUNTIME", 
    NETWORK: "NETWORK",
    RPC: "RPC"
};

/**
 * [ IMMUTABLE ERROR TABLE ]
 * [ DO NOT MODIFY AT RUNTIME ]
 * 全局标准异常枚举
 * 🚨 铁律：所有 Fail() 调用的第一个参数必须是此对象中的枚举
 */
const ERR = {
    E_SYSTEM_BUSY:     { code: 1001, category: CATEGORY.CORE,    severity: SEVERITY.WARN, recoverable: true,  msg: "系统忙，请稍后再试" },
    E_AUTH_DENIED:     { code: 403,  category: CATEGORY.RPC,     severity: SEVERITY.CRIT, recoverable: false, msg: "越权调用已被拒绝" },
    E_CONFIG_FAULT:    { code: 500,  category: CATEGORY.CONFIG,  severity: SEVERITY.CRIT, recoverable: false, msg: "配置模型构建失败或语法错误" },
    E_WILL_DISABLED:   { code: 503,  category: CATEGORY.RUNTIME, severity: SEVERITY.INFO, recoverable: false, msg: "用户意志：彻底禁用代理服务" },
    E_ENV_MISSING:     { code: 500,  category: CATEGORY.CORE,    severity: SEVERITY.CRIT, recoverable: false, msg: "系统物理环境异常或依赖缺失" },
    E_NET_UNREACHABLE: { code: 502,  category: CATEGORY.NETWORK, severity: SEVERITY.WARN, recoverable: true,  msg: "网络拨测连通性失败" }
};

// 🚨 铁律 1: 文件末尾统一导出
export { SEVERITY, CATEGORY, ERR };
