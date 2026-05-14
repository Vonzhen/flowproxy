/**
 * FlowProxy | core/selfcheck.uc | v1.0
 * 环境与契约自检器 (SSOT Aligned Fail-Fast Edition)
 * 职责：在 Worker 启动时扫描系统完整性与契约同步情况。如果不达标，拒绝执行。
 * 核心对齐：完全抛弃硬编码，直接与基石中的 PATH、BIN 和静态 JOB_TYPES 验证对齐。
 */

'use strict';

// 🚨 铁律 5: 原生模块解构导入
import { stat } from 'fs';

// 🚨 铁律 3: 绝对命名空间寻址
import { PATH, BIN } from 'flowproxy.core.constants';
import { JOB_TYPES } from 'flowproxy.core.contract';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';

/**
 * 运行系统运行前置校验
 * @param {string} trace_id 全链路追踪 ID
 */
function run_all_checks(trace_id) {
    let issues = [];

    // 1. 检查关键二进制核心 (⭐ 基石对齐：BIN.SINGBOX / BIN.CURL / BIN.NFT)
    let required_bins = [BIN.SINGBOX, BIN.CURL, BIN.NFT, BIN.SH];
    for (let i = 0; i < length(required_bins); i++) {
        let b = required_bins[i];
        if (!stat(b)) {
            push(issues, "致命缺失: 找不到二进制文件 -> " + b);
        }
    }

    // 2. 检查物理目录或核心文件 (⭐ 基石对齐：PATH.UCI / PATH.ASSETS)
    let required_paths = [
        PATH.UCI,
        PATH.ASSETS
    ];
    for (let i = 0; i < length(required_paths); i++) {
        let p = required_paths[i];
        if (!stat(p)) {
            push(issues, "系统异常: 基础目录或文件不存在 -> " + p);
        }
    }

    // 3. 检查契约定义完整性 (⭐ 契约对齐：直接读取静态字典)
    if (!JOB_TYPES || !JOB_TYPES["apply_config"] || !JOB_TYPES["stop_service"]) {
        push(issues, "契约损坏: 缺失 apply_config 或 stop_service 核心定义");
    }

    // ⭐ 协议对齐：强制返回 1.0 Result 结构，挂钩 E_ENV_MISSING
    if (length(issues) > 0) {
        return Fail(ERR.E_ENV_MISSING, join(" | ", issues), trace_id);
    }
    
    return Success(true, 200, trace_id);
}

// 🚨 铁律 1: 文件末尾统一导出
export { run_all_checks };
