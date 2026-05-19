/**
 * FlowProxy | core/selfcheck.uc | v1.1
 * 环境与契约静态自检器 (Fail-Fast Edition)
 * 职责：在 Worker 启动时扫描核心物理依赖。绝不检查运行态（如端口/网卡）。
 */

'use strict';

import { stat } from 'fs';
import { PATH, BIN } from 'flowproxy.core.constants';
import { JOB_TYPES } from 'flowproxy.core.contract';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';

function run_all_checks(trace_id) {
    let issues = [];

    // 1. 检查关键二进制核心 (sing-box, curl, nft, sh 缺一不可)
    let required_bins = [BIN.SINGBOX, BIN.CURL, BIN.NFT, BIN.SH];
    for (let i = 0; i < length(required_bins); i++) {
        let b = required_bins[i];
        if (!stat(b)) {
            push(issues, "致命缺失: 找不到二进制核心 -> " + b);
        }
    }

    // 2. 检查基础 UCI 配置文件
    // 🚨 架构修正：移除 PATH.ASSETS 检查，防止冷启动时陷入“无资产->拦截->无法下载资产”的死锁
    let required_paths = [ PATH.UCI ];
    for (let i = 0; i < length(required_paths); i++) {
        let p = required_paths[i];
        if (!stat(p)) {
            push(issues, "系统异常: 缺失核心配置文件 -> " + p);
        }
    }

    // 3. 检查契约定义完整性
    if (!JOB_TYPES || !JOB_TYPES["apply_config"]) {
        push(issues, "契约损坏: 缺失 apply_config 核心定义");
    }

    if (length(issues) > 0) {
        return Fail(ERR.E_ENV_MISSING, join(" | ", issues), trace_id);
    }
    
    return Success(true, 200, trace_id);
}

export { run_all_checks };
