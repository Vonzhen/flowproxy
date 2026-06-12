/**
 * FlowProxy | runtime/generate.uc | v1.0 Route-B Aligned
 * 角色：同步 Runtime Gateway (生命周期层与业务层之间的绝对物理防火墙)
 * 职责：专供 /etc/init.d/flowproxy 阻塞调用的纯净入口。
 * 行为：读取 UCI -> 校验 Model -> 翻译 JSON -> 写入磁盘 -> 退出(0/1)
 */

'use strict';

// 🚨 环境对齐：防御性注入寻址路径，供 CLI 模式执行
push(REQUIRE_SEARCH_PATH, "/usr/share/ucode/*.uc");
push(REQUIRE_SEARCH_PATH, "/usr/share/ucode/*/init.uc");

import { writefile } from 'fs';
import { PATH } from 'flowproxy.core.constants';
import { init as gen_trace_id } from 'flowproxy.core.trace';
import { log } from 'flowproxy.core.logger';
import { ensure_dir } from 'flowproxy.core.utils';

import { build_flow_model } from 'flowproxy.model.schema';
import { validate_model } from 'flowproxy.model.validator';
import { Adapter } from 'flowproxy.adapter.singbox';
import { detect as detect_singbox_caps } from 'flowproxy.adapter.singbox.capabilities';

let trace_id = 'SYNC_BOOT_' + gen_trace_id();
let candidate_path = sprintf("%s/sing-box-run.candidate.json", PATH.RUNTIME);

if (length(ARGV) > 0 && ARGV[0]) {
    candidate_path = ARGV[0];
}

if (candidate_path !== sprintf("%s/sing-box-run.candidate.json", PATH.RUNTIME)) {
    log(trace_id, 'CRIT', 'GATEWAY', 'Illegal candidate output path: ' + candidate_path);
    exit(1);
}

log(trace_id, 'INFO', 'GATEWAY', '========================================');
log(trace_id, 'INFO', 'GATEWAY', 'Synchronous Runtime Generation Started.');

try {
    // [Step 1] 读取真相源，构建模型
    let model_res = build_flow_model(trace_id);
    if (!model_res.ok || !model_res.data) {
        log(trace_id, 'CRIT', 'GATEWAY', 'Fatal: Failed to build FlowModel from UCI.');
        exit(1);
    }
    
    let flow_model = model_res.data;

    // [Step 2] 意图闭环：如果 UCI 明确禁用，网关直接阻断生成 (双重保险)
    if (flow_model.enabled === false) {
        log(trace_id, 'WARN', 'GATEWAY', 'Abort: User intent is DISABLED. JSON will not be generated.');
        // 返回 1 告诉 Shell 层启动失败，不要拉起进程
        exit(1); 
    }

    // [Step 3] 静态校验
    let scan_result = validate_model(flow_model, trace_id);
    if (!scan_result.ok) {
        log(trace_id, 'CRIT', 'GATEWAY', 'Model Validation Failed: ' + scan_result.detail);
        exit(1);
    }

    // [Step 4] 翻译生成 JSON
    let caps = detect_singbox_caps(trace_id);
    let adapter_res = Adapter.translate(flow_model, caps, trace_id);
    if (!adapter_res.ok || !adapter_res.data) {
        log(trace_id, 'CRIT', 'GATEWAY', 'Adapter Translation Failed: ' + adapter_res.detail);
        exit(1);
    }

    // [Step 5] 落地为物理文件 (Artifact)
    ensure_dir(PATH.RUNTIME);
    let is_ok = writefile(candidate_path, adapter_res.data);
    if (!is_ok) {
        log(trace_id, 'CRIT', 'GATEWAY', 'Fatal: Failed to write candidate JSON artifact to disk!');
        exit(1);
    }

    log(trace_id, 'INFO', 'GATEWAY', 'Synchronous candidate generation SUCCESS: ' + candidate_path);
    log(trace_id, 'INFO', 'GATEWAY', '========================================');
    
    // 成功退出，允许 init.d 往下执行
    exit(0);

} catch (e) {
    let err_msg = "" + e;
    log(trace_id, 'CRIT', 'GATEWAY', 'Crash: Unhandled exception during synchronous generation: ' + err_msg);
    exit(1);
}
