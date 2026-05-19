/**
 * FlowProxy | runtime/launcher.uc | v1.2 (Sandbox Edition)
 * 职责：只读的内核配置离线校验器 (Sandbox Validator)
 * 边界：剥夺了启停控制权，专职负责在配置应用前使用 sing-box check 进行离线安检。
 */

'use strict';

import { stat } from 'fs';
import { PATH, BIN } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { ExecSafe } from 'flowproxy.core.utils';

function _validate_path(path) {
    if (type(path) !== 'string') return false;
    let runtime_dir = PATH.RUNTIME;
    if (substr(path, 0, length(runtime_dir)) !== runtime_dir) return false;
    if (index(path, '../') >= 0 || index(path, '..\\') >= 0) return false;
    if (!match(path, regexp('\\.json$'))) return false;
    return true;
}

/**
 * 校验配置文件合法性 (由 worker.uc 在事务准备阶段调用)
 */
function check(config_path, ctx, trace_id) {
    try {
        if (!ctx || ctx.caller !== 'runtime.manager') {
            return Fail(ERR.E_AUTH_DENIED, "Caller Unauthorized", trace_id);
        }

        if (!_validate_path(config_path)) {
            return Fail(ERR.E_SYSTEM_BUSY, "Security Violation: Illegal config path", trace_id);
        }

        if (!stat(BIN.SINGBOX)) {
            return Fail(ERR.E_ENV_MISSING, "Binary Missing: sing-box not found", trace_id);
        }

        // 调用内核命令进行离线预检，绝不启动进程
        let res = ExecSafe(BIN.SINGBOX, ["check", "-c", config_path], { timeout: 10 }, trace_id);
        
        if (res.ok) {
            return Success(res.data, 200, trace_id);
        }
        return Fail(ERR.E_CONFIG_FAULT, res.detail, trace_id);

    } catch(e) {
        let err_str = "" + e;
        return Fail(ERR.E_SYSTEM_BUSY, "Launcher Check Exception: " + err_str, trace_id);
    }
}

// 剔除越权的 reload 和 stop，仅暴露 check 契约
export { check };
