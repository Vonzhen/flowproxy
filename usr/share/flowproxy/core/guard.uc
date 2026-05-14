/**
 * FlowProxy | core/guard.uc | v1.0
 * 执行路径强制收敛守卫 (SSOT Aligned Edition)
 * 职责：执行路径强制收敛与越权熔断。
 * 核心对齐：全面接入 Trace 追踪，触发标准防爆熔断 (Rule 6)。
 */

'use strict';

// 🚨 铁律 3: 绝对命名空间寻址
import { log } from 'flowproxy.core.logger';
import { ERR } from 'flowproxy.core.error';

/**
 * 执行路径拦截与守卫
 * @param {string} trace_id 全链路追踪 ID
 * @param {string} from 调用方标识
 * @param {string} to 目标方标识
 */
function allow_call(trace_id, from, to) {
    // 1. 契约对齐：所有经过 Guard 的调用，必定留下可追溯的日志
    log(trace_id, 'INFO', 'GUARD', sprintf("CALL: %s -> %s", from, to));

    // 2. 铁律校验：目标如果是 system 层（如拆建网卡、改防火墙）
    if (index(to, "system") == 0) {
        // 来源必须是 runtime。否则直接击毙，零隐式故障！
        if (from != "runtime") {
            // 🚨 铁律 6: 抛出异常使用 die() 并且熔断必须挂钩标准错误字典
            die(sprintf("[FATAL] %s: %s -> %s", ERR.E_AUTH_DENIED.msg, from, to));
        }
    }

    // 拦截器断言通过，纯内部布尔逻辑
    return true;
}

// 🚨 铁律 1: 文件末尾统一导出
export { allow_call };
