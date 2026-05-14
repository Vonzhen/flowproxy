/**
 * FlowProxy | core/trace.uc | v1.0
 * 职责：生成跨模块调用的唯一标识符 (Trace ID)，用于日志贯穿与故障回溯。
 */

'use strict';

// [Note] 模块级私有状态：自增序列计数器。
// 驻留于内存顶层作用域，提供 O(1) 性能的唯一性保障，彻底阻断外部 math 库依赖风险。
let _seq = 0;

/**
 * 生成全链路唯一追踪 ID
 * 格式：tx_时间戳_序列号 (例如: tx_1715000000_0001)
 * 
 * @returns {string} 追踪标识
 */
function init() {
    let t = time();
    
    // 每次调用自增，到达 65535 (0xFFFF) 后安全溢出归零
    _seq = (_seq + 1) % 65536;
    
    return sprintf("tx_%d_%04x", t, _seq);
}

// 🚨 遵守铁律 1: 绝对集中在文件末尾导出 (此文件为被引用的 Module 零件)
export { init };
