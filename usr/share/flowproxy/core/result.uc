/**
 * FlowProxy | core/result.uc | v1.0
 * 唯一交互标准 (Strict Immutable Edition)
 * 职责：强制所有函数返回统一格式，构造标准响应体。
 * 核心规则：协议级构造器。全系统模块交互必须返回此对象，严禁篡改属性名。
 */

'use strict';

/**
 * [ IMMUTABLE PROTOCOL FUNCTION ]
 * 构造成功响应体 (1.0 标准)
 * @param {any} data - 成功时的业务载荷
 * @param {number} code - 业务状态码 (默认 200)
 * @param {string} trace_id - 全链路追踪 ID
 */
function Success(data, code, trace_id) {
    return { 
        ok: true, 
        code: code || 200, 
        data: data, 
        error: "", 
        detail: "", 
        trace_id: trace_id || "", 
        ts: time() 
    };
}

/**
 * [ IMMUTABLE PROTOCOL FUNCTION ]
 * 构造失败响应体 (1.0 标准)
 * 强制依赖 core/error.uc 的错误常量对象
 * @param {object} err_obj - 错误常量对象 (包含 code, msg, severity 等)
 * @param {string} detail - 具体排障细节 (如 catch 捕获的异常字符串)
 * @param {string} trace_id - 全链路追踪 ID
 */
function Fail(err_obj, detail, trace_id) {
    return { 
        ok: false, 
        code: err_obj?.code || 500, 
        data: null, 
        error: err_obj?.msg || "Unknown Error", 
        detail: detail || "", 
        trace_id: trace_id || "", 
        ts: time() 
    };
}

// 🚨 铁律 1: 文件末尾统一导出
export { Success, Fail };
