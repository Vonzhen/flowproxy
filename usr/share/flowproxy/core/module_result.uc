/**
 * FlowProxy | core/module_result.uc | v1.0
 * Module 纯执行载荷辅助：统一 changed 字段，reload 决策由 Worker 独占。
 */

'use strict';

/**
 * @param {boolean} changed - 是否产生需要数据面跟进的实质变更
 * @param {object} fields - 模块元数据（updated/version/nodes 等）
 */
function with_changed(changed, fields) {
    let data = { changed: !!changed };
    if (fields && type(fields) === 'object') {
        for (let k in fields) {
            data[k] = fields[k];
        }
    }
    return data;
}

export { with_changed };
