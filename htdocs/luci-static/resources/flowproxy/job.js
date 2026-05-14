/**
 * --- [ FlowProxy | RPC 数据代理层 (Job API) | v1.0 SDK Aligned ] ---
 * 职责：纯粹的异步调度总线。
 * 架构对齐：全量接入 flowproxy.js 全局拦截器，彻底剥离原生 RPC 底层细节。
 */

'use strict';
'require baseclass';
'require flowproxy as SDK';

return baseclass.extend({
    // 发起异步任务
    start: function(job_type, payload) {
        return SDK.rpc_call('flowproxy.job', 'start', { 
            type: job_type, 
            payload: payload || {} 
        });
    },

    // 查询任务状态机
    status: function(job_id) {
        return SDK.rpc_call('flowproxy.job', 'status', { 
            job_id: job_id 
        });
    },

    // 按游标拉取执行日志
    log: function(job_id, cursor) {
        return SDK.rpc_call('flowproxy.job', 'log', { 
            job_id: job_id, 
            cursor: cursor || 0 
        });
    }
});
