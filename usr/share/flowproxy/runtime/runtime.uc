/**
 * FlowProxy | runtime/runtime.uc | v1.1 (Route B Aligned)
 * [Category B] 职责：纯粹的系统级真实世界（Reality Layer）安全操作代理（Facade）。
 * [Category C] Note: 本模块已剥离所有业务生命周期控制与配置生成权，
 * 仅作为底层网络栈装配与安全防线回退的受保护入口。
 */

'use strict';

// [Category A] 仅保留极简的安全守卫与底层系统操作模块依赖
import { allow_call } from 'flowproxy.core.guard';
import { setup, teardown } from 'flowproxy.system.network';
import { inject_bypass, execute_fallback } from 'flowproxy.system.safety';

// [Category A] 调用方身份上下文
const AUTH_CTX = { caller: 'runtime.manager' };

/**
 * [Category B] 内部私有函数：受保护的底层调用（权限守卫）
 */
function safe_exec(trace_id, from, to, fn) {
    allow_call(trace_id, from, to); 
    return fn();
}

/**
 * [Category B] 模块对外导出的主接口：系统操作代理层
 * 职能：封装针对 network 与 safety 层的安全调用，剥离所有配置翻译与进程启停逻辑。
 */
const RuntimeOrchestrator = {
    
    sys_setup: function(model, job_id) { 
        return safe_exec(job_id, 'runtime', 'system.network.setup', () => setup(model, job_id)); 
    },
    
    sys_teardown: function(job_id) { 
        return safe_exec(job_id, 'runtime', 'system.network.teardown', () => teardown(job_id)); 
    },
    
    sys_bypass: function(job_id) { 
        return safe_exec(job_id, 'runtime', 'system.safety.bypass', () => inject_bypass(job_id)); 
    },
    
    sys_fallback: function(job_id) { 
        return safe_exec(job_id, 'runtime', 'system.safety.fallback', () => execute_fallback(job_id)); 
    }
};

// [Category A] 遵守铁律 1: 绝对集中在文件末尾导出
export { RuntimeOrchestrator };
