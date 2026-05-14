/**
 * FlowProxy | core/lock.uc | v1.0
 * VFS 级原子目录锁 (SSOT Aligned Edition)
 * 职责：提供基于 Linux 目录创建原子性的并发锁机制。防范 ucode flock() 暴毙缺陷。
 * 核心对齐：全面接入基石路径与 Trace 追踪。
 */

'use strict';

// 🚨 铁律 3: 绝对命名空间寻址
import { ExecSafe } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';
import { PATH, BIN } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';

/**
 * 尝试获取系统原子锁
 * @param {string} trace_id 
 */
function acquire(trace_id) {
    // 1. 确保基础运行目录存在
    ExecSafe(BIN.MKDIR, ["-p", PATH.RUNTIME], null, trace_id);

    let dir_lock = sprintf("%s/worker.lock", PATH.RUNTIME);

    // 2. 利用 Linux mkdir 的内核级原子特性进行抢锁 (🚨 铁律 4: 规避原生 flock)
    let res = ExecSafe(BIN.MKDIR, [dir_lock], null, trace_id);
    
    // ⭐ 协议对齐：适配 1.0 的 ExecSafe 返回值
    if (!res.ok) {
        log(trace_id, "WARN", "LOCK", "System busy. Lock directory already exists.");
        // 返回标准 Fail 协议，携带 code 和 trace_id
        return Fail(ERR.E_SYSTEM_BUSY, "Lock directory already exists", trace_id);
    }

    // 3. 抢锁成功，返回包含释放句柄的标准 Success 对象
    return Success({
        release: function() {
            // ⭐ 契约对齐：释放锁时也使用沙箱与常量子典
            ExecSafe(BIN.RM, ["-rf", dir_lock], null, trace_id);
        }
    }, 200, trace_id);
}

// 🚨 铁律 1: 文件末尾统一导出
export { acquire };
