/**
 * FlowProxy | core/lock.uc | v1.1
 * VFS 级原子目录锁 (SSOT Aligned Edition)
 * 职责：提供基于 Linux 目录创建原子性的并发锁机制。防范 ucode flock() 暴毙缺陷。
 */

'use strict';

import { ExecSafe } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';
import { PATH, BIN } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';

function acquire(trace_id) {
    // 1. 确保基础运行目录存在
    ExecSafe(BIN.MKDIR, ["-p", PATH.RUNTIME], null, trace_id);

    let dir_lock = sprintf("%s/worker.lock", PATH.RUNTIME);

    // 2. 利用 Linux mkdir 的内核级原子特性进行抢锁 (非阻塞式)
    let res = ExecSafe(BIN.MKDIR, [dir_lock], null, trace_id);
    
    if (!res.ok) {
        log(trace_id, "WARN", "LOCK", "System busy. Worker lock directory already exists.");
        return Fail(ERR.E_SYSTEM_BUSY, "Worker is already running (Lock exists)", trace_id);
    }

    // 3. 抢锁成功，返回包含物理释放句柄的对象
    return Success({
        release: function() {
            ExecSafe(BIN.RM, ["-rf", dir_lock], null, trace_id);
        }
    }, 200, trace_id);
}

export { acquire };
