/**
 * FlowProxy | core/logger.uc | v1.0
 * 统一日志黑匣子 (SSOT Aligned Edition)
 * 职责：约束所有的日志行为，提供系统级与任务级的标准化、可追踪输出。
 * 铁律：日志模块绝对禁止抛出异常（die），必须静默失败以保护主业务流。
 */

'use strict';

// 🚨 铁律 5: 原生模块解构导入
import { open } from 'fs';

// 🚨 铁律 3: 绝对命名空间寻址
import { PATH, BIN } from 'flowproxy.core.constants';
import { ExecSafe } from 'flowproxy.core.utils';

/**
 * 写入 1.0 标准化可追踪日志
 * 格式: [ts] [trace_id] [level] [module] message
 * @param {string} trace_id - 全链路追踪 ID
 * @param {string} level - INFO, WARN, CRIT
 * @param {string} mod - 模块名称 (如 RUNTIME, MODULES, SYSTEM)
 * @param {string} message - 日志内容
 */
function log(trace_id, level, mod, message) {
    try {
        // 保证物理路径存在
        ExecSafe(BIN.MKDIR, ["-p", PATH.JOB]);
        ExecSafe(BIN.MKDIR, ["-p", PATH.LOG_DIR]); // [Category C] Note: 补偿新建统一日志目录，防止文件句柄打开失败
        
        let path = PATH.LOG_SYS;
        let fd = open(path, "a+");
        
        if (fd) {
            let ts = "";
            let ts_res = ExecSafe(BIN.DATE, ["+%Y-%m-%d %H:%M:%S"]);
            
            // ⭐ 协议对齐与排雷：严格按照 Result 1.0 结构访问 .data.stdout
            if (ts_res.ok && ts_res.data) {
                ts = trim(ts_res.data.stdout || "");
            }
            if (ts == "") ts = "" + time(); // 兜底保障
            
            let t_id = trace_id ? trace_id : "SYS_NO_TRACE";
            let line = sprintf("[%s] [%s] [%s] [%s] %s\n", ts, t_id, level || "INFO", mod || "CORE", message || "");
            
            fd.write(line);
            fd.close();
        }
    } catch(e) {
        // 🚨 铁律 6: 隐式异常捕获转字符串。日志模块绝不能 die。
        let err = "" + e;
    }
}

// 🚨 铁律 1: 文件末尾统一导出
export { log };
