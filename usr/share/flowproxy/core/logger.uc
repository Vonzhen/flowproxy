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

/**
 * P3 日志防失忆钩子 (V1.0 宪法对齐版)
 */
function logrotate() {
    try {
        // 1. 严格使用 Constants 常量
        ExecSafe(BIN.MKDIR, ["-p", PATH.LOG_ARCHIVE]);
        
        if (!stat(PATH.LOG_SYS)) return; 

        let dt_res = ExecSafe(BIN.DATE, ["+%Y%m%d_%H%M"]);
        let dt_str = (dt_res.ok && dt_res.data) ? trim(dt_res.data.stdout || "") : "" + time();
        let archive_file = sprintf("%s/sys_%s_warn.log", PATH.LOG_ARCHIVE, dt_str);
        
        // 2. 提取致命日志
        let cmd = sprintf("grep -E 'WARN|CRIT|ERROR|FATAL' %s > %s 2>/dev/null", PATH.LOG_SYS, archive_file);
        ExecSafe(BIN.SH, ["-c", cmd]);
        
        // 3. 🚨 架构修复：使用 Ucode 原生 fs 截断文件，保护常驻进程的 file descriptor
        let fd = open(PATH.LOG_SYS, "w");
        if (fd) {
            fd.write(""); // 写入空，底层自动截断至 0 字节
            fd.close();
        }
        
        // 4. 压缩并清理 7 天前存档
        ExecSafe(BIN.SH, ["-c", sprintf("gzip -f %s", archive_file)]);
        ExecSafe(BIN.SH, ["-c", sprintf("find %s -type f -name '*.gz' -mtime +7 -delete 2>/dev/null", PATH.LOG_ARCHIVE)]);
        
    } catch(e) {
        let err = "" + e;
    }
}

export { log, logrotate };
