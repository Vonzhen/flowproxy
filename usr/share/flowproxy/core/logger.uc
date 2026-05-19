/**
 * FlowProxy | core/logger.uc | v1.1
 * 统一日志黑匣子 (SSOT Aligned Edition)
 * 架构修正：彻底剥离环境装配权，完全依赖 init.d 的目录初始化。
 */

'use strict';

import { open, stat } from 'fs';
import { PATH, BIN } from 'flowproxy.core.constants';
import { ExecSafe } from 'flowproxy.core.utils';

/**
 * 写入 1.0 标准化可追踪日志
 */
function log(trace_id, level, mod, message) {
    try {
        // 🚨 架构修正：删除了这里原有的 MKDIR 越权行为，直接假设 PATH.LOG_SYS 所在目录已就绪
        let path = PATH.LOG_SYS;
        let fd = open(path, "a+");
        
        if (fd) {
            let ts = "";
            let ts_res = ExecSafe(BIN.DATE, ["+%Y-%m-%d %H:%M:%S"]);
            if (ts_res.ok && ts_res.data) {
                ts = trim(ts_res.data.stdout || "");
            }
            if (ts == "") ts = "" + time(); 
            
            let t_id = trace_id ? trace_id : "SYS_NO_TRACE";
            let line = sprintf("[%s] [%s] [%s] [%s] %s\n", ts, t_id, level || "INFO", mod || "CORE", message || "");
            
            fd.write(line);
            fd.close();
        }
    } catch(e) {
        let err = "" + e;
    }
}

/**
 * P3 日志防失忆钩子
 */
function logrotate() {
    try {
        // 🚨 架构修正：删除了这里原有的 MKDIR 越权行为，直接使用 PATH.LOG_ARCHIVE
        
        if (!stat(PATH.LOG_SYS)) return; 

        let dt_res = ExecSafe(BIN.DATE, ["+%Y%m%d_%H%M"]);
        let dt_str = (dt_res.ok && dt_res.data) ? trim(dt_res.data.stdout || "") : "" + time();
        let archive_file = sprintf("%s/sys_%s_warn.log", PATH.LOG_ARCHIVE, dt_str);
        
        // 提取致命日志
        let cmd = sprintf("grep -E 'WARN|CRIT|ERROR|FATAL' %s > %s 2>/dev/null", PATH.LOG_SYS, archive_file);
        ExecSafe(BIN.SH, ["-c", cmd]);
        
        // 截断文件，保护句柄
        let fd = open(PATH.LOG_SYS, "w");
        if (fd) {
            fd.write(""); 
            fd.close();
        }
        
        // 压缩并清理 7 天前存档
        ExecSafe(BIN.SH, ["-c", sprintf("gzip -f %s", archive_file)]);
        ExecSafe(BIN.SH, ["-c", sprintf("find %s -type f -name '*.gz' -mtime +7 -delete 2>/dev/null", PATH.LOG_ARCHIVE)]);
        
    } catch(e) {
        let err = "" + e;
    }
}

export { log, logrotate };
