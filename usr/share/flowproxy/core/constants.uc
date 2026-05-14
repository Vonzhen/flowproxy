/**
 * FlowProxy | core/constants.uc | v1.1
 * 唯一物理真相源 (Strict Immutable Edition)
 * 职责：定义全系统所有不可变的路径、二进制位置、系统限额。
 * 核心规则：纯静态数据源。禁止任何模块私自定义路径字符串，严禁在运行时修改。
 */

'use strict';

/**
 * [ IMMUTABLE CONSTANT TABLE ]
 * [ DO NOT MODIFY AT RUNTIME ]
 * 绝对路径坐标系 (UI 意图落地与系统运行态的物理锚点)
 */
const PATH = {
    BASE:     "/usr/share/flowproxy",                  // [Category A] 基础逻辑寻址目录 (新增: 供 worker.uc 定位网关脚本)
    INIT:     "/etc/init.d/flowproxy",                 // [Category A] 系统生命周期总线脚本位置 (新增: 供 worker.uc 触发重启)
    UCI:      "/etc/config/flowproxy",                 // [Category A] 真相源 (SSOT)
    RUNTIME:  "/var/run/flowproxy",                    // [Category A] 运行态根目录
    RUNNING_PID: "/var/run/flowproxy.pid",             // [Category A] 真实的守护进程 PID 凭证路径
    JOB:      "/var/run/flowproxy/jobs",               // [Category A] 异步任务锁与状态目录
    LOG_DIR:  "/var/run/flowproxy/logs",               // [Category B] 统一聚合日志基准目录
    LOG_SYS:  "/var/run/flowproxy/logs/system.log",    // [Category B] 架构系统级日志
    LOG_RUN:  "/var/run/flowproxy/logs/sing-box.log",  // [Category B] 内核运行级日志
    ASSETS:   "/etc/flowproxy/resources",              // [Category A] 资源基目录
    RULESET:  "/etc/flowproxy/ruleset",                // [Category A] 规则集存放目录
    PANELS:   "/www/zashboard",                        // [Category A] 前端面板部署物理路径
    RUN_JSON: "/var/run/flowproxy/sing-box-run.json"   // [Category A] 最终供给内核的 JSON
};

/**
 * [ IMMUTABLE CONSTANT TABLE ]
 * [ DO NOT MODIFY AT RUNTIME ]
 * 二进制执行文件白名单 (严禁直接使用裸命令字符串)
 */
const BIN = {
    SH:      "/bin/sh",
    UCODE:   "/usr/bin/ucode",                         // [Category A] Ucode 执行引擎 (新增: 供 worker.uc 唤起预检沙盒)
    SINGBOX: "/usr/bin/sing-box",
    CURL:    "/usr/bin/curl",
    PIDOF:   "/bin/pidof",
    TIMEOUT: "/usr/bin/timeout",
    TAR:     "/bin/tar",
    UNZIP:   "/usr/bin/unzip",
    LN:      "/bin/ln",
    NFT:     "/usr/sbin/nft",
    IP:      "/usr/sbin/ip",
    NETSTAT: "/bin/netstat",
    MKDIR:   "/bin/mkdir",
    RM:      "/bin/rm",
    MV:      "/bin/mv",
    CP:      "/bin/cp",
    DATE:    "/bin/date"
};

/**
 * [ IMMUTABLE CONSTANT TABLE ]
 * 物理资源与时间限额
 */
const LIMIT = {
    PROBE_TIMEOUT: 10,       // 连通性探测超时 (秒)
    DL_TIMEOUT:    60,       // 资源下载超时 (秒)
    JOB_TIMEOUT:   600,      // 异步长任务全局超时 (10分钟)
    MAX_READ:      8192,     // 默认单次读取 8KB
    LOCK_RETRY:    5         // 锁抢占重试次数
};

// 🚨 铁律 1: 文件末尾统一导出
export { PATH, BIN, LIMIT };
