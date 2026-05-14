/**
 * FlowProxy | core/types.uc | v1.0
 * 纯净数据标准 (Strict Immutable Edition)
 * 职责：定义系统所需的基础数据结构格式与正则表达式约束。
 * 环境适配：全量改用 regexp() 构造函数，平铺非捕获组，完美兼容 POSIX ERE 引擎。
 */

'use strict';

/**
 * [ IMMUTABLE REGEX TABLE ]
 * [ DO NOT MODIFY AT RUNTIME ]
 * 全系统通用的模式匹配标准。
 * 警告(Category C): 此处正则字符串在编译期交由底层引擎处理，必须进行双重转义(\\)
 */
const REGEX = {
    // 消除 (?:...)，平铺为显式的 4 段结构匹配
    IP:     regexp('^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$'),
    
    // 消除 (?:...)，改用标准捕获组
    DOMAIN: regexp('^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$'),
    
    // UUID 标准结构
    UUID:   regexp('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    
    // TAG 标签基础字符集
    TAG:    regexp('^[a-zA-Z0-9_.-]+$')
};

// 遵循身份二元论：作为零件(Module)，必须暴露导出
export { REGEX };
