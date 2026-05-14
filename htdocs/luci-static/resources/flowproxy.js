/**
 * FlowProxy | 基础工具库模块 | v1.3 (SSOT Aligned & Strict Interceptor Fixed)
 * 职责：提供 Ubus 全局拦截代理、UI 视图渲染辅助引擎、及跨端数据格式化校验。
 * 核心：作为前端唯一的 RPC 出口与表单构建基座，强制执行 1.0 Result 协议断言。
 */

'use strict';
'require baseclass';
'require form';
'require fs';
'require rpc';
'require uci';
'require ui';

return baseclass.extend({
    /* --- 静态字典对齐 --- */
    dns_strategy: {
        '': _('Default'),
        'prefer_ipv4': _('Prefer IPv4'),
        'prefer_ipv6': _('Prefer IPv6'),
        'ipv4_only': _('IPv4 only'),
        'ipv6_only': _('IPv6 only')
    },

    shadowsocks_encrypt_methods: [
        'none', 'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm',
        'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305',
        '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
        '2022-blake3-chacha20-poly1305'
    ],

    tls_cipher_suites: [
        'TLS_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA',
        'TLS_RSA_WITH_AES_128_GCM_SHA256', 'TLS_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256'
    ],

    tls_versions: ['1.0', '1.1', '1.2', '1.3'],

    /**
     * =========================================================
     * 🛡️ L1: Global RPC Interceptor (1.0 强类型契约拦截器)
     * =========================================================
     */
    rpc_call: function(object, method, params) {
        let p_keys = [];
        let p_vals = [];
        
        // 🚨 架构修复：将对象打平为位置参数数组，防止 LuCI 将对象嵌套塞入单一变量
        if (params && typeof params === 'object') {
            p_keys = Object.keys(params);
            for (let i = 0; i < p_keys.length; i++) {
                p_vals.push(params[p_keys[i]]);
            }
        }

        const call_backend = rpc.declare({
            object: object,
            method: method,
            params: p_keys
            // 🚨 架构修复：彻底删除了破坏性的 expect: { '': {} }，让底层原样透传 Result JSON
        });

        // 🚨 架构修复：使用 apply 展开参数数组
        return call_backend.apply(null, p_vals).then(res => {
            // 状态 1: Ubus 通讯中断 (网络层或守护进程无响应)
            if (!res) {
                ui.addNotification(null, E('p', _('RPC Communication Error: No response from backend.')));
                return Promise.reject(new Error("E_RPC_TIMEOUT"));
            }

            // 状态 2: 严格拦截 1.0 Result 协议 (强类型断言防御)
            // 🚨 架构对齐：拒绝弱类型猜测。只要 ok 不为绝对的 true，一律视为违宪阻断！
            if (res.ok !== true) {
                let trace_id = res.trace_id || 'N/A';
                console.error(`[FlowProxy SDK] API Fault in ${object}.${method}. Trace: ${trace_id}`, res);
                
                let msg = res.error || _('System/Contract Error');
                let detail = res.detail ? ` (${res.detail})` : '';
                
                // 全局拦截渲染错误弹窗
                ui.addNotification(null, E('p', msg + detail), 'danger');
                
                // 阻断 Promise 链，绝不允许残缺/裸数据流入 View 层
                return Promise.reject(new Error("E_API_FAULT"));
            }

            // 状态 3: 成功，直接交付纯净的 Result.data 负载
            return res.data;
        }).catch(e => {
            // 过滤掉内部主动抛出的阻断错误，避免二次捕获弹窗
            if (e && e.message !== "E_RPC_TIMEOUT" && e.message !== "E_API_FAULT") {
                ui.addNotification(null, E('p', _('Network/System Error: ') + e.message));
            }
            return Promise.reject(e);
        });
    },

    /**
     * =========================================================
     * 🧩 L2: Business Methods (基于拦截器的业务封装)
     * =========================================================
     */
    getBuiltinFeatures: function() {
        return this.rpc_call('flowproxy.system', 'singbox_get_features', {});
    },

    uploadCertificate: function(type, filename, ev) {
        return ui.uploadFile('/tmp/flowproxy_certificate.tmp', ev.target)
        .then(res => {
            return this.rpc_call('flowproxy.system', 'certificate_write', { filename: filename })
            .then(() => {
                ui.addNotification(null, E('p', _('Your %s was successfully uploaded. Size: %sB.').format(type, res.size)));
            });
        })
        .catch(e => { /* 错误已由拦截器处理 */ });
    },

    /**
     * =========================================================
     * 🎨 L3: UI Rendering Helpers (恢复的表单构建辅助组件)
     * =========================================================
     */
    loadDefaultLabel: function(uciconfig, ucisection) {
        let label = uci.get(uciconfig, ucisection, 'label');
        if (label) {
            return label;
        } else {
            uci.set(uciconfig, ucisection, 'label', ucisection);
            return ucisection;
        }
    },

    loadModalTitle: function(title, addtitle, uciconfig, ucisection) {
        let label = uci.get(uciconfig, ucisection, 'label');
        return label ? title + ' » ' + label : addtitle;
    },

    renderSectionAdd: function(section, extra_class) {
        let el = form.GridSection.prototype.renderSectionAdd.apply(section, [ extra_class ]),
            nameEl = el.querySelector('.cbi-section-create-name');
        ui.addValidator(nameEl, 'uciname', true, (v) => {
            let button = el.querySelector('.cbi-section-create > .cbi-button-add');
            let uciconfig = section.uciconfig || section.map.config;
            if (!v) {
                button.disabled = true;
                return true;
            } else if (uci.get(uciconfig, v)) {
                button.disabled = true;
                return _('Expecting: %s').format(_('unique UCI identifier'));
            } else {
                button.disabled = null;
                return true;
            }
        }, 'blur', 'keyup');
        return el;
    },

    /* --- UI 辅助组件与校验器 --- */
    CBIStaticList: form.DynamicList.extend({
        __name__: 'CBI.StaticList',
        renderWidget: function() {
            let dl = form.DynamicList.prototype.renderWidget.apply(this, arguments);
            dl.querySelector('.add-item ul > li[data-value="-"]')?.remove();
            return dl;
        }
    }),

    decodeBase64Str: function(str) {
        if (!str) return null;
        str = str.replace(/-/g, '+').replace(/_/g, '/');
        let padding = (4 - str.length % 4) % 4;
        if (padding) str = str + Array(padding + 1).join('=');
        return decodeURIComponent(Array.prototype.map.call(atob(str), (c) =>
            '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
        ).join(''));
    },

    calcStringMD5: function(e) {
        let h = (a, b) => {
            let g = (a & 1073741823) + (b & 1073741823);
            return (a & 1073741824) & (b & 1073741824) ? g ^ 2147483648 ^ (a & 2147483648) ^ (b & 2147483648) : g ^ (a & 2147483648) ^ (b & 2147483648);
        }, k = (a, b, c, d, e, f, g) => h((a = h(a, h(h(b & c | ~b & d, e), g))) << f | a >>> 32 - f, b),
        l = (a, b, c, d, e, f, g) => h((a = h(a, h(h(b & d | c & ~d, e), g))) << f | a >>> 32 - f, b),
        m = (a, b, c, d, e, f, g) => h((a = h(a, h(h(b ^ c ^ d, e), g))) << f | a >>> 32 - f, b),
        n = (a, b, c, d, e, f, g) => h((a = h(a, h(h(c ^ (b | ~d), e), g))) << f | a >>> 32 - f, b),
        p = a => { let b = '', d = ''; for (let c = 0; c <= 3; c++) { d = a >>> 8 * c & 255; d = '0' + d.toString(16); b += d.substr(d.length - 2, 2); } return b; };

        let f = [], q, r, s, t, a, b, c, d;
        e = (() => {
            e = e.replace(/\r\n/g, '\n');
            let b = '';
            for (let d = 0; d < e.length; d++) {
                let c = e.charCodeAt(d);
                b += c < 128 ? String.fromCharCode(c) : c < 2048 ? String.fromCharCode(c >> 6 | 192) + String.fromCharCode(c & 63 | 128) :
                    String.fromCharCode(c >> 12 | 224) + String.fromCharCode(c >> 6 & 63 | 128) + String.fromCharCode(c & 63 | 128);
            }
            return b;
        })();
        f = (() => {
            let c = e.length, a = c + 8, d = 16 * ((a - a % 64) / 64 + 1), b = Array(d - 1), f = 0, g = 0;
            for (; g < c;) { a = (g - g % 4) / 4; f = g % 4 * 8; b[a] |= e.charCodeAt(g) << f; g++; }
            a = (g - g % 4) / 4; b[a] |= 128 << g % 4 * 8; b[d - 2] = c << 3; b[d - 1] = c >>> 29;
            return b;
        })();

        a = 1732584193; b = 4023233417; c = 2562383102; d = 271733878;
        for (e = 0; e < f.length; e += 16) {
            q = a; r = b; s = c; t = d;
            a = k(a, b, c, d, f[e +  0],  7, 3614090360); d = k(d, a, b, c, f[e +  1], 12, 3905402710);
            c = k(c, d, a, b, f[e +  2], 17,  606105819); b = k(b, c, d, a, f[e +  3], 22, 3250441966);
            a = k(a, b, c, d, f[e +  4],  7, 4118548399); d = k(d, a, b, c, f[e +  5], 12, 1200080426);
            c = k(c, d, a, b, f[e +  6], 17, 2821735955); b = k(b, c, d, a, f[e +  7], 22, 4249261313);
            a = k(a, b, c, d, f[e +  8],  7, 1770035416); d = k(d, a, b, c, f[e +  9], 12, 2336552879);
            c = k(c, d, a, b, f[e + 10], 17, 4294925233); b = k(b, c, d, a, f[e + 11], 22, 2304563134);
            a = k(a, b, c, d, f[e + 12],  7, 1804603682); d = k(d, a, b, c, f[e + 13], 12, 4254626195);
            c = k(c, d, a, b, f[e + 14], 17, 2792965006); b = k(b, c, d, a, f[e + 15], 22, 1236535329);
            a = l(a, b, c, d, f[e +  1],  5, 4129170786); d = l(d, a, b, c, f[e +  6],  9, 3225465664);
            c = l(c, d, a, b, f[e + 11], 14,  643717713); b = l(b, c, d, a, f[e +  0], 20, 3921069994);
            a = l(a, b, c, d, f[e +  5],  5, 3593408605); d = l(d, a, b, c, f[e + 10],  9,   38016083);
            c = l(c, d, a, b, f[e + 15], 14, 3634488961); b = l(b, c, d, a, f[e +  4], 20, 3889429448);
            a = l(a, b, c, d, f[e +  9],  5,  568446438); d = l(d, a, b, c, f[e + 14],  9, 3275163606);
            c = l(c, d, a, b, f[e +  3], 14, 4107603335); b = l(b, c, d, a, f[e +  8], 20, 1163531501);
            a = l(a, b, c, d, f[e + 13],  5, 2850285829); d = l(d, a, b, c, f[e +  2],  9, 4243563512);
            c = l(c, d, a, b, f[e +  7], 14, 1735328473); b = l(b, c, d, a, f[e + 12], 20, 2368359562);
            a = m(a, b, c, d, f[e +  5],  4, 4294588738); d = m(d, a, b, c, f[e +  8], 11, 2272392833);
            c = m(c, d, a, b, f[e + 11], 16, 1839030562); b = m(b, c, d, a, f[e + 14], 23, 4259657740);
            a = m(a, b, c, d, f[e +  1],  4, 2763975236); d = m(d, a, b, c, f[e +  4], 11, 1272893353);
            c = m(c, d, a, b, f[e +  7], 16, 4139469664); b = m(b, c, d, a, f[e + 10], 23, 3200236656);
            a = m(a, b, c, d, f[e + 13],  4,  681279174); d = m(d, a, b, c, f[e +  0], 11, 3936430074);
            c = m(c, d, a, b, f[e +  3], 16, 3572445317); b = m(b, c, d, a, f[e +  6], 23,   76029189);
            a = m(a, b, c, d, f[e +  9],  4, 3654602809); d = m(d, a, b, c, f[e + 12], 11, 3873151461);
            c = m(c, d, a, b, f[e + 15], 16,  530742520); b = m(b, c, d, a, f[e +  2], 23, 3299628645);
            a = n(a, b, c, d, f[e +  0],  6, 4096336452); d = n(d, a, b, c, f[e +  7], 10, 1126891415);
            c = n(c, d, a, b, f[e + 14], 15, 2878612391); b = n(b, c, d, a, f[e +  5], 21, 4237533241);
            a = n(a, b, c, d, f[e + 12],  6, 1700485571); d = n(d, a, b, c, f[e +  3], 10, 2399980690);
            c = n(c, d, a, b, f[e + 10], 15, 4293915773); b = n(b, c, d, a, f[e +  1], 21, 2240044497);
            a = n(a, b, c, d, f[e +  8],  6, 1873313359); d = n(d, a, b, c, f[e + 15], 10, 4264355552);
            c = n(c, d, a, b, f[e +  6], 15, 2734768916); b = n(b, c, d, a, f[e + 13], 21, 1309151649);
            a = n(a, b, c, d, f[e +  4],  6, 4149444226); d = n(d, a, b, c, f[e + 11], 10, 3174756917);
            c = n(c, d, a, b, f[e +  2], 15,  718787259); b = n(b, c, d, a, f[e +  9], 21, 3951481745);
            a = h(a, q); b = h(b, r); c = h(c, s); d = h(d, t);
        }
        return (p(a) + p(b) + p(c) + p(d)).toLowerCase();
    },

    generateRand: function(type, length) {
        let byteArr;
        if (['base64', 'hex'].includes(type))
            byteArr = crypto.getRandomValues(new Uint8Array(length));
        switch (type) {
            case 'base64': return btoa(String.fromCharCode.apply(null, byteArr));
            case 'hex': return Array.from(byteArr, b => (b & 255).toString(16).padStart(2, '0')).join('');
            case 'uuid': return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c => (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16));
            default: return null;
        }
    },

    /* --- 严格模式校验器 --- */
    validateUUID: function(section_id, value) {
        if (section_id && value) {
            if (!value.match(/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/))
                return _('Expecting: %s').format(_('valid uuid'));
        }
        return true;
    },

    validateBase64Key: function(length, section_id, value) {
        if (section_id && value)
            if (value.length !== length || !value.match(/^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/) || value[length-1] !== '=')
                return _('Expecting: %s').format(_('valid base64 key with %d characters').format(length));
        return true;
    },

    validateCertificatePath: function(section_id, value) {
        if (section_id && value)
            if (!value.match(/^(\/etc\/flowproxy\/certs\/|\/etc\/acme\/|\/etc\/ssl\/).+$/))
                return _('Expecting: %s').format(_('/etc/flowproxy/certs/..., /etc/acme/..., /etc/ssl/...'));
        return true;
    },

    validatePortRange: function(section_id, value) {
        if (section_id && value) {
            let m = value.match(/^(\d+)?\:(\d+)?$/);
            if (m && (m[1] || m[2])) {
                let p1 = m[1] ? parseInt(m[1]) : 0;
                let p2 = m[2] ? parseInt(m[2]) : 65535;
                if (p1 < p2 && p2 <= 65535) return true;
            }
            return _('Expecting: %s').format(_('valid port range (port1:port2)'));
        }
        return true;
    },

    validateUniqueValue: function(uciconfig, ucisection, ucioption, section_id, value) {
        if (section_id && value) {
            if (ucioption === 'node' && value === 'urltest') return true;
            let duplicate = false;
            uci.sections(uciconfig, ucisection, (res) => {
                if (res['.name'] !== section_id && res[ucioption] === value) duplicate = true;
            });
            if (duplicate) return _('Expecting: %s').format(_('unique value'));
        }
        return true;
    }
});
