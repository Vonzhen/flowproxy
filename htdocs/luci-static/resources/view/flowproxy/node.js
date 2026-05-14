// --- [ FlowProxy | Node & Subscription 视图模块 | v1.2 ] ---
// 功能：渲染节点配置与订阅管理表单，触发数据面状态机流转
// 职责：持久化配置 (UCI Mapping) 并安全提交调度指令至全局异步引擎 (Job Observer)

// --- [ 变更记录 ] ---
// v1.2 (2026-04-26)
// - 修复：对齐后端 Worker 契约，修正 update_subscriptions 的 Payload 参数 (airport_id, scope: 'all')
// - 确保：补全 rebuild_groups 调度指令
// v1.1 (2026-04-24)
// - 重构：全量剥离 fs.exec_direct 越权调用，引入 flowproxy.job 桥接器
// - 优化：废弃旧版基于 URL 的主键模型，对齐 FlowProxy v1.1 新版 Schema
// v1.0 (2022-01-01)
// - 新增：基于 ImmortalWrt HomeProxy 的初始化实现

// --- [ 初始化 ] ---
'use strict';
'require form';
'require fs';
'require uci';
'require ui';
'require view';

'require flowproxy as fp';
'require tools.widgets as widgets';
'require flowproxy.observer as observer';

// --- [ 子模块1：辅助与解析引擎 ] ---
function allowInsecureConfirm(ev, _section_id, value) {
    if (value === '1' && !confirm(_('Are you sure to allow insecure?')))
        ev.target.firstElementChild.checked = null;
}

function parseShareLink(uri, features) {
    let config, url, params;

    uri = uri.split('://');
    if (uri[0] && uri[1]) {
        switch (uri[0]) {
        case 'anytls':
            url = new URL('http://' + uri[1]);
            params = url.searchParams;

            if (!url.username)
                return null;

            config = {
                label: url.hash ? decodeURIComponent(url.hash.slice(1)) : null,
                type: 'anytls',
                address: url.hostname,
                port: url.port || '80',
                password: url.username ? decodeURIComponent(url.username) : null,
                tls: '1',
                tls_sni: params.get('sni'),
                tls_insecure: (params.get('insecure') === '1') ? '1' : '0'
            };

            break;
        case 'http':
        case 'https':
            url = new URL('http://' + uri[1]);

            config = {
                label: url.hash ? decodeURIComponent(url.hash.slice(1)) : null,
                type: 'http',
                address: url.hostname,
                port: url.port || '80',
                username: url.username ? decodeURIComponent(url.username) : null,
                password: url.password ? decodeURIComponent(url.password) : null,
                tls: (uri[0] === 'https') ? '1' : '0'
            };

            break;
        case 'hysteria':
            url = new URL('http://' + uri[1]);
            params = url.searchParams;

            if (!features.with_quic || (params.get('protocol') && params.get('protocol') !== 'udp'))
                return null;

            config = {
                label: url.hash ? decodeURIComponent(url.hash.slice(1)) : null,
                type: 'hysteria',
                address: url.hostname,
                port: url.port || '80',
                hysteria_protocol: params.get('protocol') || 'udp',
                hysteria_auth_type: params.get('auth') ? 'string' : null,
                hysteria_auth_payload: params.get('auth'),
                hysteria_obfs_password: params.get('obfsParam'),
                hysteria_down_mbps: params.get('downmbps'),
                hysteria_up_mbps: params.get('upmbps'),
                tls: '1',
                tls_sni: params.get('peer'),
                tls_alpn: params.get('alpn'),
                tls_insecure: (params.get('insecure') === '1') ? '1' : '0'
            };

            break;
        case 'hysteria2':
        case 'hy2':
            url = new URL('http://' + uri[1]);
            params = url.searchParams;

            if (!features.with_quic)
                return null;

            config = {
                label: url.hash ? decodeURIComponent(url.hash.slice(1)) : null,
                type: 'hysteria2',
                address: url.hostname,
                port: url.port || '80',
                password: url.username ? (
                    decodeURIComponent(url.username + (url.password ? (':' + url.password) : ''))
                ) : null,
                hysteria_obfs_type: params.get('obfs'),
                hysteria_obfs_password: params.get('obfs-password'),
                tls: '1',
                tls_sni: params.get('sni'),
                tls_insecure: params.get('insecure') ? '1' : '0'
            };

            break;
        case 'socks':
        case 'socks4':
        case 'socks4a':
        case 'socsk5':
        case 'socks5h':
            url = new URL('http://' + uri[1]);

            config = {
                label: url.hash ? decodeURIComponent(url.hash.slice(1)) : null,
                type: 'socks',
                address: url.hostname,
                port: url.port || '80',
                username: url.username ? decodeURIComponent(url.username) : null,
                password: url.password ? decodeURIComponent(url.password) : null,
                socks_version: (uri[0].includes('4')) ? '4' : '5'
            };

            break;
        case 'ss':
            try {
                try {
                    let suri = uri[1].split('#'), slabel = '';
                    if (suri.length <= 2) {
                        if (suri.length === 2)
                            slabel = '#' + suri[1];
                        uri[1] = fp.decodeBase64Str(suri[0]) + slabel;
                    }
                } catch(e) { }

                url = new URL('http://' + uri[1]);

                let userinfo;
                if (url.username && url.password) {
                    userinfo = [url.username, decodeURIComponent(url.password)];
                } else if (url.username) {
                    userinfo = fp.decodeBase64Str(decodeURIComponent(url.username)).split(':');
                    if (userinfo.length > 1)
                        userinfo = [userinfo[0], userinfo.slice(1).join(':')]
                }

                if (!fp.shadowsocks_encrypt_methods.includes(userinfo[0]))
                    return null;

                let plugin, plugin_opts;
                if (url.search && url.searchParams.get('plugin')) {
                    let plugin_info = url.searchParams.get('plugin').split(';');
                    plugin = plugin_info[0];
                    plugin_opts = (plugin_info.length > 1) ? plugin_info.slice(1).join(';') : null;
                }

                config = {
                    label: url.hash ? decodeURIComponent(url.hash.slice(1)) : null,
                    type: 'shadowsocks',
                    address: url.hostname,
                    port: url.port || '80',
                    shadowsocks_encrypt_method: userinfo[0],
                    password: userinfo[1],
                    shadowsocks_plugin: plugin,
                    shadowsocks_plugin_opts: plugin_opts
                };
            } catch(e) {
                uri = uri[1].split('@');
                if (uri.length < 2)
                    return null;
                else if (uri.length > 2)
                    uri = [ uri.slice(0, -1).join('@'), uri.slice(-1).toString() ];

                config = {
                    type: 'shadowsocks',
                    address: uri[1].split(':')[0],
                    port: uri[1].split(':')[1],
                    shadowsocks_encrypt_method: uri[0].split(':')[0],
                    password: uri[0].split(':').slice(1).join(':')
                };
            }

            break;
        case 'trojan':
            url = new URL('http://' + uri[1]);
            params = url.searchParams;

            if (!url.username)
                return null;

            config = {
                label: url.hash ? decodeURIComponent(url.hash.slice(1)) : null,
                type: 'trojan',
                address: url.hostname,
                port: url.port || '80',
                password: decodeURIComponent(url.username),
                transport: params.get('type') !== 'tcp' ? params.get('type') : null,
                tls: '1',
                tls_sni: params.get('sni')
            };
            switch (params.get('type')) {
            case 'grpc':
                config.grpc_servicename = params.get('serviceName');
                break;
            case 'ws':
                config.ws_host = params.get('host') ? decodeURIComponent(params.get('host')) : null;
                config.ws_path = params.get('path') ? decodeURIComponent(params.get('path')) : null;
                if (config.ws_path && config.ws_path.includes('?ed=')) {
                    config.websocket_early_data_header = 'Sec-WebSocket-Protocol';
                    config.websocket_early_data = config.ws_path.split('?ed=')[1];
                    config.ws_path = config.ws_path.split('?ed=')[0];
                }
                break;
            }

            break;
        case 'tuic':
            url = new URL('http://' + uri[1]);
            params = url.searchParams;

            if (!url.username)
                return null;

            config = {
                label: url.hash ? decodeURIComponent(url.hash.slice(1)) : null,
                type: 'tuic',
                address: url.hostname,
                port: url.port || '80',
                uuid: url.username,
                password: url.password ? decodeURIComponent(url.password) : null,
                tuic_congestion_control: params.get('congestion_control'),
                tuic_udp_relay_mode: params.get('udp_relay_mode'),
                tls: '1',
                tls_sni: params.get('sni'),
                tls_alpn: params.get('alpn') ? decodeURIComponent(params.get('alpn')).split(',') : null
            };

            break;
        case 'vless':
            url = new URL('http://' + uri[1]);
            params = url.searchParams;

            if (params.get('type') === 'kcp')
                return null;
            else if (params.get('type') === 'quic' && ((params.get('quicSecurity') && params.get('quicSecurity') !== 'none') || !features.with_quic))
                return null;
            if (!url.username || !params.get('type'))
                return null;

            config = {
                label: url.hash ? decodeURIComponent(url.hash.slice(1)) : null,
                type: 'vless',
                address: url.hostname,
                port: url.port || '80',
                uuid: url.username,
                transport: params.get('type') !== 'tcp' ? params.get('type') : null,
                tls: ['tls', 'xtls', 'reality'].includes(params.get('security')) ? '1' : '0',
                tls_sni: params.get('sni'),
                tls_alpn: params.get('alpn') ? decodeURIComponent(params.get('alpn')).split(',') : null,
                tls_reality: (params.get('security') === 'reality') ? '1' : '0',
                tls_reality_public_key: params.get('pbk') ? decodeURIComponent(params.get('pbk')) : null,
                tls_reality_short_id: params.get('sid'),
                tls_utls: features.with_utls ? params.get('fp') : null,
                vless_flow: ['tls', 'reality'].includes(params.get('security')) ? params.get('flow') : null
            };
            switch (params.get('type')) {
            case 'grpc':
                config.grpc_servicename = params.get('serviceName');
                break;
            case 'http':
            case 'tcp':
                if (config.transport === 'http' || params.get('headerType') === 'http') {
                    config.http_host = params.get('host') ? decodeURIComponent(params.get('host')).split(',') : null;
                    config.http_path = params.get('path') ? decodeURIComponent(params.get('path')) : null;
                }
                break;
            case 'httpupgrade':
                config.httpupgrade_host = params.get('host') ? decodeURIComponent(params.get('host')) : null;
                config.http_path = params.get('path') ? decodeURIComponent(params.get('path')) : null;
                break;
            case 'ws':
                config.ws_host = params.get('host') ? decodeURIComponent(params.get('host')) : null;
                config.ws_path = params.get('path') ? decodeURIComponent(params.get('path')) : null;
                if (config.ws_path && config.ws_path.includes('?ed=')) {
                    config.websocket_early_data_header = 'Sec-WebSocket-Protocol';
                    config.websocket_early_data = config.ws_path.split('?ed=')[1];
                    config.ws_path = config.ws_path.split('?ed=')[0];
                }
                break;
            }

            break;
        case 'vmess':
            if (uri.includes('&'))
                return null;

            uri = JSON.parse(fp.decodeBase64Str(uri[1]));

            if (uri.v != '2')
                return null;
            else if (uri.net === 'kcp')
                return null;
            else if (uri.net === 'quic' && ((uri.type && uri.type !== 'none') || !features.with_quic))
                return null;

            config = {
                label: uri.ps,
                type: 'vmess',
                address: uri.add,
                port: uri.port,
                uuid: uri.id,
                vmess_alterid: uri.aid,
                vmess_encrypt: uri.scy || 'auto',
                transport: (uri.net !== 'tcp') ? uri.net : null,
                tls: uri.tls === 'tls' ? '1' : '0',
                tls_sni: uri.sni || uri.host,
                tls_alpn: uri.alpn ? uri.alpn.split(',') : null,
                tls_utls: features.with_utls ? uri.fp : null
            };
            switch (uri.net) {
            case 'grpc':
                config.grpc_servicename = uri.path;
                break;
            case 'h2':
            case 'tcp':
                if (uri.net === 'h2' || uri.type === 'http') {
                    config.transport = 'http';
                    config.http_host = uri.host ? uri.host.split(',') : null;
                    config.http_path = uri.path;
                }
                break;
            case 'httpupgrade':
                config.httpupgrade_host = uri.host;
                config.http_path = uri.path;
                break;
            case 'ws':
                config.ws_host = uri.host;
                config.ws_path = uri.path;
                if (config.ws_path && config.ws_path.includes('?ed=')) {
                    config.websocket_early_data_header = 'Sec-WebSocket-Protocol';
                    config.websocket_early_data = config.ws_path.split('?ed=')[1];
                    config.ws_path = config.ws_path.split('?ed=')[0];
                }
                break;
            }

            break;
        }
    }

    if (config) {
        if (!config.address || !config.port)
            return null;
        else if (!config.label)
            config.label = config.address + ':' + config.port;

        config.address = config.address.replace(/\[|\]/g, '');
    }

    return config;
}

// --- [ 子模块2：节点表单构建器 ] ---
function renderNodeSettings(section, data, features, main_node, routing_mode) {
    let s = section, o;
    s.rowcolors = true;
    s.sortable = true;
    s.nodescriptions = true;
    s.modaltitle = L.bind(fp.loadModalTitle, this, _('Node'), _('Add a node'), data[0]);
    s.sectiontitle = L.bind(fp.loadDefaultLabel, this, data[0]);

    if (routing_mode !== 'custom') {
        o = s.option(form.Button, '_apply', _('Apply'));
        o.editable = true;
        o.modalonly = false;
        o.inputstyle = 'apply';
        o.inputtitle = function(section_id) {
            if (main_node == section_id) {
                this.readonly = true;
                return _('Applied');
            } else {
                this.readonly = false;
                return _('Apply');
            }
        }
        o.onclick = function(ev, section_id) {
            uci.set(data[0], 'config', 'main_node', section_id);

            return this.map.save(null, true).then(() => {
                ui.changes.apply(true);
            });
        }
    }

    o = s.option(form.Value, 'label', _('Label'));
    o.load = L.bind(fp.loadDefaultLabel, this, data[0]);
    o.validate = L.bind(fp.validateUniqueValue, this, data[0], 'node', 'label');
    o.modalonly = true;

    o = s.option(form.ListValue, 'type', _('Type'));
    o.value('direct', _('Direct'));
    o.value('anytls', _('AnyTLS'));
    o.value('http', _('HTTP'));
    if (features.with_quic) {
        o.value('hysteria', _('Hysteria'));
        o.value('hysteria2', _('Hysteria2'));
    }
    o.value('shadowsocks', _('Shadowsocks'));
    o.value('shadowtls', _('ShadowTLS'));
    o.value('socks', _('Socks'));
    o.value('ssh', _('SSH'));
    o.value('trojan', _('Trojan'));
    if (features.with_quic)
        o.value('tuic', _('Tuic'));
    if (features.with_wireguard && features.with_gvisor)
        o.value('wireguard', _('WireGuard'));
    o.value('vless', _('VLESS'));
    o.value('vmess', _('VMess'));
    o.rmempty = false;

    o = s.option(form.Value, 'address', _('Address'));
    o.datatype = 'host';
    o.depends({'type': 'direct', '!reverse': true});
    o.rmempty = false;

    o = s.option(form.Value, 'port', _('Port'));
    o.datatype = 'port';
    o.depends({'type': 'direct', '!reverse': true});
    o.rmempty = false;

    o = s.option(form.Value, 'username', _('Username'));
    o.depends('type', 'http');
    o.depends('type', 'socks');
    o.depends('type', 'ssh');
    o.modalonly = true;

    o = s.option(form.Value, 'password', _('Password'));
    o.password = true;
    o.depends('type', 'anytls');
    o.depends('type', 'http');
    o.depends('type', 'hysteria2');
    o.depends('type', 'shadowsocks');
    o.depends('type', 'ssh');
    o.depends('type', 'trojan');
    o.depends('type', 'tuic');
    o.depends({'type': 'shadowtls', 'shadowtls_version': '2'});
    o.depends({'type': 'shadowtls', 'shadowtls_version': '3'});
    o.depends({'type': 'socks', 'socks_version': '5'});
    o.validate = function(section_id, value) {
        if (section_id) {
            let type = this.section.formvalue(section_id, 'type');
            let required_type = [ 'anytls', 'shadowsocks', 'shadowtls', 'trojan' ];

            if (required_type.includes(type)) {
                if (type === 'shadowsocks') {
                    let encmode = this.section.formvalue(section_id, 'shadowsocks_encrypt_method');
                    if (encmode === 'none')
                        return true;
                }
                if (!value)
                    return _('Expecting: %s').format(_('non-empty value'));
            }
        }
        return true;
    }
    o.modalonly = true;

    /* Direct config */
    o = s.option(form.ListValue, 'proxy_protocol', _('Proxy protocol'),
        _('Write proxy protocol in the connection header.'));
    o.value('', _('Disable'));
    o.value('1', _('v1'));
    o.value('2', _('v2'));
    o.depends('type', 'direct');
    o.modalonly = true;

    /* AnyTLS config start */
    o = s.option(form.Value, 'anytls_idle_session_check_interval', _('Idle session check interval'),
        _('Interval checking for idle sessions, in seconds.'));
    o.datatype = 'uinteger';
    o.placeholder = '30';
    o.depends('type', 'anytls');
    o.modalonly = true;

    o = s.option(form.Value, 'anytls_idle_session_timeout', _('Idle session check timeout'),
        _('In the check, close sessions that have been idle for longer than this, in seconds.'));
    o.datatype = 'uinteger';
    o.placeholder = '30';
    o.depends('type', 'anytls');
    o.modalonly = true;

    o = s.option(form.Value, 'anytls_min_idle_session', _('Minimum idle sessions'),
        _('In the check, at least the first <code>n</code> idle sessions are kept open.'));
    o.datatype = 'uinteger';
    o.placeholder = '0';
    o.depends('type', 'anytls');
    o.modalonly = true;

    /* Hysteria (2) config start */
    o = s.option(form.DynamicList, 'hysteria_hopping_port', _('Hopping port'));
    o.depends('type', 'hysteria');
    o.depends('type', 'hysteria2');
    o.validate = fp.validatePortRange;
    o.modalonly = true;

    o = s.option(form.Value, 'hysteria_hop_interval', _('Hop interval'),
        _('Port hopping interval in seconds.'));
    o.datatype = 'uinteger';
    o.placeholder = '30';
    o.depends({'type': 'hysteria', 'hysteria_hopping_port': /[\s\S]/});
    o.depends({'type': 'hysteria2', 'hysteria_hopping_port': /[\s\S]/});
    o.modalonly = true;

    o = s.option(form.ListValue, 'hysteria_protocol', _('Protocol'));
    o.value('udp');
    o.default = 'udp';
    o.depends('type', 'hysteria');
    o.rmempty = false;
    o.modalonly = true;

    o = s.option(form.ListValue, 'hysteria_auth_type', _('Authentication type'));
    o.value('', _('Disable'));
    o.value('base64', _('Base64'));
    o.value('string', _('String'));
    o.depends('type', 'hysteria');
    o.modalonly = true;

    o = s.option(form.Value, 'hysteria_auth_payload', _('Authentication payload'));
    o.password = true;
    o.depends({'type': 'hysteria', 'hysteria_auth_type': /[\s\S]/});
    o.rmempty = false;
    o.modalonly = true;

    o = s.option(form.ListValue, 'hysteria_obfs_type', _('Obfuscate type'));
    o.value('', _('Disable'));
    o.value('salamander', _('Salamander'));
    o.depends('type', 'hysteria2');
    o.modalonly = true;

    o = s.option(form.Value, 'hysteria_obfs_password', _('Obfuscate password'));
    o.password = true;
    o.depends('type', 'hysteria');
    o.depends({'type': 'hysteria2', 'hysteria_obfs_type': /[\s\S]/});
    o.modalonly = true;

    o = s.option(form.Value, 'hysteria_down_mbps', _('Max download speed'),
        _('Max download speed in Mbps.'));
    o.datatype = 'uinteger';
    o.depends('type', 'hysteria');
    o.depends('type', 'hysteria2');
    o.modalonly = true;

    o = s.option(form.Value, 'hysteria_up_mbps', _('Max upload speed'),
        _('Max upload speed in Mbps.'));
    o.datatype = 'uinteger';
    o.depends('type', 'hysteria');
    o.depends('type', 'hysteria2');
    o.modalonly = true;

    o = s.option(form.Value, 'hysteria_recv_window_conn', _('QUIC stream receive window'),
        _('The QUIC stream-level flow control window for receiving data.'));
    o.datatype = 'uinteger';
    o.depends('type', 'hysteria');
    o.modalonly = true;

    o = s.option(form.Value, 'hysteria_revc_window', _('QUIC connection receive window'),
        _('The QUIC connection-level flow control window for receiving data.'));
    o.datatype = 'uinteger';
    o.depends('type', 'hysteria');
    o.modalonly = true;

    o = s.option(form.Flag, 'hysteria_disable_mtu_discovery', _('Disable Path MTU discovery'),
        _('Disables Path MTU Discovery (RFC 8899). Packets will then be at most 1252 (IPv4) / 1232 (IPv6) bytes in size.'));
    o.depends('type', 'hysteria');
    o.modalonly = true;

    /* Shadowsocks config start */
    o = s.option(form.ListValue, 'shadowsocks_encrypt_method', _('Encrypt method'));
    for (let i of fp.shadowsocks_encrypt_methods)
        o.value(i);
    o.value('aes-128-ctr');
    o.value('aes-192-ctr');
    o.value('aes-256-ctr');
    o.value('aes-128-cfb');
    o.value('aes-192-cfb');
    o.value('aes-256-cfb');
    o.value('chacha20');
    o.value('chacha20-ietf');
    o.value('rc4-md5');
    o.default = 'aes-128-gcm';
    o.depends('type', 'shadowsocks');
    o.rmempty = false;
    o.modalonly = true;

    o = s.option(form.ListValue, 'shadowsocks_plugin', _('Plugin'));
    o.value('', _('none'));
    o.value('obfs-local');
    o.value('v2ray-plugin');
    o.depends('type', 'shadowsocks');
    o.modalonly = true;

    o = s.option(form.Value, 'shadowsocks_plugin_opts', _('Plugin opts'));
    o.depends('shadowsocks_plugin', 'obfs-local');
    o.depends('shadowsocks_plugin', 'v2ray-plugin');
    o.modalonly = true;

    /* ShadowTLS config */
    o = s.option(form.ListValue, 'shadowtls_version', _('ShadowTLS version'));
    o.value('1', _('v1'));
    o.value('2', _('v2'));
    o.value('3', _('v3'));
    o.default = '1';
    o.depends('type', 'shadowtls');
    o.rmempty = false;
    o.modalonly = true;

    /* Socks config */
    o = s.option(form.ListValue, 'socks_version', _('Socks version'));
    o.value('4', _('Socks4'));
    o.value('4a', _('Socks4A'));
    o.value('5', _('Socks5'));
    o.default = '5';
    o.depends('type', 'socks');
    o.rmempty = false;
    o.modalonly = true;

    /* SSH config start */
    o = s.option(form.Value, 'ssh_client_version', _('Client version'),
        _('Random version will be used if empty.'));
    o.depends('type', 'ssh');
    o.modalonly = true;

    o = s.option(form.DynamicList, 'ssh_host_key', _('Host key'),
        _('Accept any if empty.'));
    o.depends('type', 'ssh');
    o.modalonly = true;

    o = s.option(form.DynamicList, 'ssh_host_key_algo', _('Host key algorithms'));
    o.depends('type', 'ssh');
    o.modalonly = true;

    o = s.option(form.DynamicList, 'ssh_priv_key', _('Private key'));
    o.password = true;
    o.depends('type', 'ssh');
    o.modalonly = true;

    o = s.option(form.Value, 'ssh_priv_key_pp', _('Private key passphrase'));
    o.password = true;
    o.depends('type', 'ssh');
    o.modalonly = true;

    /* TUIC config start */
    o = s.option(form.Value, 'uuid', _('UUID'));
    o.password = true;
    o.depends('type', 'tuic');
    o.depends('type', 'vless');
    o.depends('type', 'vmess');
    o.validate = fp.validateUUID;
    o.modalonly = true;

    o = s.option(form.ListValue, 'tuic_congestion_control', _('Congestion control algorithm'),
        _('QUIC congestion control algorithm.'));
    o.value('cubic', _('CUBIC'));
    o.value('new_reno', _('New Reno'));
    o.value('bbr', _('BBR'));
    o.default = 'cubic';
    o.depends('type', 'tuic');
    o.rmempty = false;
    o.modalonly = true;

    o = s.option(form.ListValue, 'tuic_udp_relay_mode', _('UDP relay mode'),
        _('UDP packet relay mode.'));
    o.value('', _('Default'));
    o.value('native', _('Native'));
    o.value('quic', _('QUIC'));
    o.depends('type', 'tuic');
    o.modalonly = true;

    o = s.option(form.Flag, 'tuic_udp_over_stream', _('UDP over stream'),
        _('This is the TUIC port of the UDP over TCP protocol, designed to provide a QUIC stream based UDP relay mode that TUIC does not provide.'));
    o.depends({'type': 'tuic','tuic_udp_relay_mode': ''});
    o.modalonly = true;

    o = s.option(form.Flag, 'tuic_enable_zero_rtt', _('Enable 0-RTT handshake'),
        _('Enable 0-RTT QUIC connection handshake on the client side. This is not impacting much on the performance, as the protocol is fully multiplexed.<br/>' +
            'Disabling this is highly recommended, as it is vulnerable to replay attacks.'));
    o.depends('type', 'tuic');
    o.modalonly = true;

    o = s.option(form.Value, 'tuic_heartbeat', _('Heartbeat interval'),
        _('Interval for sending heartbeat packets for keeping the connection alive (in seconds).'));
    o.datatype = 'uinteger';
    o.default = '10';
    o.depends('type', 'tuic');
    o.modalonly = true;

    /* VMess / VLESS config start */
    o = s.option(form.ListValue, 'vless_flow', _('Flow'));
    o.value('', _('None'));
    o.value('xtls-rprx-vision');
    o.depends('type', 'vless');
    o.modalonly = true;

    o = s.option(form.Value, 'vmess_alterid', _('Alter ID'),
        _('Legacy protocol support (VMess MD5 Authentication) is provided for compatibility purposes only, use of alterId > 1 is not recommended.'));
    o.datatype = 'uinteger';
    o.depends('type', 'vmess');
    o.modalonly = true;

    o = s.option(form.ListValue, 'vmess_encrypt', _('Encrypt method'));
    o.value('auto');
    o.value('none');
    o.value('zero');
    o.value('aes-128-gcm');
    o.value('chacha20-poly1305');
    o.default = 'auto';
    o.depends('type', 'vmess');
    o.rmempty = false;
    o.modalonly = true;

    o = s.option(form.Flag, 'vmess_global_padding', _('Global padding'),
        _('Protocol parameter. Will waste traffic randomly if enabled (enabled by default in v2ray and cannot be disabled).'));
    o.default = o.enabled;
    o.depends('type', 'vmess');
    o.rmempty = false;
    o.modalonly = true;

    o = s.option(form.Flag, 'vmess_authenticated_length', _('Authenticated length'),
        _('Protocol parameter. Enable length block encryption.'));
    o.depends('type', 'vmess');
    o.modalonly = true;

    /* Transport config start */
    o = s.option(form.ListValue, 'transport', _('Transport'),
        _('No TCP transport, plain HTTP is merged into the HTTP transport.'));
    o.value('', _('None'));
    o.value('grpc', _('gRPC'));
    o.value('http', _('HTTP'));
    o.value('httpupgrade', _('HTTPUpgrade'));
    o.value('quic', _('QUIC'));
    o.value('ws', _('WebSocket'));
    o.depends('type', 'trojan');
    o.depends('type', 'vless');
    o.depends('type', 'vmess');
    o.onchange = function(ev, section_id, value) {
        let desc = this.map.findElement('id', 'cbid.flowproxy.%s.transport'.format(section_id)).nextElementSibling;
        if (value === 'http')
            desc.innerHTML = _('TLS is not enforced. If TLS is not configured, plain HTTP 1.1 is used.');
        else if (value === 'quic')
            desc.innerHTML = _('No additional encryption support: It\'s basically duplicate encryption.');
        else
            desc.innerHTML = _('No TCP transport, plain HTTP is merged into the HTTP transport.');

        let tls = this.map.findElement('id', 'cbid.flowproxy.%s.tls'.format(section_id)).firstElementChild;
        if ((value === 'http' && tls.checked) || (value === 'grpc' && !features.with_grpc)) {
            this.map.findElement('id', 'cbid.flowproxy.%s.http_idle_timeout'.format(section_id)).nextElementSibling.innerHTML =
                _('Specifies the period of time (in seconds) after which a health check will be performed using a ping frame if no frames have been received on the connection.<br/>' +
                    'Please note that a ping response is considered a received frame, so if there is no other traffic on the connection, the health check will be executed every interval.');

            this.map.findElement('id', 'cbid.flowproxy.%s.http_ping_timeout'.format(section_id)).nextElementSibling.innerHTML =
                _('Specifies the timeout duration (in seconds) after sending a PING frame, within which a response must be received.<br/>' +
                    'If a response to the PING frame is not received within the specified timeout duration, the connection will be closed.');
        } else if (value === 'grpc' && features.with_grpc) {
            this.map.findElement('id', 'cbid.flowproxy.%s.http_idle_timeout'.format(section_id)).nextElementSibling.innerHTML =
                _('If the transport doesn\'t see any activity after a duration of this time (in seconds), it pings the client to check if the connection is still active.');

            this.map.findElement('id', 'cbid.flowproxy.%s.http_ping_timeout'.format(section_id)).nextElementSibling.innerHTML =
                _('The timeout (in seconds) that after performing a keepalive check, the client will wait for activity. If no activity is detected, the connection will be closed.');
        }
    }
    o.modalonly = true;

    /* gRPC config start */
    o = s.option(form.Value, 'grpc_servicename', _('gRPC service name'));
    o.depends('transport', 'grpc');
    o.modalonly = true;

    if (features.with_grpc) {
        o = s.option(form.Flag, 'grpc_permit_without_stream', _('gRPC permit without stream'),
            _('If enabled, the client transport sends keepalive pings even with no active connections.'));
        o.depends('transport', 'grpc');
        o.modalonly = true;
    }

    /* HTTP(Upgrade) config start */
    o = s.option(form.DynamicList, 'http_host', _('Host'));
    o.datatype = 'hostname';
    o.depends('transport', 'http');
    o.modalonly = true;

    o = s.option(form.Value, 'httpupgrade_host', _('Host'));
    o.datatype = 'hostname';
    o.depends('transport', 'httpupgrade');
    o.modalonly = true;

    o = s.option(form.Value, 'http_path', _('Path'));
    o.depends('transport', 'http');
    o.depends('transport', 'httpupgrade');
    o.modalonly = true;

    o = s.option(form.Value, 'http_method', _('Method'));
    o.value('GET', _('GET'));
    o.value('PUT', _('PUT'));
    o.depends('transport', 'http');
    o.modalonly = true;

    o = s.option(form.Value, 'http_idle_timeout', _('Idle timeout'));
    o.datatype = 'uinteger';
    o.depends('transport', 'grpc');
    o.depends({'transport': 'http', 'tls': '1'});
    o.modalonly = true;

    o = s.option(form.Value, 'http_ping_timeout', _('Ping timeout'));
    o.datatype = 'uinteger';
    o.depends('transport', 'grpc');
    o.depends({'transport': 'http', 'tls': '1'});
    o.modalonly = true;

    /* WebSocket config start */
    o = s.option(form.Value, 'ws_host', _('Host'));
    o.depends('transport', 'ws');
    o.modalonly = true;

    o = s.option(form.Value, 'ws_path', _('Path'));
    o.depends('transport', 'ws');
    o.modalonly = true;

    o = s.option(form.Value, 'websocket_early_data', _('Early data'),
        _('Allowed payload size is in the request.'));
    o.datatype = 'uinteger';
    o.value('2048');
    o.depends('transport', 'ws');
    o.modalonly = true;

    o = s.option(form.Value, 'websocket_early_data_header', _('Early data header name'));
    o.value('Sec-WebSocket-Protocol');
    o.depends('transport', 'ws');
    o.modalonly = true;

    o = s.option(form.ListValue, 'packet_encoding', _('Packet encoding'));
    o.value('', _('none'));
    o.value('packetaddr', _('packet addr (v2ray-core v5+)'));
    o.value('xudp', _('Xudp (Xray-core)'));
    o.depends('type', 'vless');
    o.depends('type', 'vmess');
    o.modalonly = true;

    /* Wireguard config start */
    o = s.option(form.DynamicList, 'wireguard_local_address', _('Local address'),
        _('List of IP (v4 or v6) addresses prefixes to be assigned to the interface.'));
    o.datatype = 'cidr';
    o.depends('type', 'wireguard');
    o.rmempty = false;
    o.modalonly = true;

    o = s.option(form.Value, 'wireguard_private_key', _('Private key'),
        _('WireGuard requires base64-encoded private keys.'));
    o.password = true;
    o.depends('type', 'wireguard');
    o.validate = L.bind(fp.validateBase64Key, this, 44);
    o.rmempty = false;
    o.modalonly = true;

    o = s.option(form.Value, 'wireguard_peer_public_key', _('Peer pubkic key'),
        _('WireGuard peer public key.'));
    o.depends('type', 'wireguard');
    o.validate = L.bind(fp.validateBase64Key, this, 44);
    o.rmempty = false;
    o.modalonly = true;

    o = s.option(form.Value, 'wireguard_pre_shared_key', _('Pre-shared key'),
        _('WireGuard pre-shared key.'));
    o.password = true;
    o.depends('type', 'wireguard');
    o.validate = L.bind(fp.validateBase64Key, this, 44);
    o.modalonly = true;

    o = s.option(form.DynamicList, 'wireguard_reserved', _('Reserved field bytes'));
    o.datatype = 'integer';
    o.depends('type', 'wireguard');
    o.modalonly = true;

    o = s.option(form.Value, 'wireguard_mtu', _('MTU'));
    o.datatype = 'range(0,9000)';
    o.placeholder = '1408';
    o.depends('type', 'wireguard');
    o.modalonly = true;

    o = s.option(form.Value, 'wireguard_persistent_keepalive_interval', _('Persistent keepalive interval'),
        _('In seconds. Disabled by default.'));
    o.datatype = 'uinteger';
    o.depends('type', 'wireguard');
    o.modalonly = true;

    /* Mux config start */
    o = s.option(form.Flag, 'multiplex', _('Multiplex'));
    o.depends('type', 'shadowsocks');
    o.depends('type', 'trojan');
    o.depends('type', 'vless');
    o.depends('type', 'vmess');
    o.modalonly = true;

    o = s.option(form.ListValue, 'multiplex_protocol', _('Protocol'));
    o.value('h2mux');
    o.value('smux');
    o.value('yamux');
    o.default = 'h2mux';
    o.depends('multiplex', '1');
    o.rmempty = false;
    o.modalonly = true;

    o = s.option(form.Value, 'multiplex_max_connections', _('Maximum connections'));
    o.datatype = 'uinteger';
    o.depends('multiplex', '1');
    o.modalonly = true;

    o = s.option(form.Value, 'multiplex_min_streams', _('Minimum streams'));
    o.datatype = 'uinteger';
    o.depends('multiplex', '1');
    o.modalonly = true;

    o = s.option(form.Value, 'multiplex_max_streams', _('Maximum streams'));
    o.datatype = 'uinteger';
    o.depends({'multiplex': '1', 'multiplex_max_connections': '', 'multiplex_min_streams': ''});
    o.modalonly = true;

    o = s.option(form.Flag, 'multiplex_padding', _('Enable padding'));
    o.depends('multiplex', '1');
    o.modalonly = true;

    o = s.option(form.Flag, 'multiplex_brutal', _('Enable TCP Brutal'));
    o.depends('multiplex', '1');
    o.modalonly = true;

    o = s.option(form.Value, 'multiplex_brutal_down', _('Download bandwidth'));
    o.datatype = 'uinteger';
    o.depends('multiplex_brutal', '1');
    o.modalonly = true;

    o = s.option(form.Value, 'multiplex_brutal_up', _('Upload bandwidth'));
    o.datatype = 'uinteger';
    o.depends('multiplex_brutal', '1');
    o.modalonly = true;

    /* TLS config start */
    o = s.option(form.Flag, 'tls', _('TLS'));
    o.depends('type', 'anytls');
    o.depends('type', 'http');
    o.depends('type', 'hysteria');
    o.depends('type', 'hysteria2');
    o.depends('type', 'shadowtls');
    o.depends('type', 'trojan');
    o.depends('type', 'tuic');
    o.depends('type', 'vless');
    o.depends('type', 'vmess');
    o.validate = function(section_id, _value) {
        if (section_id) {
            let type = this.map.lookupOption('type', section_id)[0].formvalue(section_id);
            let tls = this.map.findElement('id', 'cbid.flowproxy.%s.tls'.format(section_id)).firstElementChild;

            if (['anytls', 'hysteria', 'hysteria2', 'shadowtls', 'tuic'].includes(type)) {
                tls.checked = true;
                tls.disabled = true;
            } else {
                tls.disabled = null;
            }
        }
        return true;
    }
    o.modalonly = true;

    o = s.option(form.Value, 'tls_sni', _('TLS SNI'),
        _('Used to verify the hostname on the returned certificates unless insecure is given.'));
    o.depends('tls', '1');
    o.modalonly = true;

    o = s.option(form.DynamicList, 'tls_alpn', _('TLS ALPN'));
    o.depends('tls', '1');
    o.modalonly = true;

    o = s.option(form.Flag, 'tls_insecure', _('Allow insecure'),
        _('Allow insecure connection at TLS client.') + '<br/>' +
        _('This is <strong>DANGEROUS</strong>, your traffic is almost like <strong>PLAIN TEXT</strong>! Use at your own risk!'));
    o.depends('tls', '1');
    o.onchange = allowInsecureConfirm;
    o.modalonly = true;

    o = s.option(form.ListValue, 'tls_min_version', _('Minimum TLS version'));
    o.value('', _('default'));
    for (let i of fp.tls_versions) o.value(i);
    o.depends('tls', '1');
    o.modalonly = true;

    o = s.option(form.ListValue, 'tls_max_version', _('Maximum TLS version'));
    o.value('', _('default'));
    for (let i of fp.tls_versions) o.value(i);
    o.depends('tls', '1');
    o.modalonly = true;

    o = s.option(fp.CBIStaticList, 'tls_cipher_suites', _('Cipher suites'));
    for (let i of fp.tls_cipher_suites) o.value(i);
    o.depends('tls', '1');
    o.optional = true;
    o.modalonly = true;

    o = s.option(form.Flag, 'tls_self_sign', _('Append self-signed certificate'));
    o.depends('tls_insecure', '0');
    o.modalonly = true;

    o = s.option(form.Value, 'tls_cert_path', _('Certificate path'));
    o.value('/etc/flowproxy/certs/client_ca.pem');
    o.depends('tls_self_sign', '1');
    o.validate = fp.validateCertificatePath;
    o.rmempty = false;
    o.modalonly = true;

    o = s.option(form.Button, '_upload_cert', _('Upload certificate'));
    o.inputstyle = 'action';
    o.inputtitle = _('Upload...');
    o.depends({'tls_self_sign': '1', 'tls_cert_path': '/etc/flowproxy/certs/client_ca.pem'});
    o.onclick = L.bind(fp.uploadCertificate, this, _('certificate'), 'client_ca');
    o.modalonly = true;

    o = s.option(form.Flag, 'tls_ech', _('Enable ECH'));
    o.depends('tls', '1');
    o.modalonly = true;

    o = s.option(form.Value, 'tls_ech_config_path', _('ECH config path'));
    o.value('/etc/flowproxy/certs/client_ech_conf.pem');
    o.depends('tls_ech', '1');
    o.modalonly = true;

    o = s.option(form.Button, '_upload_ech_config', _('Upload ECH config'));
    o.inputstyle = 'action';
    o.inputtitle = _('Upload...');
    o.depends({'tls_ech': '1', 'tls_ech_config_path': '/etc/flowproxy/certs/client_ech_conf.pem'});
    o.onclick = L.bind(fp.uploadCertificate, this, _('ECH config'), 'client_ech_conf');
    o.modalonly = true;

    if (features.with_utls) {
        o = s.option(form.ListValue, 'tls_utls', _('uTLS fingerprint'));
        o.value('', _('Disable'));
        o.value('360');
        o.value('android');
        o.value('chrome');
        o.value('edge');
        o.value('firefox');
        o.value('ios');
        o.value('qq');
        o.value('random');
        o.value('randomized');
        o.value('safari');
        o.depends({'tls': '1', 'type': /^((?!hysteria2?|tuic$).)+$/});
        o.validate = function(section_id, value) {
            if (section_id) {
                let tls_reality = this.map.findElement('id', 'cbid.flowproxy.%s.tls_reality'.format(section_id)).firstElementChild;
                if (tls_reality.checked && !value)
                    return _('Expecting: %s').format(_('non-empty value'));

                let vless_flow = this.map.lookupOption('vless_flow', section_id)[0].formvalue(section_id);
                if ((tls_reality.checked || vless_flow) && ['360', 'android'].includes(value))
                    return _('Unsupported fingerprint!');
            }
            return true;
        }
        o.modalonly = true;

        o = s.option(form.Flag, 'tls_reality', _('REALITY'));
        o.depends({'tls': '1', 'type': 'anytls'});
        o.depends({'tls': '1', 'type': 'vless'});
        o.modalonly = true;

        o = s.option(form.Value, 'tls_reality_public_key', _('REALITY public key'));
        o.password = true;
        o.depends('tls_reality', '1');
        o.rmempty = false;
        o.modalonly = true;

        o = s.option(form.Value, 'tls_reality_short_id', _('REALITY short ID'));
        o.password = true;
        o.depends('tls_reality', '1');
        o.modalonly = true;
    }

    /* Extra settings start */
    o = s.option(form.Flag, 'tcp_fast_open', _('TCP fast open'));
    o.modalonly = true;

    o = s.option(form.Flag, 'tcp_multi_path', _('MultiPath TCP'));
    o.modalonly = true;

    o = s.option(form.Flag, 'udp_fragment', _('UDP Fragment'));
    o.modalonly = true;

    o = s.option(form.Flag, 'udp_over_tcp', _('UDP over TCP'));
    o.depends('type', 'socks');
    o.depends({'type': 'shadowsocks', 'multiplex': '0'});
    o.modalonly = true;

    o = s.option(form.ListValue, 'udp_over_tcp_version', _('SUoT version'));
    o.value('1', _('v1'));
    o.value('2', _('v2'));
    o.default = '2';
    o.depends('udp_over_tcp', '1');
    o.modalonly = true;

    return s;
}

// --- [ 子模块3：主视图流转与交互调度 ] ---
return view.extend({
    load() {
        return Promise.all([
            uci.load('flowproxy'),
            fp.getBuiltinFeatures()
        ]);
    },

    render(data) {
        let m, s, o, ss, so;
        let main_node = uci.get(data[0], 'config', 'main_node');
        let routing_mode = uci.get(data[0], 'config', 'routing_mode');
        let features = data[1];

        /* 读取新的 airport 模型，废弃旧的 subscription_url */
        let subinfo = [];
        uci.sections(data[0], 'subscription_airport', (sec) => {
            if (sec.url) {
                subinfo.push({
                    'hash': sec['.name'],
                    'title': sec.name || 'Unnamed Airport'
                });
            }
        });

        // 临时兼容：如果有旧版的 URL，依然生成 Tab 以便用户删掉旧节点
        for (let suburl of (uci.get(data[0], 'subscription', 'subscription_url') || [])) {
            const urlhash = fp.calcStringMD5(suburl.replace(/#.*$/, ''));
            if (!subinfo.find(i => i.hash === urlhash)) {
                subinfo.push({ 'hash': urlhash, 'title': 'Legacy Sub' });
            }
        }

        m = new form.Map('flowproxy', _('Edit nodes'));

        s = m.section(form.NamedSection, 'subscription', 'flowproxy');

        /* === Subscriptions settings start === */
        s.tab('subscription', '订阅设置');

        /* UI 位移与排版渲染脚本 */
        o = s.taboption('subscription', form.DummyValue, '_ui_optimization');
        o.rawhtml = true;
        o.default = `
        <style>
            #cbi-flowproxy-subscription-_ui_optimization { display: none !important; }
            #cbi-flowproxy-subscription-_airports { max-width: none !important; width: 100%; }
            .fp-native-title { margin-top: 10px !important; margin-bottom: 15px !important; border: none !important; }
        </style>
        <img src="x" style="display:none" onerror="
            let img = this;
            setTimeout(function() {
                img.remove();

                let divider = document.getElementById('cbi-flowproxy-subscription-_divider_main');
                if (divider && !document.querySelector('.fp-layout-row')) {
                    let row = document.createElement('div');
                    row.className = 'fp-layout-row';
                    row.style.display = 'flex';
                    row.style.gap = '50px';
                    row.style.alignItems = 'flex-start';
                    row.style.width = '100%';

                    let leftCol = document.createElement('div');
                    leftCol.style.flex = '1';
                    leftCol.style.minWidth = '0';

                    let rightCol = document.createElement('div');
                    rightCol.style.flex = '1';
                    rightCol.style.minWidth = '0';

                    row.appendChild(leftCol);
                    row.appendChild(rightCol);

                    let leftIds = ['_left_title', 'auto_update', 'auto_update_time', 'update_via_proxy', 'filter_nodes', 'filter_keywords', 'user_agent', 'allow_insecure', 'packet_encoding'];
                    let rightIds = ['_right_title', 'global_regions'];

                    leftIds.forEach(id => {
                        let el = document.getElementById('cbi-flowproxy-subscription-' + id);
                        if (el) leftCol.appendChild(el);
                    });

                    rightIds.forEach(id => {
                        let el = document.getElementById('cbi-flowproxy-subscription-' + id);
                        if (el) rightCol.appendChild(el);
                    });

                    divider.parentNode.insertBefore(row, divider);
                }

                let airportsSection = document.getElementById('cbi-flowproxy-subscription-_airports');
                if (airportsSection) {
                    let createRow = airportsSection.querySelector('.cbi-section-create');
                    if (createRow) {
                        createRow.style.display = 'flex';
                        createRow.style.gap = '12px';
                        createRow.style.alignItems = 'center';
                        createRow.style.flexWrap = 'wrap';
                        createRow.style.marginTop = '10px';

                        let btnSave = document.querySelector('#cbi-flowproxy-subscription-_save_subscriptions button, #cbi-flowproxy-subscription-_save_subscriptions input[type=\\'button\\']');
                        let btnUpdate = document.querySelector('#cbi-flowproxy-subscription-_update_subscriptions button, #cbi-flowproxy-subscription-_update_subscriptions input[type=\\'button\\']');
                        let btnRebuild = document.querySelector('#cbi-flowproxy-subscription-_rebuild_groups button, #cbi-flowproxy-subscription-_rebuild_groups input[type=\\'button\\']');
                        let btnRemove = document.querySelector('#cbi-flowproxy-subscription-_remove_subscriptions button, #cbi-flowproxy-subscription-_remove_subscriptions input[type=\\'button\\']');

                        if (btnSave) createRow.appendChild(btnSave);
                        if (btnUpdate) createRow.appendChild(btnUpdate);
                        if (btnRebuild) createRow.appendChild(btnRebuild);
                        if (btnRemove) createRow.appendChild(btnRemove);

                        ['#cbi-flowproxy-subscription-_save_subscriptions',
                         '#cbi-flowproxy-subscription-_update_subscriptions',
                         '#cbi-flowproxy-subscription-_rebuild_groups',
                         '#cbi-flowproxy-subscription-_remove_subscriptions'].forEach(id => {
                            let el = document.querySelector(id);
                            if (el) el.style.display = 'none';
                        });
                    }
                }
            }, 200);
        " />`;

        o = s.taboption('subscription', form.DummyValue, '_left_title', '');
        o.rawhtml = true;
        o.default = '<h3 class="panel-title fp-native-title">⚙️ 全局设置</h3>';

        o = s.taboption('subscription', form.Flag, 'auto_update', '自动更新', '自动更新订阅节点和 Geo 数据。');
        o.rmempty = false;

        o = s.taboption('subscription', form.ListValue, 'auto_update_time', '更新时间');
        for (let i = 0; i < 24; i++) o.value(i, i + ':00');
        o.default = '2';
        o.depends('auto_update', '1');

        o = s.taboption('subscription', form.Flag, 'update_via_proxy', '使用代理更新', '通过当前的代理网络更新订阅。');
        o.rmempty = false;

        o = s.taboption('subscription', form.ListValue, 'filter_nodes', '过滤节点 (全局)');
        o.value('disabled', '禁用');
        o.value('blacklist', '黑名单模式');
        o.value('whitelist', '白名单模式');
        o.default = 'disabled';
        o.rmempty = false;

        o = s.taboption('subscription', form.DynamicList, 'filter_keywords', '过滤关键词 (全局)');
        o.depends({'filter_nodes': 'disabled', '!reverse': true});
        o.rmempty = false;

        o = s.taboption('subscription', form.Value, 'user_agent', 'User-Agent (用户代理)');
        o.placeholder = 'Wget/1.21 (FlowProxy, like v2rayN)';

        o = s.taboption('subscription', form.Flag, 'allow_insecure', '允许不安全连接',
            '强制开启不安全连接。Trojan/VLESS等现代协议将严格遵循订阅自身设置。');
        o.rmempty = false;
        o.onchange = allowInsecureConfirm;

        o = s.taboption('subscription', form.ListValue, 'packet_encoding', '默认包封装格式');
        o.value('', '无');
        o.value('packetaddr', 'packet addr (v2ray-core v5+)');
        o.value('xudp', 'Xudp (Xray-core)');

        o = s.taboption('subscription', form.DummyValue, '_right_title', '');
        o.rawhtml = true;
        o.default = '<h3 class="panel-title fp-native-title">🛠️ 顶级区域组设置</h3>';

        o = s.taboption('subscription', form.DynamicList, 'global_regions', '顶级自动区域组',
            '指定要生成的顶级 Auto 组（如 <b>HK</b>, <b>US</b>）。<br/>如果留空，将自动为您机场规则中发现的所有区域生成顶级组。');
        o.rmempty = true;

        /* 分割线 */
        o = s.taboption('subscription', form.DummyValue, '_divider_main', '');
        o.rawhtml = true;
        o.default = '<hr style="margin: 10px 0 30px 0; border: 0; border-top: 1px dashed #ccc;" />';

        o = s.taboption('subscription', form.SectionValue, '_airports', form.GridSection, 'subscription_airport',
            '订阅管理 (Airports Management)',
            '在此管理您的订阅。支持<b>拖拽排序</b>，排序决定底层节点组的命名后缀（如 hk01, hk02）。');
        o.subsection.addremove = true;
        o.subsection.sortable = true;
        o.subsection.nodescriptions = true;
        o.subsection.modaltitle = '编辑订阅设置';
        o.subsection.anonymous = true;

        so = o.subsection.option(form.Flag, 'enabled', '启用');
        so.rmempty = false;
        so.default = '1';

        so = o.subsection.option(form.Value, 'name', '订阅名称', '用作节点组名称的后缀。');
        so.rmempty = false;

        so = o.subsection.option(form.Value, 'url', '订阅链接 (URL)');
        so.rmempty = false;
        so.modalonly = true;

        so = o.subsection.option(form.DynamicList, 'region_group', '底层区域组正则规则',
            '格式: <code>区域名称|关键字1,关键字2</code> (例如 <b>HK|香港,HK</b>)。如果只填 <b>US</b>，则区域和关键字均为 US。');

        so = o.subsection.option(form.DynamicList, 'top_level_whitelist', '参与顶级组 (区域白名单)',
            '严格控制该机场是否有资格参与顶级自动组（⚡ Auto）。<br/><b>留空 (默认)</b>：不参与任何顶级组。<br/><b>填写区域代码 (如 HK)</b>：仅允许参与指定的顶级组。<br/><b>填写 <code>*</code> </b>：无限制，允许参与所有顶级组。');

        so = o.subsection.option(form.DummyValue, '_update_single', '快捷操作');
        so.modalonly = false;
        so.textvalue = function(section_id) {
            return E('button', {
                'type': 'button',
                'class': 'cbi-button cbi-button-apply',
                'click': (ev) => {
                    ev.preventDefault();
                    ev.stopPropagation();
                    // 🚨 彻底移除 map.save，将 JobObserver 修正为 observer
                    observer.execute('update_subscriptions', { airport_id: section_id }, '🔄 正在更新单个订阅');
                }
            }, '更新订阅');
        };

        o = s.taboption('subscription', form.Button, '_save_subscriptions', '保存订阅');
        o.inputstyle = 'apply';
        o.onclick = function() { return this.map.save(null, true).then(() => { ui.changes.apply(true); }); }

        o = s.taboption('subscription', form.Button, '_update_subscriptions', '更新全部订阅');
        o.inputstyle = 'apply';
        o.onclick = function(ev) {
            ev.preventDefault();
            // 🚨 彻底移除 map.save，将 JobObserver 修正为 observer
            observer.execute('update_subscriptions', { scope: 'all' }, '🔄 全局订阅更新');
        };

        o = s.taboption('subscription', form.Button, '_rebuild_groups', '⚡ 极速重组本地节点组');
        o.inputstyle = 'action';
        o.inputtitle = '重组本地节点组';
        o.onclick = function(ev) {
            ev.preventDefault();
            // 🚨 彻底移除 map.save，将 JobObserver 修正为 observer
            observer.execute('rebuild_groups', {}, '⚡ 极速重组节点组');
        };

        o = s.taboption('subscription', form.Button, '_remove_subscriptions', '移除全部订阅节点');
        o.inputstyle = 'reset';
        o.onclick = function() {
            let subnodes = [];
            uci.sections(data[0], 'node', (res) => { if (res.airport_id || res.grouphash) subnodes = subnodes.concat(res['.name']) });
            for (let i in subnodes) uci.remove(data[0], subnodes[i]);
            if (subnodes.includes(uci.get(data[0], 'config', 'main_node'))) uci.set(data[0], 'config', 'main_node', 'nil');
            this.inputtitle = '已移除 ' + subnodes.length + ' 个节点';
            this.readonly = true;
            return this.map.save(null, true);
        }

        /* === Node settings start === */
        s.tab('node', _('Nodes'));
        o = s.taboption('node', form.SectionValue, '_node', form.GridSection, 'node');
        ss = renderNodeSettings(o.subsection, data, features, main_node, routing_mode);
        ss.addremove = true;

        ss.filter = function(section_id) {
            let airport_id = uci.get(data[0], section_id, 'airport_id');
            let grouphash = uci.get(data[0], section_id, 'grouphash');
            if (airport_id || grouphash) return false;
            return true;
        }

        ss.handleLinkImport = function() {
            let textarea = new ui.Textarea();
            ui.showModal(_('Import share links'), [
                E('p', _('Support Hysteria, Shadowsocks, Trojan, v2rayN (VMess), and XTLS (VLESS) online configuration delivery standard.')),
                textarea.render(),
                E('div', { class: 'right' }, [
                    E('button', {
                        class: 'btn',
                        click: ui.hideModal
                    }, [ _('Cancel') ]),
                    '',
                    E('button', {
                        class: 'btn cbi-button-action',
                        click: ui.createHandlerFn(this, () => {
                            let input_links = textarea.getValue().trim().split('\n');
                            if (input_links && input_links[0]) {
                                input_links = input_links.reduce((pre, cur) =>
                                    (!pre.includes(cur) && pre.push(cur), pre), []);

                                let allow_insecure = uci.get(data[0], 'subscription', 'allow_insecure');
                                let packet_encoding = uci.get(data[0], 'subscription', 'packet_encoding');
                                let imported_node = 0;
                                input_links.forEach((l) => {
                                    let config = parseShareLink(l, features);
                                    if (config) {
                                        if (config.tls === '1' && allow_insecure === '1')
                                            config.tls_insecure = '1'
                                        if (['vless', 'vmess'].includes(config.type))
                                            config.packet_encoding = packet_encoding

                                        let nameHash = fp.calcStringMD5(config.label);
                                        let sid = uci.add(data[0], 'node', nameHash);
                                        Object.keys(config).forEach((k) => {
                                            uci.set(data[0], sid, k, config[k]);
                                        });
                                        imported_node++;
                                    }
                                });

                                if (imported_node === 0)
                                    ui.addNotification(null, E('p', _('No valid share link found.')));
                                else
                                    ui.addNotification(null, E('p', _('Successfully imported %s nodes of total %s.').format(
                                        imported_node, input_links.length)));

                                return uci.save()
                                    .then(L.bind(this.map.load, this.map))
                                    .then(L.bind(this.map.reset, this.map))
                                    .then(L.ui.hideModal)
                                    .catch(() => {});
                            } else {
                                return ui.hideModal();
                            }
                        })
                    }, [ _('Import') ])
                ])
            ])
        }
        ss.renderSectionAdd = function(/* ... */) {
            let el = form.GridSection.prototype.renderSectionAdd.apply(this, arguments),
                nameEl = el.querySelector('.cbi-section-create-name');

            ui.addValidator(nameEl, 'uciname', true, (v) => {
                let button = el.querySelector('.cbi-section-create > .cbi-button-add');
                let uciconfig = this.uciconfig || this.map.config;

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

            el.appendChild(E('button', {
                'class': 'cbi-button cbi-button-add',
                'title': _('Import share links'),
                'click': ui.createHandlerFn(this, 'handleLinkImport')
            }, [ _('Import share links') ]));

            return el;
        }

        for (const info of subinfo) {
            s.tab('sub_' + info.hash, _('Sub (%s)').format(info.title));
            o = s.taboption('sub_' + info.hash, form.SectionValue, '_sub_' + info.hash, form.GridSection, 'node');
            ss = renderNodeSettings(o.subsection, data, features, main_node, routing_mode);
            ss.filter = function(section_id) {
                return (uci.get(data[0], section_id, 'airport_id') === info.hash) ||
                       (uci.get(data[0], section_id, 'grouphash') === info.hash);
            }
        }

        return m.render();
    }
});
