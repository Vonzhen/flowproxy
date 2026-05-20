// --- [ FlowProxy | 状态与监控视图模块 | v1.0 Contract Aligned Edition ] ---
'use strict';
'require dom';
'require form';
'require fs';
'require poll';
'require rpc';
'require uci';
'require ui';
'require view';

'require flowproxy.observer as observer';

const css = `
#log_textarea {
    padding: 10px;
    text-align: left;
}
#log_textarea pre {
    padding: .5rem;
    word-break: break-all;
    margin: 0;
}
.description {
    background-color: #33ccff;
}`;

const fp_dir = '/var/run/flowproxy/logs';

const callSystemStatus = rpc.declare({
    object: 'flowproxy.system',
    method: 'status',
    expect: { '': {} }
});

const callConnectionCheck = rpc.declare({
    object: 'flowproxy.system',
    method: 'connection_check',
    params: ['site'],
    expect: { '': {} }
});

const callGetResVersion = rpc.declare({
    object: 'flowproxy.system',
    method: 'resources_get_version',
    params: ['type'],
    expect: { '': {} }
});

const callKernelVersionCheck = rpc.declare({
    object: 'flowproxy.system',
    method: 'kernel_version_check',
    expect: { '': {} }
});

const callLogClean = rpc.declare({
    object: 'flowproxy.system',
    method: 'log_clean',
    params: ['type'],
    expect: { '': {} }
});

function getConnStat(o, site) {
    o.default = E('div', { 'style': 'cbi-value-field' }, [
        E('button', {
            'class': 'btn cbi-button cbi-button-action',
            'click': ui.createHandlerFn(this, () => {
                let ele = o.default.firstElementChild.nextElementSibling;
                ele.innerHTML = _('checking...');
                ele.style.setProperty('color', 'gray');
                
                return L.resolveDefault(callConnectionCheck(site), {}).then((ret) => {
                    let res = (ret && ret.data) ? ret.data : ret;
                    if (res && res.result) {
                        ele.style.setProperty('color', 'green');
                        ele.innerHTML = _('passed') + ' (' + res.http_code + ')';
                    } else {
                        ele.style.setProperty('color', 'red');
                        ele.innerHTML = _('failed') + ' (' + (res.http_code || res.error || 'timeout') + ')';
                    }
                }).catch(() => {
                    ele.style.setProperty('color', 'red');
                    ele.innerHTML = _('RPC Error');
                });
            })
        }, [ _('Check') ]),
        ' ',
        E('strong', { 'style': 'color:gray' }, _('unchecked')),
    ]);
}

function getResVersion(o, type) {
    return L.resolveDefault(callGetResVersion(type), {}).then((ret) => {
        let res = (ret && ret.data) ? ret.data : ret;
        let spanTemp = E('div', { 'style': 'cbi-value-field' }, [
            E('button', {
                'class': 'btn cbi-button cbi-button-action',
                'click': ui.createHandlerFn(this, () => {
                    return observer.execute('update_resources', { action: 'update', target: type }, '🔄 检查资源更新')
                        .then(() => location.reload())
                        .catch(() => {});
                })
            }, [ _('Check update') ]),
            ' ',
            E('strong', { 'style': (res.error ? 'color:red' : 'color:green') },
                [ res.error ? 'not found' : (res.version || 'Unknown') ]
            ),
        ]);
        o.default = spanTemp;
    }).catch(() => {
        o.default = E('em', { 'style': 'color:red' }, 'RPC Error');
    });
}

function getRuntimeLog(o, name, _option_index, section_id, _in_table) {
    const opt_name = o.option.split('_')[1];
    const filename = opt_name === 'flowproxy' ? 'system' : opt_name;

    let section, log_level_el;
    if (opt_name === 'sing-box') {
        section = 'config';
    } else if (opt_name === 'flowproxy') {
        section = null; 
    }

    if (section) {
        const selected = uci.get('flowproxy', section, 'log_level') || 'warn';
        const choices = {
            trace: _('Trace'), debug: _('Debug'), info: _('Info'),
            warn: _('Warn'), error: _('Error'), fatal: _('Fatal'), panic: _('Panic')
        };

        log_level_el = E('select', {
            'id': o.cbid(section_id),
            'class': 'cbi-input-select',
            'style': 'margin-left: 4px; width: 6em;',
            'change': ui.createHandlerFn(this, (ev) => {
                uci.set('flowproxy', section, 'log_level', ev.target.value);
                return o.map.save(null, true).then(() => { ui.changes.apply(true); });
            })
        });

        Object.keys(choices).forEach((v) => {
            log_level_el.appendChild(E('option', { 'value': v, 'selected': (v === selected) ? '' : null }, [ choices[v] ]));
        });
    }

    const log_textarea = E('div', { 'id': 'log_textarea' },
        E('img', { 'src': L.resource('icons/loading.svg'), 'alt': _('Loading'), 'style': 'vertical-align:middle' }, _('Collecting data...'))
    );

    let log;
    poll.add(L.bind(() => {
        return fs.read_direct(String.format('%s/%s.log', fp_dir, filename), 'text')
        .then((res) => {
            log = E('pre', { 'wrap': 'pre' }, [ res.trim() || _('Log is empty.') ]);
            dom.content(log_textarea, log);
        }).catch((err) => {
            if (err.toString().includes('NotFoundError')) log = E('pre', { 'wrap': 'pre' }, [ _('Log file does not exist or waiting for output...') ]);
            else log = E('pre', { 'wrap': 'pre' }, [ _('Unknown error: %s').format(err) ]);
            dom.content(log_textarea, log);
        });
    }));

    return E([
        E('style', [ css ]),
        E('div', {'class': 'cbi-map'}, [
            E('h3', {'name': 'content', 'style': 'align-items: center; display: flex;'}, [
                _('%s log').format(name),
                log_level_el || '',
                E('button', {
                    'class': 'btn cbi-button cbi-button-action',
                    'style': 'margin-left: 4px;',
                    'click': ui.createHandlerFn(this, () => { 
                        return L.resolveDefault(callLogClean(filename), {}).then(() => location.reload());
                    })
                }, [ _('Clean log') ])
            ]),
            E('div', {'class': 'cbi-section'}, [
                log_textarea,
                E('div', {'style': 'text-align:right'}, E('small', {}, _('Refresh every %s seconds.').format(L.env.pollinterval)))
            ])
        ])
    ]);
}

return view.extend({
    load() {
        return Promise.all([
            uci.load('flowproxy'),
            L.resolveDefault(callSystemStatus(), {})
        ]);
    },

    render(data) {
        let m, s, o;
        let sys_status = (data[1] && data[1].data) ? data[1].data : data[1]; 
        let isRunning = sys_status && sys_status.process ? sys_status.process.running : false;

        m = new form.Map('flowproxy');

        // ============================================================================
        // 🚨 架构缝合：渲染三态健康大盘警告框
        // ============================================================================
        s = m.section(form.NamedSection, 'config', 'flowproxy');
        s.anonymous = true;
        
        o = s.option(form.DummyValue, '_health_status');
        o.render = function() {
            if (sys_status && sys_status.enabled) {
                let h_state = (sys_status.health && sys_status.health.state) ? sys_status.health.state : (isRunning ? "healthy" : "broken");
                let h_failed = (sys_status.health && Array.isArray(sys_status.health.failed)) ? sys_status.health.failed : [];
                
                let alert_color = '#d4edda';
                let alert_text = '#155724';
                let alert_msg = '✅ <b>FlowProxy 运行正常 (Healthy)</b> - 所有核心组件与数据面均已就绪。';
                
                if (h_state === 'broken') {
                    alert_color = '#f8d7da';
                    alert_text = '#721c24';
                    let fail_str = h_failed.length > 0 ? h_failed.join(", ") : "未知";
                    alert_msg = '🚨 <b>系统严重损毁 (Broken)</b> - 核心进程或网络基建已脱机！丢失组件：' + fail_str;
                } else if (h_state === 'degraded') {
                    alert_color = '#fff3cd';
                    alert_text = '#856404';
                    let fail_str = h_failed.length > 0 ? h_failed.join(", ") : "未知";
                    alert_msg = '⚠️ <b>系统降级运行 (Degraded)</b> - 进程存活但部分网络规则遗失，可能漏网。遗失：' + fail_str;
                }

                // 强制使用基础字符串拼接，防止老浏览器出现 Unexpected token 解析错误
                let alert_style = 'background-color: ' + alert_color + '; color: ' + alert_text + '; padding: 15px; margin-bottom: 20px; border-radius: 4px; border-left: 5px solid ' + alert_text + '; font-size: 14px;';
                let alert_box = E('div', { 'class': 'alert', 'style': alert_style });
                alert_box.innerHTML = alert_msg;
                return alert_box;
            } else {
                let disabled_style = 'background-color: #e2e3e5; color: #383d41; padding: 15px; margin-bottom: 20px; border-radius: 4px; border-left: 5px solid #383d41; font-size: 14px;';
                let disabled_box = E('div', { 'class': 'alert', 'style': disabled_style });
                disabled_box.innerHTML = '⏸️ <b>系统已禁用</b> - 用户未配置默认出站或手动关闭了服务。';
                return disabled_box;
            }
        };

        // --- [ 子模块 2.1：网络拨测区 ] ---
        s = m.section(form.NamedSection, 'config', 'flowproxy', _('Connection check'));
        s.anonymous = true;

        o = s.option(form.DummyValue, '_check_baidu', _('BaiDu'));
        o.cfgvalue = L.bind(getConnStat, this, o, 'baidu');

        o = s.option(form.DummyValue, '_check_google', _('Google'));
        o.cfgvalue = L.bind(getConnStat, this, o, 'google');

        // --- [ 子模块 2.2：资源版本管理 ] ---
        s = m.section(form.NamedSection, 'config', 'flowproxy', _('Resources management'));
        s.anonymous = true;

        o = s.option(form.DummyValue, '_china_ip4_version', _('China IPv4 list version'));
        o.cfgvalue = L.bind(getResVersion, this, o, 'china_ip4');
        o.rawhtml = true;

        o = s.option(form.DummyValue, '_china_ip6_version', _('China IPv6 list version'));
        o.cfgvalue = L.bind(getResVersion, this, o, 'china_ip6');
        o.rawhtml = true;

        o = s.option(form.DummyValue, '_china_list_version', _('China list version'));
        o.cfgvalue = L.bind(getResVersion, this, o, 'china_list');
        o.rawhtml = true;

        o = s.option(form.DummyValue, '_gfw_list_version', _('GFW list version'));
        o.cfgvalue = L.bind(getResVersion, this, o, 'gfw_list');
        o.rawhtml = true;

        // --- [ 子模块 2.3：内核动力管理区 ] ---
        o = s.option(form.DummyValue, '_kernel_manager', _('Sing-box 内核管理'));
        o.description = _('检查版本并选择性热替换。建议定期检查并保持内核处于活跃版本。');
        o.renderWidget = function(section_id, option_index, cfgvalue) {
            let container = E('div', { 'class': 'cbi-value-field', 'style': 'display: flex; flex-direction: column; gap: 12px; padding: 10px; background: #f8f9fa; border-radius: 6px; border: 1px solid #ddd;' });

            let local_val = E('span', { 'style': 'color: #555; font-family: monospace;' }, '未知 (点击检查)');
            let stable_val = E('span', { 'style': 'color: #555; font-family: monospace; margin-right: 15px;' }, '-');
            let beta_val = E('span', { 'style': 'color: #555; font-family: monospace; margin-right: 15px;' }, '-');

            let stable_btn = E('button', { 'class': 'btn cbi-button cbi-button-apply', 'style': 'display:none; padding: 2px 10px;', 'click': (ev) => { ev.preventDefault(); do_update('stable'); } }, '📥 升级稳定版');
            let beta_btn = E('button', { 'class': 'btn cbi-button cbi-button-action', 'style': 'display:none; padding: 2px 10px;', 'click': (ev) => { ev.preventDefault(); do_update('beta'); } }, '⚡ 升级测试版');

            let row_local = E('div', {}, [ E('span', { 'style': 'display:inline-block; width: 90px; font-weight:bold;' }, '📍 当前版本:'), local_val ]);
            let row_stable = E('div', {}, [ E('span', { 'style': 'display:inline-block; width: 90px; font-weight:bold;' }, '🟢 稳定版本:'), stable_val, stable_btn ]);
            let row_beta = E('div', {}, [ E('span', { 'style': 'display:inline-block; width: 90px; font-weight:bold;' }, '🟠 测试版本:'), beta_val, beta_btn ]);

            let check_btn = E('button', { 'class': 'btn cbi-button cbi-button-neutral', 'style': 'width: 140px; margin-top: 5px;', 'click': function(ev) {
                ev.preventDefault();
                check_btn.disabled = true;
                check_btn.textContent = '🔄 正在执行检查...';

                L.resolveDefault(callKernelVersionCheck(), {}).then(ret => {
                    let data = (ret && ret.data) ? ret.data : ret;
                    
                    check_btn.disabled = false;
                    check_btn.textContent = '🔄 重新检查';
                    
                    local_val.textContent = data.local || '获取失败';
                    local_val.style.color = '#007bff';

                    stable_val.textContent = data.stable || '获取失败';
                    if (data.stable && data.local !== data.stable) {
                        stable_val.style.color = '#28a745';
                        stable_val.style.fontWeight = 'bold';
                        stable_btn.style.display = 'inline-block';
                    } else {
                        stable_btn.style.display = 'none';
                    }

                    beta_val.textContent = data.beta || '获取失败';
                    if (data.beta && data.local !== data.beta) {
                        beta_val.style.color = '#fd7e14';
                        beta_val.style.fontWeight = 'bold';
                        beta_btn.style.display = 'inline-block';
                    } else {
                        beta_btn.style.display = 'none';
                    }
                }).catch(() => {
                    check_btn.disabled = false;
                    check_btn.textContent = '❌ 检查失败重试';
                });
            }}, '🔍 检查线上版本');

            let do_update = function(track) {
                observer.execute('update_kernel', { track: track }, '🚀 Sing-box 内核热升级').then(() => {
                    setTimeout(() => { location.reload(); }, 1500);
                }).catch(() => {});
            };

            container.appendChild(row_local);
            container.appendChild(row_stable);
            container.appendChild(row_beta);
            container.appendChild(check_btn);
            return container;
        };

        o = s.option(form.Value, 'github_token', _('GitHub token'));
        o.password = true;
        o.renderWidget = function() {
            let node = form.Value.prototype.renderWidget.apply(this, arguments);
            (node.querySelector('.control-group') || node).appendChild(E('button', {
                'class': 'cbi-button cbi-button-apply',
                'title': _('Save'),
                'click': ui.createHandlerFn(this, () => {
                    return this.map.save(null, true).then(() => { ui.changes.apply(true); });
                }, this.option)
            }, [ _('Save') ]));
            return node;
        }

        // --- 通知中心配置 ---
        s = m.section(form.NamedSection, 'config', 'flowproxy', '消息中心');
        s.anonymous = true;

        o = s.option(form.Flag, 'tg_notify_enabled', '启用 Telegram 自动告警',
            '统一接管订阅更新、规则集更新以及服务崩溃监控。所有脚本将读取此处的配置进行通讯。');

        o = s.option(form.Value, 'location_name', '路由器名称', '用于在通知头部区分不同的设备。');
        o.default = 'FlowProxy';
        o.placeholder = '如：家里主路由、公司软路由';
        o.depends('tg_notify_enabled', '1');

        o = s.option(form.ListValue, 'tg_notify_mode', '通知触发策略');
        o.value('always', '总是通知 (成功与失败均发送)');
        o.value('fail_only', '静默模式 (仅在发生错误、中断或回滚时才通知)');
        o.default = 'always';
        o.depends('tg_notify_enabled', '1');

        o = s.option(form.Value, 'tg_token', 'Bot Token', '填入你的 TG 机器人 Token。');
        o.password = true;
        o.depends('tg_notify_enabled', '1');

        o = s.option(form.Value, 'tg_chat_id', 'Chat ID', '填入接收消息的频道或用户 ID。');
        o.depends('tg_notify_enabled', '1');

        o = s.option(form.Button, '_save_tg_btn', '保存通知设置');
        o.inputstyle = 'apply';
        o.onclick = function() {
            return this.map.save(null, true).then(() => { ui.changes.apply(true); });
        }

        // --- 日志挂载视图 ---
        s = m.section(form.NamedSection, 'config', 'flowproxy');
        s.anonymous = true;

        o = s.option(form.DummyValue, '_flowproxy_logview');
        o.render = L.bind(getRuntimeLog, this, o, _('FlowProxy 控制面'));

        o = s.option(form.DummyValue, '_sing-box_logview');
        o.render = L.bind(getRuntimeLog, this, o, _('Sing-box 运行引擎'));

        return m.render();
    },

    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
