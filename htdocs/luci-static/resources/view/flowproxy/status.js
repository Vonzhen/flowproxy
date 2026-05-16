// --- [ FlowProxy | 状态与监控视图模块 | v1.0 Contract Aligned Edition ] ---
// 功能：渲染系统运行状态大盘、内核管理、通信拨测与运行时日志展示
// 核心升级：废除 service.list 轮询，全量接入 System 真相引擎；恢复资源管理 UI 面板。

'use strict';
'require dom';
'require form';
'require fs';
'require poll';
'require rpc';
'require uci';
'require ui';
'require view';

// [Category A] 模块依赖对齐：废弃裸奔 job，接入统一的 observer 状态机
'require flowproxy.observer as observer';

// --- [ 子模块1：基础辅助函数与 CSS 注入 ] ---
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

// [Category B] 物理路径对齐：严格指向 Constants.uc 规划的聚合日志目录
const fp_dir = '/var/run/flowproxy/logs';

// ⭐ 对接 Truth Chain：接入唯一的真实状态快照引擎
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

// ⭐ 恢复资源版本查询 RPC 通道
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
                
                // ⭐ 使用系统实时探针，不走 Job 队列
                return L.resolveDefault(callConnectionCheck(site), {}).then((ret) => {
                    // [Category A] 防御性解包：穿透后端的 Success() 包装体
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

// ⭐ 恢复核心引擎：获取资源版本并绑定更新钩子
function getResVersion(o, type) {
    // 使用同步 RPC 查询版本号，不走 Job 队列
    return L.resolveDefault(callGetResVersion(type), {}).then((ret) => {
        // [Category A] 防御性解包，兼容 v1.0 Result 协议
        let res = (ret && ret.data) ? ret.data : ret;
        
        let spanTemp = E('div', { 'style': 'cbi-value-field' }, [
            E('button', {
                'class': 'btn cbi-button cbi-button-action',
                'click': ui.createHandlerFn(this, () => {
                    // [Category B] 架构对齐：抛弃 fs.exec_direct，转由 observer 唤醒后端 Worker 异步处理
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
    // [Category C] Note: 将前端意图的 flowproxy 映射为后端的实际物理日志名 system.log
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
        // [Category C] Note: 维持 fs.read_direct，路径已通过 fp_dir 对齐到 /var/run/flowproxy/logs
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
                        // ⭐ 清理日志使用同步系统调用
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

// --- [ 子模块2：大盘主视图映射构建 ] ---
return view.extend({
    load() {
        return Promise.all([
            uci.load('flowproxy'),
            L.resolveDefault(callSystemStatus(), {}) // ⭐ 提取全局快照
        ]);
    },

    render(data) {
        let m, s, o;
        let sys_status = (data[1] && data[1].data) ? data[1].data : data[1]; // 防御性解包全局快照
        let isRunning = sys_status && sys_status.process ? sys_status.process.running : false;

        m = new form.Map('flowproxy');
        
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

        // 🚨 恢复 UI 渲染区：四大战略资源白名单版本检视
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

                // ⭐ 内核版本检查使用系统同步查询
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
                // [Category B] 指令对齐：切换为 observer.execute，隔离裸壳操作
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

        // --- [ 子模块4：通知中心配置 ] ---
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

        // --- [ 子模块5：日志挂载视图 ] ---
        s = m.section(form.NamedSection, 'config', 'flowproxy');
        s.anonymous = true;

        o = s.option(form.DummyValue, '_flowproxy_logview');
        o.render = L.bind(getRuntimeLog, this, o, _('FlowProxy 控制面'));

        o = s.option(form.DummyValue, '_sing-box_logview');
        o.render = L.bind(getRuntimeLog, this, o, _('Sing-box 运行引擎'));

        return m.render();
    },

    // 禁用底部原生的默认保存按钮，强制用户通过业务按钮调度
    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
