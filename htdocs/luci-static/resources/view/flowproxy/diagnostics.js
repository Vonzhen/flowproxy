/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * FlowProxy Diagnostics
 */

'use strict';
'require form';
'require rpc';
'require view';

const callStatus = rpc.declare({
    object: 'flowproxy.system',
    method: 'status',
    expect: { '': {} }
});

const callRuntimeArtifacts = rpc.declare({
    object: 'flowproxy.system',
    method: 'get_runtime_artifacts',
    expect: { '': {} }
});

const callRuntimeLog = rpc.declare({
    object: 'flowproxy.system',
    method: 'log_read_runtime',
    params: [ 'type' ],
    expect: { '': {} }
});

const callNetworkState = rpc.declare({
    object: 'flowproxy.system',
    method: 'get_network_state',
    expect: { '': {} }
});

const callSingboxCheck = rpc.declare({
    object: 'flowproxy.system',
    method: 'singbox_check_readonly',
    expect: { '': {} }
});

function unwrapResult(ret) {
    if (!ret)
        return {};
    if (ret.data)
        return ret.data;
    return ret;
}

function pretty(v) {
    try {
        return JSON.stringify(v, null, 2);
    } catch(e) {
        return String(v || '');
    }
}

function pre(text) {
    return E('pre', {
        'style': 'white-space:pre-wrap;word-break:break-word;max-height:520px;overflow:auto;background:#f8f9fa;border:1px solid #ddd;border-radius:6px;padding:10px;margin:8px 0;'
    }, [ text || _('No data') ]);
}

function panel(title, body) {
    return E('div', {
        'style': 'border:1px solid #ddd;border-radius:6px;background:#fff;padding:12px;margin-bottom:12px;'
    }, [
        E('div', { 'style': 'font-weight:700;margin-bottom:8px;' }, [ title ]),
        body
    ]);
}

function loadButton(label, loader) {
    let box = E('div', {}, [ pre(_('Not loaded.')) ]);
    let btn = E('button', {
        'class': 'btn cbi-button cbi-button-neutral',
        'click': function(ev) {
            ev.preventDefault();
            btn.disabled = true;
            btn.textContent = _('Loading...');
            box.replaceChildren(pre(_('Loading...')));

            return L.resolveDefault(loader(), { error: 'api unavailable' }).then((ret) => {
                box.replaceChildren(loader.render ? loader.render(ret) : pre(pretty(unwrapResult(ret))));
            }).catch((e) => {
                box.replaceChildren(pre(_('Error: ') + (e && (e.message || e.code) || String(e || 'unknown'))));
            }).finally(() => {
                btn.disabled = false;
                btn.textContent = label;
            });
        }
    }, [ label ]);

    return E('div', {}, [
        E('div', { 'style': 'margin-bottom:8px;' }, [ btn ]),
        box
    ]);
}

function artifactPanel(name, item) {
    item = item || {};
    let raw = item.raw || item.parse_error || _('No data');
    let content = raw;
    try {
        content = raw ? pretty(JSON.parse(raw.replace(/\n\.\.\.\[truncated\]$/, ''))) : raw;
    } catch(e) {}

    return panel(name, E('div', {}, [
        E('div', { 'style': 'color:#666;' }, [
            item.exists ? _('exists') : _('not found'),
            ' | ',
            item.path || '',
            item.truncated ? ' | ' + _('truncated') : ''
        ]),
        pre(content)
    ]));
}

function renderArtifacts(ret) {
    let data = unwrapResult(ret);
    return E('div', {}, [
        artifactPanel('run.json', data.run),
        artifactPanel('candidate.json', data.candidate),
        artifactPanel('prev.json', data.prev)
    ]);
}

function renderLogs(ret) {
    let data = unwrapResult(ret);
    return panel(data.type || _('log'), E('div', {}, [
        E('div', { 'style': 'color:#666;' }, [
            data.exists ? _('exists') : _('not found'),
            ' | ',
            data.path || '',
            data.truncated ? ' | ' + _('truncated') : ''
        ]),
        pre(data.content || data.error || _('No data'))
    ]));
}

function commandPanel(name, item) {
    item = item || {};
    return panel(name, E('div', {}, [
        E('div', { 'style': item.ok ? 'color:#155724;' : 'color:#721c24;' }, [
            item.ok ? _('ok') : _('failed'),
            item.exit_code != null ? ' | exit ' + item.exit_code : ''
        ]),
        pre(item.stdout || item.stderr || item.error || _('No data'))
    ]));
}

function renderNetwork(ret) {
    let data = unwrapResult(ret);
    return E('div', {}, [
        commandPanel('nft', data.nft),
        commandPanel('ip rule', data.ip_rule),
        commandPanel('route', data.route),
        commandPanel('route6', data.route6),
        commandPanel('link', data.link)
    ]);
}

function renderSingboxCheck(ret) {
    let data = unwrapResult(ret);
    return panel(_('sing-box check'), E('div', {}, [
        E('div', { 'style': data.valid ? 'color:#155724;' : 'color:#721c24;' }, [
            data.valid ? _('valid') : _('invalid'),
            data.path ? ' | ' + data.path : ''
        ]),
        pre(data.output || data.stderr || data.error || _('No data'))
    ]));
}

return view.extend({
    load() {
        return L.resolveDefault(callStatus(), {});
    },

    render(statusRet) {
        let m = new form.Map('flowproxy', _('Diagnostics'));
        let s, o;

        s = m.section(form.NamedSection, 'config', 'flowproxy');
        s.anonymous = true;

        s.tab('health', _('Health Detail'));
        s.tab('artifacts', _('Runtime Artifacts'));
        s.tab('logs', _('Logs'));
        s.tab('network', _('Network State'));
        s.tab('debug', _('Debug'));

        o = s.taboption('health', form.DummyValue, '_health_detail', _('Health Detail'));
        o.renderWidget = function() {
            let data = unwrapResult(statusRet);
            return pre(pretty({
                health: data.health || {},
                diagnostic: data.diagnostic || {},
                process: data.process || {},
                config: data.config || {}
            }));
        };

        o = s.taboption('artifacts', form.DummyValue, '_runtime_artifacts', _('Runtime Artifacts'));
        o.renderWidget = function() {
            let loader = function() { return callRuntimeArtifacts(); };
            loader.render = renderArtifacts;
            return loadButton(_('Refresh runtime artifacts'), loader);
        };

        o = s.taboption('logs', form.ListValue, '_log_type', _('Log type'));
        o.value('system', _('FlowProxy system'));
        o.value('sing-box', _('sing-box'));
        o.value('job', _('Job worker'));
        o.default = 'system';

        o = s.taboption('logs', form.DummyValue, '_runtime_logs', _('Logs'));
        o.renderWidget = function() {
            let loader = function() {
                let type = document.querySelector('[name="cbid.flowproxy.config._log_type"]');
                return callRuntimeLog(type ? type.value : 'system');
            };
            loader.render = renderLogs;
            return loadButton(_('Refresh logs'), loader);
        };

        o = s.taboption('network', form.DummyValue, '_network_state', _('Network State'));
        o.renderWidget = function() {
            let loader = function() { return callNetworkState(); };
            loader.render = renderNetwork;
            return loadButton(_('Refresh network state'), loader);
        };

        o = s.taboption('debug', form.DummyValue, '_singbox_check', _('sing-box check readonly'));
        o.description = _('Checks the existing run.json only. It does not generate, apply, or restart anything.');
        o.renderWidget = function() {
            let loader = function() { return callSingboxCheck(); };
            loader.render = renderSingboxCheck;
            return loadButton(_('Run readonly check'), loader);
        };

        return m.render();
    }
});
