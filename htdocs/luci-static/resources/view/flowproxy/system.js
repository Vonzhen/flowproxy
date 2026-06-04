/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * FlowProxy System
 */

'use strict';
'require form';
'require rpc';
'require uci';
'require ui';
'require view';

const callSystemStatus = rpc.declare({
    object: 'flowproxy.system',
    method: 'status',
    expect: { '': {} }
});

const callKernelVersionCheck = rpc.declare({
    object: 'flowproxy.system',
    method: 'kernel_version_check',
    expect: { '': {} }
});

function unwrapResult(ret) {
    if (!ret)
        return {};
    if (ret.data)
        return ret.data;
    return ret;
}

function textValue(v) {
    if (v === null || v === undefined || v === '')
        return _('unknown');
    if (typeof v === 'boolean')
        return v ? _('yes') : _('no');
    return String(v);
}

function rowValue(value) {
    if (value && typeof value === 'object' && value.nodeType)
        return value;
    return E('strong', { 'style': 'text-align:right;overflow-wrap:anywhere;' }, [ textValue(value) ]);
}

function row(label, value) {
    return E('div', {
        'style': 'display:flex;justify-content:space-between;gap:12px;padding:5px 0;border-bottom:1px solid #eee;'
    }, [
        E('span', { 'style': 'color:#666;' }, [ label ]),
        rowValue(value)
    ]);
}

function renderKernelCheck() {
    let current = E('strong', { 'style': 'color:#777;' }, [ _('unknown') ]);
    let stable = E('strong', { 'style': 'color:#777;' }, [ _('not checked') ]);
    let beta = E('strong', { 'style': 'color:#777;' }, [ _('not checked') ]);
    let detail = E('div', { 'style': 'color:#666;' }, [
        _('Readonly check only. FlowProxy will not download, install, replace sing-box, or restart services.')
    ]);

    let button = E('button', {
        'class': 'btn cbi-button cbi-button-neutral',
        'click': function(ev) {
            ev.preventDefault();
            button.disabled = true;
            button.textContent = _('Checking...');
            detail.textContent = _('Checking GitHub release information...');

            return callKernelVersionCheck().then((ret) => {
                let data = unwrapResult(ret);

                current.textContent = data.current_version || data.local || _('unknown');
                stable.textContent = data.latest_version || data.stable || _('not returned');
                beta.textContent = data.beta || _('not returned');

                detail.replaceChildren(E('div', { 'style': 'display:flex;flex-direction:column;gap:6px;' }, [
                    E('div', { 'style': 'font-weight:600;' }, [
                        _('Kernel check completed. No download or restart was performed.')
                    ]),
                    data.release_url ? E('a', {
                        'href': data.release_url,
                        'target': '_blank',
                        'rel': 'noopener noreferrer'
                    }, [ _('Open release page') ]) : E('span', {}, [ _('Release page is not provided by this readonly check.') ])
                ]));
            }).catch((e) => {
                detail.textContent = _('Kernel version check failed: ') + (e && (e.message || e.code) || String(e || 'unknown'));
                ui.addNotification(null, E('p', detail.textContent), 'danger');
            }).finally(() => {
                button.disabled = false;
                button.textContent = _('Check again');
            });
        }
    }, [ _('Check update') ]);

    return E('div', {
        'style': 'display:flex;flex-direction:column;gap:10px;padding:10px;background:#f8f9fa;border:1px solid #ddd;border-radius:6px;'
    }, [
        row(_('Current version'), current),
        row(_('Stable version'), stable),
        row(_('Beta version'), beta),
        detail,
        E('div', {}, [ button ])
    ]);
}

function renderVersionSummary(statusRet) {
    let status = unwrapResult(statusRet);
    let apiUnavailable = !status || (!status.process && typeof status.enabled === 'undefined');

    return E('div', {
        'style': 'max-width:720px;'
    }, [
        row(_('backend RPC'), apiUnavailable ? _('unavailable') : _('available')),
        row(_('sing-box'), apiUnavailable ? _('unknown') : (status.version && status.version.singbox)),
        row(_('process running'), apiUnavailable ? _('unknown') : (status.process && status.process.running)),
        row(_('config valid'), apiUnavailable ? _('unknown') : (status.config && status.config.valid)),
        row(_('mixed port'), apiUnavailable ? _('unknown') : (status.ports && status.ports.mixed)),
        row(_('dns port'), apiUnavailable ? _('unknown') : (status.ports && status.ports.dns)),
        row(_('FlowProxy frontend'), _('installed'))
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
        let m = new form.Map('flowproxy', _('System'));
        let s, o;

        s = m.section(form.NamedSection, 'config', 'flowproxy');
        s.anonymous = true;

        s.tab('telegram', _('Telegram'));
        s.tab('kernel', _('Kernel Check'));
        s.tab('version', _('Version'));

        o = s.taboption('telegram', form.Flag, 'tg_notify_enabled', _('Enable Telegram notifications'),
            _('Global notification settings used by FlowProxy jobs and health events.'));
        o.rmempty = false;

        o = s.taboption('telegram', form.Value, 'location_name', _('Router name'),
            _('Used to distinguish this device in notification messages.'));
        o.default = 'FlowProxy';
        o.placeholder = _('Home router');
        o.depends('tg_notify_enabled', '1');

        o = s.taboption('telegram', form.ListValue, 'tg_notify_mode', _('Notification policy'));
        o.value('always', _('Always notify'));
        o.value('fail_only', _('Notify failures only'));
        o.default = 'always';
        o.depends('tg_notify_enabled', '1');

        o = s.taboption('telegram', form.Value, 'tg_token', _('Bot Token'));
        o.password = true;
        o.depends('tg_notify_enabled', '1');

        o = s.taboption('telegram', form.Value, 'tg_chat_id', _('Chat ID'));
        o.depends('tg_notify_enabled', '1');

        o = s.taboption('kernel', form.Value, 'github_token', _('GitHub token'),
            _('Global GitHub API token used by FlowProxy when accessing GitHub APIs.'));
        o.password = true;

        o = s.taboption('kernel', form.DummyValue, '_kernel_check', _('Sing-box Kernel Check'));
        o.description = _('Readonly check only. FlowProxy will not download, install, replace sing-box, or restart services.');
        o.renderWidget = renderKernelCheck;

        o = s.taboption('version', form.DummyValue, '_version_summary', _('Version summary'));
        o.renderWidget = function() {
            return renderVersionSummary(data[1]);
        };

        return m.render();
    }
});
