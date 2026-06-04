/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * FlowProxy Resources
 */

'use strict';
'require form';
'require uci';
'require view';

'require flowproxy as fp';
'require flowproxy.observer as observer';

function runManualJob(type, payload, title) {
    payload = payload || {};
    payload.source = 'manual';
    payload.auto_apply = false;

    return observer.execute(type, payload, title);
}

function renderMovedNotice() {
    return E('div', {
        'style': 'padding:10px 12px;background:#f8f9fa;border-left:4px solid #17a2b8;border-radius:4px;color:#333;'
    }, [
        E('strong', {}, [ _('Resource management') ]),
        E('div', { 'style': 'margin-top:4px;' }, [
            _('Rulesets are managed here and referenced by Client routing or DNS rules.')
        ])
    ]);
}

function renderManualDownload() {
    return E('div', { 'style': 'display:flex;align-items:flex-start;gap:12px;flex-wrap:wrap;' }, [
        E('textarea', {
            'id': 'resources_manual_rule_name_input',
            'class': 'cbi-input-textarea',
            'placeholder': 'geosite-google\ngeoip-netflix\ngeosite-cn',
            'style': 'flex:1;min-width:260px;max-width:460px;min-height:84px;padding:8px;'
        }),
        E('button', {
            'class': 'cbi-button cbi-button-apply',
            'click': function(ev) {
                ev.preventDefault();

                let ele = document.getElementById('resources_manual_rule_name_input');
                let val = ele ? ele.value.trim() : '';
                if (!val) {
                    alert(_('Please enter one or more ruleset names.'));
                    return;
                }

                let target = val.replace(/[\n,]/g, ' ').replace(/\s+/g, ' ').trim();
                return runManualJob('update_assets', {
                    action: 'download',
                    target: target
                }, _('Downloading rule assets'));
            }
        }, [ _('Download') ])
    ]);
}

function renderUsedRulesetUpdate() {
    return E('div', { 'style': 'display:flex;align-items:center;gap:12px;flex-wrap:wrap;' }, [
        E('button', {
            'class': 'cbi-button cbi-button-action',
            'click': function(ev) {
                ev.preventDefault();

                return runManualJob('update_assets', {
                    action: 'update',
                    target: 'manual'
                }, _('Updating used rule assets'));
            }
        }, [ _('Update used rule assets') ]),
        E('span', { 'style': 'color:#666;' }, [
            _('Manual resource updates do not apply configuration automatically.')
        ])
    ]);
}

function renderResourceVersion(type) {
    let version = E('strong', { 'style': 'color:#777;' }, [ _('loading...') ]);

    fp.rpc_call('flowproxy.system', 'resources_get_version', { type: type }).then((res) => {
        if (res && res.error) {
            version.style.color = '#721c24';
            version.textContent = _('not found');
            return;
        }

        version.style.color = '#155724';
        version.textContent = (res && res.version) ? res.version : _('unknown');
    }).catch((e) => {
        version.style.color = '#721c24';
        version.textContent = _('RPC Error') + ': ' + (e && (e.message || e.code) || String(e || 'unknown'));
    });

    return E('div', { 'style': 'display:flex;align-items:center;gap:10px;flex-wrap:wrap;' }, [
        E('button', {
            'class': 'cbi-button cbi-button-action',
            'click': function(ev) {
                ev.preventDefault();

                return runManualJob('update_resources', {
                    action: 'update',
                    target: type
                }, _('Updating resource') + ': ' + type).then(() => location.reload()).catch(() => {});
            }
        }, [ _('Check update') ]),
        version
    ]);
}

return view.extend({
    load() {
        return uci.load('flowproxy');
    },

    render() {
        let m = new form.Map('flowproxy', _('Resources'));
        let s, ss, o, so;

        s = m.section(form.NamedSection, 'config', 'flowproxy');
        s.anonymous = true;

        s.tab('settings', _('Ruleset Settings'));
        s.tab('list', _('Ruleset List'));
        s.tab('ip_domain', _('IP / Domain Resources'));

        o = s.taboption('settings', form.DummyValue, '_resources_notice', '');
        o.rawhtml = true;
        o.renderWidget = renderMovedNotice;

        o = s.taboption('settings', form.SectionValue, '_assets', form.NamedSection, 'assets', 'assets');
        ss = o.subsection;

        so = ss.option(form.Value, 'base_url', _('Mirror base URL'),
            _('Base URL used to download public rule assets.'));
        so.default = 'https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing';
        so.placeholder = 'https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing';

        so = ss.option(form.Value, 'private_repo', _('Private repository URL'),
            _('Optional URL prefix used to download private SRS assets.'));
        so.placeholder = 'https://raw.githubusercontent.com/YourName/Repo/main';

        so = ss.option(form.Flag, 'auto_update', _('Automatic ruleset update'),
            _('Schedule background ruleset update for this resource group.'));
        so.rmempty = false;

        so = ss.option(form.ListValue, 'update_time', _('Daily update time'));
        for (let i = 0; i < 24; i++)
            so.value(String(i), i + ':00');
        so.default = '4';
        so.depends('auto_update', '1');

        o = s.taboption('settings', form.DummyValue, '_manual_download', _('Download rule assets'));
        o.description = _('Enter one or more ruleset names, separated by comma or newline.');
        o.renderWidget = renderManualDownload;

        o = s.taboption('settings', form.DummyValue, '_manual_update', _('Update used rule assets'));
        o.description = _('Update rulesets currently referenced by FlowProxy. This does not apply configuration automatically.');
        o.renderWidget = renderUsedRulesetUpdate;

        o = s.taboption('list', form.SectionValue, '_ruleset', form.GridSection, 'ruleset');
        ss = o.subsection;
        ss.addremove = true;
        ss.rowcolors = true;
        ss.sortable = true;
        ss.nodescriptions = true;
        ss.modaltitle = L.bind(fp.loadModalTitle, this, _('Rule set'), _('Add a rule set'), 'flowproxy');
        ss.sectiontitle = L.bind(fp.loadDefaultLabel, this, 'flowproxy');
        ss.renderSectionAdd = L.bind(fp.renderSectionAdd, this, ss);

        o = ss.option(form.Value, 'label', _('Label'));
        o.load = L.bind(fp.loadDefaultLabel, this, 'flowproxy');
        o.validate = L.bind(fp.validateUniqueValue, this, 'flowproxy', 'ruleset', 'label');
        o.modalonly = true;

        o = ss.option(form.Flag, 'enabled', _('Enable'));
        o.default = o.enabled;
        o.rmempty = false;
        o.editable = true;

        o = ss.option(form.ListValue, 'type', _('Type'));
        o.value('local', _('Local'));
        o.value('remote', _('Remote'));
        o.default = 'remote';
        o.rmempty = false;

        o = ss.option(form.ListValue, 'format', _('Format'));
        o.value('binary', _('Binary file'));
        o.value('source', _('Source file'));
        o.default = 'binary';
        o.rmempty = false;

        o = ss.option(form.Value, 'path', _('Path'));
        o.datatype = 'file';
        o.placeholder = '/etc/flowproxy/ruleset/example.json';
        o.rmempty = false;
        o.depends('type', 'local');
        o.modalonly = true;

        o = ss.option(form.Value, 'url', _('Rule set URL'));
        o.validate = function(section_id, value) {
            if (section_id) {
                if (!value)
                    return _('Expecting: %s').format(_('non-empty value'));

                try {
                    let url = new URL(value);
                    if (!url.hostname)
                        return _('Expecting: %s').format(_('valid URL'));
                }
                catch(e) {
                    return _('Expecting: %s').format(_('valid URL'));
                }
            }

            return true;
        };
        o.rmempty = false;
        o.depends('type', 'remote');
        o.modalonly = true;

        o = ss.option(form.ListValue, 'outbound', _('Outbound'),
            _('Tag of the outbound to download rule set.'));
        o.load = function(section_id) {
            delete this.keylist;
            delete this.vallist;

            this.value('', _('Default'));
            this.value('direct-out', _('Direct'));
            uci.sections('flowproxy', 'routing_node', (res) => {
                if (res.enabled === '1')
                    this.value(res['.name'], res.label);
            });

            return this.super('load', section_id);
        };
        o.depends('type', 'remote');

        o = ss.option(form.Value, 'update_interval', _('Update interval'),
            _('Update interval of rule set.'));
        o.placeholder = '1d';
        o.depends('type', 'remote');

        o = s.taboption('ip_domain', form.DummyValue, '_china_ip4_version', _('China IPv4 list version'));
        o.renderWidget = function() { return renderResourceVersion('china_ip4'); };

        o = s.taboption('ip_domain', form.DummyValue, '_china_ip6_version', _('China IPv6 list version'));
        o.renderWidget = function() { return renderResourceVersion('china_ip6'); };

        o = s.taboption('ip_domain', form.DummyValue, '_china_list_version', _('China domain list version'));
        o.renderWidget = function() { return renderResourceVersion('china_list'); };

        o = s.taboption('ip_domain', form.DummyValue, '_gfw_list_version', _('GFW list version'));
        o.renderWidget = function() { return renderResourceVersion('gfw_list'); };

        return m.render();
    }
});
