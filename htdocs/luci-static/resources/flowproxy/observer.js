/**
 * --- [ FlowProxy | 任务视图监听器 (Job Observer) | v1.0 SDK Aligned ] ---
 * 职责：渲染模态框，按游标轮询日志流，处理 UI 状态锁。
 * 架构对齐：彻底铲除“前端猜谜”，全权信任 JobAPI (SDK) 的异常阻断机制。
 */

'use strict';
'require baseclass';
'require dom';
'require ui';
'require flowproxy.job as JobAPI';

return baseclass.extend({
    execute: function(job_type, payload, modal_title) {
        // 1. 发起任务。若底层异常，SDK 会直接 Promise.reject 并阻断流程
        return JobAPI.start(job_type, payload).then(data => {
            let job_id = data.job_id;
            let current_cursor = 0;
            let ui_elements = this._renderModal(modal_title, job_id);

            return new Promise((resolve, reject) => {
                // 严格对齐白皮书：1.5 秒轮询间隔
                let poll_timer = setInterval(() => {
                    // 2. 并发轮询状态与日志
                    Promise.all([
                        JobAPI.status(job_id).catch(e => {
                            // 兜底：如果轮询状态时网络中断，强转为 fail 态终止死循环
                            return { state: 'fail', error: e.message || 'Polling disconnected' };
                        }),
                        JobAPI.log(job_id, current_cursor).catch(e => {
                            return { lines: [], next_cursor: current_cursor, eof: false };
                        })
                    ]).then(results => {
                        let status = results[0];
                        let logs = results[1];

                        // 3. 同步渲染引擎日志
                        if (logs.lines && logs.lines.length > 0) {
                            this._appendLogs(ui_elements.log_pre, logs.lines);
                            current_cursor = logs.next_cursor;
                        }

                        // 4. 处理 DFA 状态终态跃迁
                        if (status.state === 'success') {
                            clearInterval(poll_timer);
                            status.type = status.type || job_type;
                            this._finishModal(ui_elements, true, this._formatFinalMessage(status), status);
                            resolve(status);
                        } else if (status.state === 'fail' || status.state === 'rollback') {
                            clearInterval(poll_timer);
                            let err_reason = status.error || status.error_code || 'E_EXEC_FAIL';
                            status.type = status.type || job_type;
                            this._finishModal(ui_elements, false, this._formatFinalMessage(status), status);
                            let err = new Error(err_reason);
                            err.status = status;
                            reject(err);
                        } else if (status.state !== 'pending' && status.state !== 'unknown') {
                            // 动态更新运行态进度
                            ui_elements.status_txt.innerHTML = `正在执行引擎调度: [${status.state.toUpperCase()}] ... ${status.progress || 0}%`;
                        }
                    });
                }, 1500); 
            });
        });
    },

    _formatFinalMessage: function(status) {
        status = status || {};
        let summary_msg = this._formatResultSummary(status);
        if (summary_msg)
            return summary_msg;

        let job_type = status.type || '';
        let state = status.state || '';
        let err_reason = status.error || status.error_code || '';

        if (state === 'rollback') {
            return '⚠ 任务异常终止\n\n系统已进入回滚/异常处理流程。\n\n请查看日志确认当前状态。';
        }

        if (state === 'fail') {
            if (err_reason) {
                return '❌ 任务失败\n\n原因：\n' + err_reason + '\n\n请查看日志。';
            }
            return '❌ 任务失败\n\n请查看日志确认原因。';
        }

        if (job_type === 'update_subscriptions') {
            return '✅ 订阅更新完成\n\n订阅数据已更新。\n\n下一步：\n请点击「保存并应用」使修改生效。';
        }

        if (job_type === 'rebuild_groups') {
            return '✅ 节点组重建完成\n\n本地节点组已重新生成。\n\n下一步：\n请点击「保存并应用」使修改生效。';
        }

        if (job_type === 'update_assets') {
            return '✅ 规则集任务完成\n\n请查看日志确认更新项。\n\n下一步：\n请点击「保存并应用」使修改生效。';
        }

        if (job_type === 'update_resources') {
            return '✅ 资源任务完成\n\n请查看日志确认资源版本与更新项。\n\n下一步：\n请点击「保存并应用」使修改生效。';
        }

        if (job_type === 'apply_config') {
            return '✅ 配置已应用\n\n运行态任务已完成。';
        }

        return '✅ 任务完成\n\n请查看日志确认执行结果。';
    },

    _summaryList: function(items, max_items) {
        if (!Array.isArray(items))
            return [];

        max_items = max_items || 20;
        let out = [];
        for (let i = 0; i < items.length && i < max_items; i++)
            out.push(items[i]);
        return out;
    },

    _summaryCount: function(summary, key) {
        let counts = summary && summary.counts ? summary.counts : {};
        let value = Number(counts[key] || 0);
        return isFinite(value) ? value : 0;
    },

    _summaryHasFailures: function(summary) {
        let items = summary && summary.items ? summary.items : {};
        return this._summaryCount(summary, 'failed') > 0 ||
            (Array.isArray(items.failed) && items.failed.length > 0);
    },

    _appendNextAction: function(lines, summary) {
        if (!summary)
            return;

        if (summary.manual_apply_required === true || summary.next_action === 'manual_apply_required') {
            lines.push('');
            lines.push('下一步：');
            lines.push('请点击「保存并应用」使修改生效。');
        }
    },

    _shouldShowApplyButton: function(status) {
        if (!status || status.state !== 'success')
            return false;

        let summary = status.result_summary || {};
        if (summary.manual_apply_required !== true && summary.next_action !== 'manual_apply_required')
            return false;

        let kind = summary.kind || status.type || '';
        return kind === 'update_subscriptions' ||
            kind === 'rebuild_groups' ||
            kind === 'update_assets' ||
            kind === 'update_resources';
    },

    _formatResultSummary: function(status) {
        let summary = status ? status.result_summary : null;
        if (!summary || typeof summary !== 'object')
            return null;

        let kind = summary.kind || status.type || '';
        let state = status.state || '';
        let items = summary.items || {};
        let lines = [];

        if (state === 'rollback') {
            return '⚠ 任务异常终止\n\n系统已进入回滚/异常处理流程。\n\n请查看日志确认当前状态。';
        }

        if (state === 'fail') {
            let reason = summary.error_message || status.error || status.error_code || '';
            if (reason)
                return '❌ 任务失败\n\n原因：\n' + reason + '\n\n请查看日志。';
            return '❌ 任务失败\n\n请查看日志确认原因。';
        }

        if (kind === 'update_subscriptions') {
            let has_fail = this._summaryHasFailures(summary);
            lines.push(has_fail ? '⚠️ 订阅部分更新成功' : '✅ 订阅全局更新成功');
            lines.push('━━━━━━━━━━━━━━━━━━');
            lines.push('⏳ 总耗时: ' + (summary.duration_sec || 0) + ' 秒 | 总节点: ' + this._summaryCount(summary, 'total_nodes'));

            let airport_stats = this._summaryList(items.airport_stats);
            if (airport_stats.length > 0) {
                lines.push('');
                lines.push('📝 更新清单:');
                for (let i = 0; i < airport_stats.length; i++) {
                    let ap = airport_stats[i] || {};
                    lines.push('🔹 ' + (ap.name || 'unknown') + ': ' + (ap.nodes || 0) + ' 节点');
                }
            }

            let failed = this._summaryList(items.failed);
            if (failed.length > 0) {
                lines.push('');
                lines.push('❌ 失败订阅:');
                for (let i = 0; i < failed.length; i++)
                    lines.push('🔸 ' + failed[i]);
            }

            this._appendNextAction(lines, summary);
            return lines.join('\n');
        }

        if (kind === 'update_assets' || kind === 'update_resources') {
            let label = kind === 'update_assets' ? '规则集' : '资源';
            let has_fail = this._summaryHasFailures(summary);
            lines.push(has_fail ? '⚠️ ' + label + '部分更新成功' : '✅ ' + label + '更新完成');
            lines.push('━━━━━━━━━━━━━━━━━━');
            if (summary.version && this._summaryCount(summary, 'total') === 0) {
                lines.push('🏷️ 当前版本: ' + summary.version);
            } else {
                lines.push('📦 更新数量: ' + this._summaryCount(summary, 'updated'));
                lines.push('🟦 未变化数量: ' + this._summaryCount(summary, 'unchanged'));
                if (this._summaryCount(summary, 'failed') > 0)
                    lines.push('❌ 失败数量: ' + this._summaryCount(summary, 'failed'));
            }

            let updated = this._summaryList(items.updated);
            if (updated.length > 0) {
                lines.push('');
                lines.push('📝 更新清单:');
                for (let i = 0; i < updated.length; i++)
                    lines.push('🔹 ' + updated[i] + ' (更新)');
            }

            let failed = this._summaryList(items.failed);
            if (failed.length > 0) {
                lines.push('');
                lines.push('❌ 失败清单:');
                for (let i = 0; i < failed.length; i++)
                    lines.push('🔸 ' + failed[i]);
            }

            this._appendNextAction(lines, summary);
            return lines.join('\n');
        }

        if (kind === 'rebuild_groups') {
            lines.push('✅ 节点组重建完成');
            lines.push('');
            lines.push('本地节点组已重新生成。');
            this._appendNextAction(lines, summary);
            return lines.join('\n');
        }

        if (kind === 'apply_config' || kind === 'mode_switch_apply') {
            if (summary.dataplane_success === false) {
                return '⚠️ 配置任务完成，但数据面验证失败\n\n请查看日志确认当前状态。';
            }
            return '✅ 配置已应用\n\n运行态验证通过。';
        }

        return summary.message ? (summary.message + '\n\n请查看日志确认执行结果。') : null;
    },

    _renderModal: function(title, job_id) {
        let status_txt = E('p', { 'class': 'spinning', 'style': 'font-weight:bold; margin-bottom:10px;' }, '任务已入队，等待引擎调度 (Job ID: ' + job_id + ') ...');
        let log_pre = E('pre', {
            'style': 'width: 100%; height: 300px; overflow-y: auto; background: #1e1e1e; color: #4af626; padding: 10px; font-family: monospace; font-size: 12px; border-radius: 4px; white-space: pre-wrap; word-wrap: break-word;'
        }, '[SYSTEM] Initiating job tracking...\n');
        
        let apply_btn = E('button', { 'class': 'cbi-button cbi-button-positive', 'style': 'display: none; margin-top: 15px; margin-right: 8px;' }, '保存并应用');
        let close_btn = E('button', { 'class': 'cbi-button cbi-button-action', 'style': 'display: none; margin-top: 15px;', 'click': ui.hideModal }, '关闭');

        ui.showModal(title, [ status_txt, log_pre, apply_btn, close_btn ]);
        return { status_txt: status_txt, log_pre: log_pre, apply_btn: apply_btn, close_btn: close_btn };
    },

    _appendLogs: function(log_element, lines) {
        let new_text = lines.join('\n') + '\n';
        log_element.textContent += new_text;
        log_element.scrollTop = log_element.scrollHeight;
    },

    _finishModal: function(elements, is_success, message, status) {
        elements.status_txt.className = '';
        if (is_success) {
            elements.status_txt.style.color = '#28a745';
            elements.log_pre.style.display = 'none';
        } else {
            elements.status_txt.style.color = '#dc3545';
            elements.log_pre.style.color = '#dc3545';
            elements.log_pre.textContent += `\n[FATAL] --- 事务回滚或失败 (Transaction Aborted) ---`;
        }
        elements.status_txt.style.whiteSpace = 'pre-line';
        elements.status_txt.textContent = message;
        elements.log_pre.scrollTop = elements.log_pre.scrollHeight;
        if (this._shouldShowApplyButton(status)) {
            elements.apply_btn.onclick = () => {
                elements.apply_btn.disabled = true;
                ui.hideModal();
                this.execute('apply_config', { source: 'observer_followup' }, '保存并应用').catch(() => {});
            };
            elements.apply_btn.style.display = 'inline-block';
        } else {
            elements.apply_btn.style.display = 'none';
        }
        elements.close_btn.style.display = 'inline-block';
    }
});
