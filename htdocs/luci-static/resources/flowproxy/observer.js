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
                            this._finishModal(ui_elements, true, '任务执行成功 (Deploy Success)');
                            resolve(status);
                        } else if (status.state === 'fail' || status.state === 'rollback') {
                            clearInterval(poll_timer);
                            let err_reason = status.error || status.error_code || 'E_EXEC_FAIL';
                            this._finishModal(ui_elements, false, '任务异常终止 [Error: ' + err_reason + ']');
                            reject(new Error(err_reason));
                        } else if (status.state !== 'pending' && status.state !== 'unknown') {
                            // 动态更新运行态进度
                            ui_elements.status_txt.innerHTML = `正在执行引擎调度: [${status.state.toUpperCase()}] ... ${status.progress || 0}%`;
                        }
                    });
                }, 1500); 
            });
        });
    },

    _renderModal: function(title, job_id) {
        let status_txt = E('p', { 'class': 'spinning', 'style': 'font-weight:bold; margin-bottom:10px;' }, '任务已入队，等待引擎调度 (Job ID: ' + job_id + ') ...');
        let log_pre = E('pre', {
            'style': 'width: 100%; height: 300px; overflow-y: auto; background: #1e1e1e; color: #4af626; padding: 10px; font-family: monospace; font-size: 12px; border-radius: 4px; white-space: pre-wrap; word-wrap: break-word;'
        }, '[SYSTEM] Initiating job tracking...\n');
        
        let close_btn = E('button', { 'class': 'cbi-button cbi-button-action', 'style': 'display: none; margin-top: 15px;', 'click': ui.hideModal }, '关闭');

        ui.showModal(title, [ status_txt, log_pre, close_btn ]);
        return { status_txt: status_txt, log_pre: log_pre, close_btn: close_btn };
    },

    _appendLogs: function(log_element, lines) {
        let new_text = lines.join('\n') + '\n';
        log_element.textContent += new_text;
        log_element.scrollTop = log_element.scrollHeight;
    },

    _finishModal: function(elements, is_success, message) {
        elements.status_txt.className = '';
        if (is_success) {
            elements.status_txt.style.color = '#28a745';
            elements.log_pre.textContent += `\n[SYSTEM] --- 事务安全提交 (Transaction Committed) ---`;
        } else {
            elements.status_txt.style.color = '#dc3545';
            elements.log_pre.style.color = '#dc3545';
            elements.log_pre.textContent += `\n[FATAL] --- 事务回滚或失败 (Transaction Aborted) ---`;
        }
        elements.status_txt.innerHTML = (is_success ? '✅ ' : '❌ ') + message;
        elements.log_pre.scrollTop = elements.log_pre.scrollHeight;
        elements.close_btn.style.display = 'inline-block';
    }
});
