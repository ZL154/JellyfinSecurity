            (function() {
                var pluginId = '94879a0c-da24-4eb1-aa06-f28b4b9333b1';
                var page = document.querySelector('#TwoFactorAuth');

                // v2.5.0: defensive translation shim — uses the shared helper
                // when available, otherwise returns the literal English fallback.
                // Keeps dynamic textContent / innerHTML assignments translatable
                // without crashing if tfa-i18n.js failed to load.
                function _tr(k, f) {
                    return (window.tfaI18n && window.tfaI18n.tr) ? window.tfaI18n.tr(k, f) : f;
                }

                // v2.5.0: translate-with-interpolation helper. Used by the
                // dashboard Score-breakdown card so factor.NextAction strings
                // like "Enroll the remaining {count} user(s) in 2FA." get the
                // {count} placeholder replaced from factor.NextActionData. The
                // server stamps both NextAction (English literal w/ number
                // already baked in) AND NextActionKey + NextActionData so the
                // frontend can re-localize without losing the count.
                function _trWithData(key, fallback, data) {
                    var s = _tr(key, fallback);
                    if (s == null) return fallback;
                    if (data && typeof data === 'object') {
                        Object.keys(data).forEach(function(k) {
                            // Escape the placeholder name — keys are
                            // server-controlled today but cheap to harden.
                            var safe = String(k).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                            s = s.replace(new RegExp('\\{' + safe + '\\}', 'g'), data[k]);
                        });
                    }
                    return s;
                }

                // v2.5.0 i18n: the shared helper at /TwoFactorAuth/tfa-i18n.js
                // (loaded from <head>) exposes window.tfaI18n.{tr, applyTranslations,
                // loadTranslations, renderLanguagePicker, getEffectiveLanguage} and
                // auto-runs loadTranslations() on DOMContentLoaded, which walks all
                // [data-i18n-key] / [data-i18n-placeholder] elements on the page.
                // The admin tab labels and headings carry data-i18n-key attributes
                // and are translated automatically — no per-call wiring needed.
                //
                // _initAdminLangPicker mounts the user-level language picker into
                // the Settings tab. We retry on a short delay if the helper hasn't
                // finished parsing yet (race on slow first paint).
                function _initAdminLangPicker() {
                    if (!(window.tfaI18n && window.tfaI18n.renderLanguagePicker)) {
                        setTimeout(_initAdminLangPicker, 100);
                        return;
                    }
                    var host = document.getElementById('adminLangPickerHost');
                    if (host && !host.firstChild) {
                        // v2.5.3: pass onChange so the dynamic Overview content
                        // (factor labels, posture top-action prose, KPI sub-text,
                        // role-enrollment labels) re-renders in the newly-picked
                        // language. tfa-i18n's applyTranslations() only refreshes
                        // [data-i18n-key] elements, which the dynamic containers
                        // intentionally no longer carry — so without this, the
                        // static chrome (tabs, headings) switches but the
                        // breakdown cards keep the previous language.
                        window.tfaI18n.renderLanguagePicker(host, {
                            onChange: function() {
                                if (typeof renderOverview === 'function') renderOverview();
                            }
                        });
                    }
                }

                function getHeaders() {
                    var token = ApiClient && ApiClient.accessToken ? ApiClient.accessToken() : '';
                    return { 'X-Emby-Token': token, 'Content-Type': 'application/json' };
                }
                function apiGet(path) {
                    return fetch(ApiClient.serverAddress() + '/' + path, { headers: getHeaders() }).then(function(r) { return r.ok ? r.json() : Promise.reject(r); });
                }
                function apiPost(path, body) {
                    return fetch(ApiClient.serverAddress() + '/' + path, { method: 'POST', headers: getHeaders(), body: body ? JSON.stringify(body) : undefined }).then(function(r) { return r.ok ? r.json().catch(function(){return{};}) : Promise.reject(r); });
                }
                function apiDelete(path) {
                    return fetch(ApiClient.serverAddress() + '/' + path, { method: 'DELETE', headers: getHeaders() }).then(function(r) { return r.ok ? r.json().catch(function(){return{};}) : Promise.reject(r); });
                }
                function downloadGet(path, fallbackName) {
                    return fetch(ApiClient.serverAddress() + '/' + path, { headers: getHeaders() }).then(function(r) {
                        if (!r.ok) return Promise.reject(r);
                        var cd = r.headers.get('Content-Disposition') || '';
                        var m = /filename="?([^";]+)"?/i.exec(cd);
                        var filename = m ? m[1] : fallbackName;
                        return r.blob().then(function(blob) {
                            var url = URL.createObjectURL(blob);
                            var a = document.createElement('a');
                            a.href = url;
                            a.download = filename;
                            document.body.appendChild(a);
                            a.click();
                            setTimeout(function() { URL.revokeObjectURL(url); a.remove(); }, 1000);
                        });
                    });
                }
                function escapeHtml(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function(c) { return { '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]; }); }

                // ---- v2.5.0: STEP-UP PROMPT MODAL ----
                // promptStepUpCode opens the modal and returns a Promise that
                // resolves with the entered code string, or null on cancel.
                var _stepUpResolve = null;
                var stepUpOverlay = document.getElementById('tfa-stepup-overlay');
                var stepUpCodeInput = document.getElementById('tfa-stepup-code');
                var stepUpErrorEl = document.getElementById('tfa-stepup-error');

                function promptStepUpCode() {
                    return new Promise(function(resolve) {
                        _stepUpResolve = resolve;
                        stepUpErrorEl.textContent = '';
                        stepUpCodeInput.value = '';
                        stepUpOverlay.classList.add('active');
                        // Focus the code input on next tick so animation completes
                        setTimeout(function() { stepUpCodeInput.focus(); }, 50);
                    });
                }
                function closeStepUpModal() {
                    stepUpOverlay.classList.remove('active');
                    stepUpErrorEl.textContent = '';
                    stepUpCodeInput.value = '';
                    if (_stepUpResolve) { _stepUpResolve(null); _stepUpResolve = null; }
                }
                function showStepUpError(msg) {
                    stepUpErrorEl.textContent = msg;
                }

                document.getElementById('tfa-stepup-cancel').addEventListener('click', closeStepUpModal);
                document.getElementById('tfa-stepup-submit').addEventListener('click', function() {
                    var code = stepUpCodeInput.value.trim();
                    if (!code) { showStepUpError(_tr('tfa.admin.modal.err_enter_code', 'Enter a code.')); return; }
                    if (_stepUpResolve) {
                        var cb = _stepUpResolve;
                        _stepUpResolve = null;
                        stepUpOverlay.classList.remove('active');
                        cb(code);
                    }
                });
                stepUpCodeInput.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter') { document.getElementById('tfa-stepup-submit').click(); }
                    if (e.key === 'Escape') { closeStepUpModal(); }
                });
                stepUpOverlay.addEventListener('click', function(e) {
                    if (e.target === stepUpOverlay) closeStepUpModal();
                });
                document.addEventListener('keydown', function(e) {
                    if (e.key === 'Escape' && stepUpOverlay.classList.contains('active')) closeStepUpModal();
                });

                // v2.5.0: step-up-aware fetch wrapper. When the server returns
                // 403 + { stepUpRequired:true } or { twoFactorRequired:true },
                // prompt for a fresh 2FA code, POST it to StepUp/Verify, then
                // transparently replay the original request once.
                // Retry loop: a wrong code shows an inline error and re-prompts
                // rather than leaving the modal stuck non-functional. A 429 from
                // the server (rate-limit hit) shows a distinct message and stops
                // retrying, returning the original 403 to the caller.
                function stepUpFetch(input, init) {
                    var fullInput = (typeof input === 'string' && input.indexOf('http') !== 0)
                        ? ApiClient.serverAddress() + '/' + input
                        : input;
                    var fullInit = init || {};
                    if (!fullInit.headers) fullInit.headers = getHeaders();
                    return fetch(fullInput, fullInit).then(function(resp) {
                        if (resp.status !== 403) return resp;
                        return resp.clone().json().catch(function() { return null; }).then(function(body) {
                            if (!body || (!body.stepUpRequired && !body.twoFactorRequired)) return resp;

                            // Retry loop — keeps the modal open until the user enters a
                            // correct code, cancels, or hits the server rate limit.
                            function tryVerify() {
                                return promptStepUpCode().then(function(code) {
                                    if (!code) return resp; // user cancelled — surface original 403
                                    return fetch(ApiClient.serverAddress() + '/TwoFactorAuth/StepUp/Verify', {
                                        method: 'POST',
                                        headers: getHeaders(),
                                        body: JSON.stringify({ Code: code }),
                                    }).then(function(verifyResp) {
                                        if (verifyResp.ok) {
                                            // Verified — modal already closed by submit handler;
                                            // replay the original request once.
                                            return fetch(fullInput, fullInit);
                                        }
                                        if (verifyResp.status === 429) {
                                            // Rate limit hit — show distinct message, stop retrying.
                                            closeStepUpModal();
                                            showStepUpError(_tr('tfa.admin.modal.err_too_many', 'Too many attempts. Try again later.'));
                                            return resp;
                                        }
                                        // Wrong code — show error and loop back to prompt again.
                                        showStepUpError(_tr('tfa.admin.modal.err_invalid_code', 'Invalid code.'));
                                        return tryVerify();
                                    });
                                });
                            }
                            return tryVerify();
                        });
                    });
                }

                page.querySelectorAll('.tfa-tab').forEach(function(tab) {
                    tab.addEventListener('click', function() {
                        page.querySelectorAll('.tfa-tab').forEach(function(t) { t.classList.remove('active'); });
                        page.querySelectorAll('.tfa-panel').forEach(function(p) { p.classList.remove('active'); });
                        tab.classList.add('active');
                        page.querySelector('#panel-' + tab.dataset.tab).classList.add('active');
                        if (tab.dataset.tab === 'users') loadUsers();
                        if (tab.dataset.tab === 'devices') loadAllDevices();
                        if (tab.dataset.tab === 'pairings') loadPairings();
                        if (tab.dataset.tab === 'audit') loadAudit();
                        if (tab.dataset.tab === 'settings') loadSettings();
                        if (tab.dataset.tab === 'overview') renderOverview();
                        if (tab.dataset.tab === 'diagnostics') { /* run on click */ }
                        if (tab.dataset.tab === 'trips') loadTrips();
                        if (tab.dataset.tab === 'sso') loadSso();
                        if (tab.dataset.tab === 'bans') loadBans();
                    });
                });

                // ---- v1.4: STATS / OVERVIEW ----
                function loadStats() {
                    var box = page.querySelector('#statsBody');
                    box.textContent = 'Loading…';
                    apiGet('TwoFactorAuth/Stats').then(function(s) {
                        var stat = function(label, val, hint) {
                            return '<div class="tfa-stat"><div class="tfa-stat-val">' + val + '</div><div class="tfa-stat-lbl">' + escapeHtml(label) + '</div>' + (hint ? '<div class="tfa-stat-hint">' + escapeHtml(hint) + '</div>' : '') + '</div>';
                        };
                        var html = stat('Users enrolled', (s.enrolledCount || s.EnrolledCount) + ' / ' + (s.totalUsers || s.TotalUsers), (s.enrolledPercent || s.EnrolledPercent) + '%')
                            + stat('Recent enrollments (7d)', (s.recentEnrollments7d || s.RecentEnrollments7d))
                            + stat('Successful logins (24h)', (s.successfulLogins24h || s.SuccessfulLogins24h))
                            + stat('Failed verifies (24h)', (s.failedVerifies24h || s.FailedVerifies24h))
                            + stat('Lockouts (24h)', (s.lockouts24h || s.Lockouts24h));
                        var behind = s.usersBehindDeadline || s.UsersBehindDeadline || [];
                        if (behind.length) {
                            html += '<div class="tfa-stat tfa-stat-warn"><div class="tfa-stat-val">' + behind.length + '</div><div class="tfa-stat-lbl">Past enrollment deadline</div><div class="tfa-stat-hint">' + behind.map(function(u){return escapeHtml(u.username || u.Username);}).slice(0,5).join(', ') + (behind.length > 5 ? '…' : '') + '</div></div>';
                        }
                        box.innerHTML = html;
                    }).catch(function() { box.textContent = 'Failed to load stats.'; });
                }

                // ---- v2.5.0 Phase 2: DASHBOARD OVERVIEW ----
                // _currentRange tracks the active auth-activity chart window.
                // Values: '1w', '1m', '1y' — passed as ?range= to the
                // overview endpoint. The range selector buttons toggle this.
                // 1m is the default since most admins care about the last
                // month of activity at a glance.
                var _currentRange = '1m';

                async function renderOverview() {
                    try {
                        // v2.5.3: defensively strip data-i18n-key from the dynamic
                        // containers BEFORE we write to them. admin.html ships these
                        // with data-i18n-key="tfa.admin.common.loading" so the
                        // initial "Loading…" placeholder localizes. After we
                        // populate them with cards/bars, any subsequent
                        // applyTranslations() sweep (e.g., the bundle finishing its
                        // async load AFTER our innerHTML write, or the user changing
                        // language) would re-walk [data-i18n-key] nodes and
                        // overwrite their content back to the translated "Loading…"
                        // — which is exactly the bug seen in non-English locales.
                        ['factorsGrid', 'enrollmentBars'].forEach(function(id) {
                            var el = document.getElementById(id);
                            if (el && el.hasAttribute('data-i18n-key')) {
                                el.removeAttribute('data-i18n-key');
                            }
                        });
                        const data = await apiGet('TwoFactorAuth/Dashboard/Overview?range=' + encodeURIComponent(_currentRange));

                        // Posture banner
                        const score = data.score.total || 0;
                        const possible = data.score.possible || 100;
                        const grade = data.score.grade || 'F';
                        document.getElementById('postureScore').textContent = score;
                        document.getElementById('postureGrade').textContent = grade;
                        const ring = document.getElementById('postureRingFg');
                        const circumference = 2 * Math.PI * 40; // r=40
                        ring.setAttribute('stroke-dasharray', circumference.toFixed(1));
                        ring.setAttribute('stroke-dashoffset', (circumference * (1 - score / possible)).toFixed(1));
                        ring.classList.remove('warn', 'bad');
                        if (score < 50) ring.classList.add('bad');
                        else if (score < 80) ring.classList.add('warn');

                        // Posture summary: top "next action" or congratulations
                        // v2.5.0: resolve the localized next-action via the key + data
                        // pair so the Top-action banner reads in the user's language
                        // instead of falling through to the English literal.
                        const gaps = data.score.factors.filter(f => f.nextAction);
                        document.getElementById('postureSummary').textContent = gaps.length === 0
                            ? _tr('tfa.admin.posture_all_full', 'All factors at full credit — well done.')
                            : `${_tr('tfa.admin.posture_top_action', 'Top action:')} ${_trWithData(gaps[0].nextActionKey, gaps[0].nextAction, gaps[0].nextActionData)} (+${gaps[0].possible - gaps[0].earned} pts)`;

                        // KPI strip
                        document.getElementById('kpiEnrolled').textContent = data.kpis.enrolledUsers ?? '–';
                        document.getElementById('kpiEnrolledSub').textContent = `${_tr('tfa.admin.overview.kpi_of', 'of')} ${data.kpis.totalUsers ?? '–'} ${_tr('tfa.admin.overview.kpi_users', 'users')}`;
                        document.getElementById('kpiSessions').textContent = data.kpis.activeSessions ?? '–';
                        document.getElementById('kpiBans').textContent = data.kpis.bannedIps ?? '–';
                        document.getElementById('kpiAudit').textContent = data.kpis.auditEntries ?? '–';
                        document.getElementById('kpiAuditSub').textContent = data.kpis.auditChainBroken === 0
                            ? _tr('tfa.admin.kpi_audit_chain_ok', 'chain ok') : `${data.kpis.auditChainBroken} ${_tr('tfa.admin.kpi_audit_chain_broken', 'broken')}`;

                        // Factor grid
                        // v2.5.0: each factor row uses f.labelKey + f.nextActionKey + f.nextActionData
                        // so the breakdown card localizes alongside the rest of the admin UI.
                        // English literals on f.label / f.nextAction stay as the fallback when
                        // a key is missing from the active bundle.
                        const factorsEl = document.getElementById('factorsGrid');
                        factorsEl.innerHTML = (data.score.factors || []).map(f => {
                            const pct = f.possible > 0 ? Math.round(100 * f.earned / f.possible) : 0;
                            const label = _tr(f.labelKey, f.label);
                            const action = f.nextAction ? _trWithData(f.nextActionKey, f.nextAction, f.nextActionData) : null;
                            return `<div class="tfa-factor ${f.status}">
                                <div class="tfa-factor-head">
                                    <div class="tfa-factor-label">${escapeHtml(label)}</div>
                                    <div class="tfa-factor-pts">${f.earned} / ${f.possible}</div>
                                </div>
                                <div class="tfa-factor-bar"><div class="tfa-factor-bar-fill" style="width:${pct}%"></div></div>
                                ${action ? `<div class="tfa-factor-action">&rarr; ${escapeHtml(action)}</div>` : ''}
                            </div>`;
                        }).join('');

                        // Auth-activity chart — stacked area: success (green), failed (orange), locked (red)
                        // v2.5.0: heading reflects the active range.
                        var headingEl = document.getElementById('authChartHeading');
                        if (headingEl) {
                            var hKey = _currentRange === '1y'
                                ? 'tfa.admin.chart.heading_1y'
                                : (_currentRange === '1w' ? 'tfa.admin.chart.heading_1w' : 'tfa.admin.chart.heading_1m');
                            var hFallback = _currentRange === '1y'
                                ? 'Auth activity (last year)'
                                : (_currentRange === '1w' ? 'Auth activity (last week)' : 'Auth activity (last month)');
                            headingEl.textContent = _tr(hKey, hFallback);
                        }
                        renderAuthChart(data.timeSeries || []);

                        // Enrollment by role bars
                        const r = data.enrollmentByRole || {};
                        const adminsPct = r.adminsTotal > 0 ? Math.round(100 * r.adminsEnrolled / r.adminsTotal) : 0;
                        const regularPct = r.regularTotal > 0 ? Math.round(100 * r.regularEnrolled / r.regularTotal) : 0;
                        document.getElementById('enrollmentBars').innerHTML = `
                            <div style="margin-bottom:10px;">
                                <div style="display:flex;justify-content:space-between;font-size:12px;color:#bbb;margin-bottom:4px;"><span>${escapeHtml(_tr('tfa.admin.overview.role_admins', 'Admins'))}</span><span>${r.adminsEnrolled || 0} / ${r.adminsTotal || 0} (${adminsPct}%)</span></div>
                                <div class="tfa-factor-bar"><div class="tfa-factor-bar-fill" style="width:${adminsPct}%;background:${adminsPct === 100 ? '#5cb85c' : '#f0ad4e'}"></div></div>
                            </div>
                            <div>
                                <div style="display:flex;justify-content:space-between;font-size:12px;color:#bbb;margin-bottom:4px;"><span>${escapeHtml(_tr('tfa.admin.overview.role_regular', 'Regular users'))}</span><span>${r.regularEnrolled || 0} / ${r.regularTotal || 0} (${regularPct}%)</span></div>
                                <div class="tfa-factor-bar"><div class="tfa-factor-bar-fill" style="width:${regularPct}%;background:#00a4dc"></div></div>
                            </div>`;

                        // Ban table
                        const bansBody = document.getElementById('overviewBansBody');
                        const bans = data.bans || [];
                        bansBody.innerHTML = bans.length === 0
                            ? `<tr><td colspan="5" class="tfa-empty">${escapeHtml(_tr('tfa.admin.no_active_bans', 'No active bans'))}</td></tr>`
                            : bans.map(b => `<tr>
                                <td>${escapeHtml(b.ip)}</td>
                                <td>${escapeHtml(b.source)}</td>
                                <td>${b.failureCount}</td>
                                <td>${new Date(b.bannedAt).toLocaleString()}</td>
                                <td>${new Date(b.expiresAt).toLocaleString()}</td>
                            </tr>`).join('');
                    } catch (err) {
                        console.error('renderOverview failed', err);
                        document.getElementById('postureSummary').textContent = _tr('tfa.admin.overview.load_failed', 'Failed to load dashboard. Check the server log.');
                    }
                }

                function renderAuthChart(series) {
                    const svg = document.getElementById('authChart');
                    const tooltip = document.getElementById('authChartTooltip');
                    svg.innerHTML = '';
                    if (tooltip) tooltip.style.display = 'none';
                    if (series.length === 0) {
                        svg.innerHTML = '<text x="300" y="70" text-anchor="middle" fill="#666" font-size="12">' + escapeHtml(_tr('tfa.admin.overview.no_chart_data', 'No data in the last 30 days')) + '</text>';
                        return;
                    }
                    const W = 600, H = 140, padL = 30, padR = 10, padT = 10, padB = 20;
                    const max = Math.max(1, ...series.map(s => (s.success + s.failed + s.locked)));
                    const xStep = (W - padL - padR) / Math.max(1, series.length - 1);
                    const yScale = (v) => H - padB - ((H - padT - padB) * v / max);
                    const layers = ['success', 'failed', 'locked'];
                    const colors = { success: '#5cb85c', failed: '#f0ad4e', locked: '#d9534f' };
                    let baseline = series.map(() => 0);
                    let svgInner = '';
                    for (const layer of layers) {
                        let points = [];
                        let bottomPoints = [];
                        series.forEach((s, i) => {
                            const val = s[layer] || 0;
                            const x = padL + i * xStep;
                            const yTop = yScale(baseline[i] + val);
                            const yBot = yScale(baseline[i]);
                            points.push(`${x},${yTop}`);
                            bottomPoints.push(`${x},${yBot}`);
                            baseline[i] += val;
                        });
                        const poly = points.concat(bottomPoints.reverse()).join(' ');
                        svgInner += `<polygon points="${poly}" fill="${colors[layer]}" fill-opacity="0.55" stroke="${colors[layer]}" stroke-width="1" />`;
                    }
                    // v2.5.0: light horizontal gridlines at 25/50/75% of max
                    // so the chart isn't visually flat between 0 and the top
                    // value. Drawn UNDER the polygons (svgInner ordering) so
                    // they read as faint background grid.
                    [0.25, 0.5, 0.75].forEach(frac => {
                        const v = Math.round(max * frac);
                        const y = yScale(v);
                        svgInner = `<line x1="${padL}" y1="${y}" x2="${W - padR}" y2="${y}" stroke="#2a2a2a" stroke-width="1" stroke-dasharray="2,3" />` +
                                   `<text x="${padL - 4}" y="${y + 3}" text-anchor="end" fill="#666" font-size="9">${v}</text>` +
                                   svgInner;
                    });
                    // Y axis baseline
                    svgInner += `<line x1="${padL}" y1="${H - padB}" x2="${W - padR}" y2="${H - padB}" stroke="#444" stroke-width="1" />`;
                    svgInner += `<text x="${padL - 4}" y="${padT + 8}" text-anchor="end" fill="#888" font-size="10">${max}</text>`;
                    svgInner += `<text x="${padL - 4}" y="${H - padB}" text-anchor="end" fill="#888" font-size="10">0</text>`;
                    // v2.5.0: x-axis date labels — show first, middle, last
                    // bucket so the user knows what date range they're seeing.
                    if (series.length >= 2) {
                        const indices = series.length >= 4
                            ? [0, Math.floor(series.length / 2), series.length - 1]
                            : [0, series.length - 1];
                        indices.forEach(i => {
                            const x = padL + i * xStep;
                            // For monthly buckets (yyyy-MM) show as-is; for daily (yyyy-MM-dd) show MM-dd.
                            const lbl = series[i].date.length === 7
                                ? series[i].date
                                : series[i].date.substring(5);
                            const anchor = i === 0 ? 'start' : (i === series.length - 1 ? 'end' : 'middle');
                            svgInner += `<text x="${x}" y="${H - 6}" text-anchor="${anchor}" fill="#888" font-size="9">${escapeHtml(lbl)}</text>`;
                        });
                    }

                    // v2.5.0: filled data-point markers at the top of the
                    // stacked totals so each day/month is a visible dot.
                    series.forEach((s, i) => {
                        const total = (s.success || 0) + (s.failed || 0) + (s.locked || 0);
                        const x = padL + i * xStep;
                        const y = yScale(total);
                        svgInner += `<circle class="tfa-chart-point" cx="${x}" cy="${y}" r="3" fill="#fff" stroke="#00a4dc" stroke-width="1" data-idx="${i}" />`;
                    });

                    // v2.5.0: invisible hit-target rects, one per data point.
                    // Wider than the marker so hover is forgiving on dense series.
                    const hitW = Math.max(xStep, 8);
                    series.forEach((s, i) => {
                        const x = padL + i * xStep - hitW / 2;
                        svgInner += `<rect class="tfa-chart-hit" x="${x}" y="${padT}" width="${hitW}" height="${H - padT - padB}" fill="transparent" data-idx="${i}" />`;
                    });

                    svg.innerHTML = svgInner;

                    // v2.5.0: hover wiring — populate + position the tooltip
                    // relative to the chart card on each rect's mouseover.
                    if (tooltip) {
                        const card = svg.closest('.tfa-chart-card');
                        const lblSuccess = _tr('tfa.admin.chart.successful', 'Successful');
                        const lblFailed = _tr('tfa.admin.chart.failed', 'Failed');
                        const lblLocked = _tr('tfa.admin.chart.locked', 'Locked-out');
                        const showTip = function(idx, evt) {
                            const s = series[idx];
                            if (!s) return;
                            tooltip.innerHTML =
                                '<div class="tt-date">' + escapeHtml(s.date) + '</div>' +
                                '<div class="tt-row tt-success"><span>' + escapeHtml(lblSuccess) + '</span><span>' + (s.success || 0) + '</span></div>' +
                                '<div class="tt-row tt-failed"><span>' + escapeHtml(lblFailed) + '</span><span>' + (s.failed || 0) + '</span></div>' +
                                '<div class="tt-row tt-locked"><span>' + escapeHtml(lblLocked) + '</span><span>' + (s.locked || 0) + '</span></div>';
                            tooltip.style.display = 'block';
                            if (card) {
                                const cardRect = card.getBoundingClientRect();
                                let left = evt.clientX - cardRect.left + 12;
                                let top = evt.clientY - cardRect.top + 12;
                                // keep inside card horizontally
                                const tw = tooltip.offsetWidth || 160;
                                if (left + tw > cardRect.width) left = cardRect.width - tw - 4;
                                if (left < 0) left = 0;
                                tooltip.style.left = left + 'px';
                                tooltip.style.top = top + 'px';
                            }
                        };
                        const hideTip = function() { tooltip.style.display = 'none'; };
                        Array.prototype.forEach.call(svg.querySelectorAll('.tfa-chart-hit'), function(rect) {
                            const idx = parseInt(rect.getAttribute('data-idx'), 10);
                            rect.addEventListener('mouseover', function(e) { showTip(idx, e); });
                            rect.addEventListener('mousemove', function(e) { showTip(idx, e); });
                            rect.addEventListener('mouseout', hideTip);
                        });
                    }
                }

                // v2.5.0: auth-activity chart range buttons. Click handlers
                // swap the active class, update _currentRange, and re-fetch
                // the dashboard overview so the chart redraws with the new
                // window. Buttons are inside the Overview panel, so they
                // exist at IIFE-parse time.
                var rangeContainer = document.getElementById('authChartRange');
                if (rangeContainer) {
                    rangeContainer.addEventListener('click', function(e) {
                        var btn = e.target.closest('.tfa-range-btn');
                        if (!btn) return;
                        var r = btn.getAttribute('data-range');
                        if (!r || r === _currentRange) return;
                        _currentRange = r;
                        Array.prototype.forEach.call(rangeContainer.querySelectorAll('.tfa-range-btn'), function(b) {
                            b.classList.toggle('active', b === btn);
                        });
                        renderOverview();
                    });
                }

                // ---- v1.4: DIAGNOSTICS ----
                page.querySelector('#diagRun').addEventListener('click', function() {
                    var box = page.querySelector('#diagResults');
                    box.innerHTML = escapeHtml(_tr('tfa.admin.diagnostics.running', 'Running…'));
                    apiGet('TwoFactorAuth/Diagnostics').then(function(rows) {
                        if (!rows || !rows.length) { box.innerHTML = '<em>' + escapeHtml(_tr('tfa.admin.diagnostics.no_checks', 'No checks ran.')) + '</em>'; return; }
                        box.innerHTML = '<table class="tfa-table"><thead><tr><th>' + escapeHtml(_tr('tfa.admin.diagnostics.col_check', 'Check')) + '</th><th>' + escapeHtml(_tr('tfa.admin.diagnostics.col_status', 'Status')) + '</th><th>' + escapeHtml(_tr('tfa.admin.diagnostics.col_detail', 'Detail')) + '</th></tr></thead><tbody>' +
                            rows.map(function(r) {
                                var s = (r.status || r.Status || '').toLowerCase();
                                var cls = s === 'ok' ? 'on' : (s === 'warn' ? 'warn' : 'locked');
                                return '<tr><td>' + escapeHtml(r.label || r.Label) + '</td><td><span class="tfa-badge ' + cls + '">' + (r.status || r.Status) + '</span></td><td style="font-size:12px;color:#aaa;">' + escapeHtml(r.detail || r.Detail) + '</td></tr>';
                            }).join('') + '</tbody></table>';
                    }).catch(function() { box.innerHTML = '<span style="color:#f44336;">' + escapeHtml(_tr('tfa.admin.diagnostics.failed', 'Failed to run diagnostics.')) + '</span>'; });
                });

                // ---- v2.5.0: REBUILD AUDIT CHAIN ----
                // Gated by the destructive-tier step-up policy server-side.
                // We use stepUpFetch so a 401-with-stepup-challenge body
                // pops the verification modal and retries automatically.
                var rebuildBtn = page.querySelector('#rebuildChainBtn');
                if (rebuildBtn) {
                    rebuildBtn.addEventListener('click', function() {
                        var msg = _tr('tfa.admin.audit.rebuild_confirm',
                            'Rebuild the audit hash chain from current data? This clears the broken-chain warning but ERASES evidence of any tampering. Continue?');
                        if (!confirm(msg)) return;
                        var out = page.querySelector('#rebuildChainResult');
                        out.style.color = '#888';
                        out.textContent = _tr('tfa.admin.common.saving', 'Saving…');
                        stepUpFetch('TwoFactorAuth/Admin/RebuildAuditChain', {
                            method: 'POST',
                            headers: getHeaders()
                        }).then(function(r) {
                            if (!r || (!r.ok && r.status !== 200)) {
                                out.style.color = '#f44336';
                                out.textContent = '✗ ' + _tr('tfa.admin.common.save_failed', 'Save failed');
                                return;
                            }
                            return r.json().catch(function() { return { rebuilt: 0 }; }).then(function(body) {
                                out.style.color = '#4caf50';
                                var tpl = _tr('tfa.admin.audit.rebuild_success', 'Rebuilt N audit entries.');
                                // Backwards-compatible substitution: prefer
                                // {count} if the translator switched to a
                                // placeholder, otherwise fall back to "N".
                                out.textContent = '✓ ' + tpl.replace('{count}', body.rebuilt || 0).replace('N', body.rebuilt || 0);
                                // Re-run diagnostics so the broken-chain row
                                // updates to "ok" without a manual refresh.
                                var diagBtn = page.querySelector('#diagRun');
                                if (diagBtn) diagBtn.click();
                                // Re-render the Overview so the score factor
                                // also reflects the cleared warning.
                                if (typeof renderOverview === 'function') renderOverview();
                            });
                        }).catch(function() {
                            out.style.color = '#f44336';
                            out.textContent = '✗ ' + _tr('tfa.admin.common.save_failed', 'Save failed');
                        });
                    });
                }

                // ---- v1.4: RATE LIMIT TRIPS ----
                function loadTrips() {
                    apiGet('TwoFactorAuth/RateLimitTrips').then(function(rows) {
                        var body = page.querySelector('#tripsBody');
                        if (!rows || !rows.length) { body.innerHTML = '<tr><td colspan="5" class="tfa-empty">' + escapeHtml(_tr('tfa.admin.trips.empty', 'No trips since startup')) + '</td></tr>'; return; }
                        body.innerHTML = rows.slice().reverse().map(function(t) {
                            var d = new Date(t.at || t.At).toLocaleString();
                            return '<tr><td style="font-size:12px;">' + d + '</td><td style="font-family:monospace;font-size:12px;">' + escapeHtml(t.key || t.Key) + '</td><td>' + (t.limit || t.Limit) + '</td><td>' + (t.windowSeconds || t.WindowSeconds) + '</td><td>' + (t.retryAfterSeconds || t.RetryAfterSeconds) + '</td></tr>';
                        }).join('');
                    }).catch(function() { page.querySelector('#tripsBody').innerHTML = '<tr><td colspan="5" class="tfa-empty">' + escapeHtml(_tr('tfa.admin.common.failed_to_load', 'Failed to load')) + '</td></tr>'; });
                }
                page.querySelector('#tripsRefresh').addEventListener('click', loadTrips);

                // ---- USERS ----
                var allUsersData = [];
                function loadUsers() {
                    apiGet('TwoFactorAuth/Users').then(function(users) {
                        allUsersData = users || [];
                        renderUsers();
                    }).catch(function() {
                        page.querySelector('#usersBody').innerHTML = '<tr><td colspan="7" class="tfa-empty">' + escapeHtml(_tr('tfa.admin.users.load_failed', 'Failed to load users')) + '</td></tr>';
                    });
                }
                function renderUsers() {
                    var body = page.querySelector('#usersBody');
                    if (!allUsersData.length) { body.innerHTML = '<tr><td colspan="7" class="tfa-empty">' + escapeHtml(_tr('tfa.admin.users.no_data', 'No user data yet')) + '</td></tr>'; return; }
                    // Render immediately with emails empty, then fill in async.
                    // Avoids blank table if plugin config can't be fetched.
                    var emails = {};
                    renderUsersRow(emails);
                    ApiClient.getPluginConfiguration(pluginId).then(function(config) {
                        (config.UserEmails || []).forEach(function(e) { emails[(e.UserId || e.userId || '').toLowerCase()] = e.Email || e.email || ''; });
                        renderUsersRow(emails);
                    }).catch(function(err) { console.warn('[2FA] getPluginConfiguration failed:', err); });
                }
                function renderUsersRow(emails) {
                    var body = page.querySelector('#usersBody');
                    var q = (page.querySelector('#usersFilter').value || '').toLowerCase();
                    var rows = allUsersData.filter(function(u) {
                        if (!q) return true;
                        return (u.username || u.Username || '').toLowerCase().indexOf(q) >= 0;
                    });
                    if (!rows.length) { body.innerHTML = '<tr><td colspan="7" class="tfa-empty">' + escapeHtml(_tr('tfa.admin.users.no_match', 'No users match')) + '</td></tr>'; return; }
                    var tDetails = _tr('tfa.admin.users.details', '▸ details');
                    var tPasskeys = _tr('tfa.admin.users.tip_passkeys', 'Passkeys');
                    var tTotp = _tr('tfa.admin.users.tip_totp', 'TOTP');
                    var tTotpOff = _tr('tfa.admin.users.tip_totp_off', 'TOTP off');
                    var tRcLeft = _tr('tfa.admin.users.tip_rc_left', 'Recovery codes left');
                    var tNoRc = _tr('tfa.admin.users.tip_no_rc', 'No recovery codes');
                    var tLocked = _tr('tfa.admin.users.status_locked', 'Locked');
                    var tOk = _tr('tfa.admin.common.ok', 'OK');
                    var tDisable = _tr('tfa.admin.users.btn_disable', 'Disable');
                    var tEnable = _tr('tfa.admin.users.btn_enable', 'Enable');
                    var tForceLogout = _tr('tfa.admin.users.btn_force_logout', 'Force logout');
                    var tRevokeAll = _tr('tfa.admin.users.btn_revoke_all', 'Revoke all');
                    var tExport = _tr('tfa.admin.users.btn_export', 'Export');
                    var tUnknown = _tr('tfa.admin.users.unknown', 'Unknown');
                    var tClickDetails = _tr('tfa.admin.users.click_to_load', 'Click ▸ details to load');
                    body.innerHTML = rows.map(function(u) {
                        var uid = u.userId || u.UserId;
                        var uidPlain = String(uid).replace(/-/g,'');
                        var totp = u.totpEnabled || u.TotpEnabled;
                        var passkeyCount = u.passkeyCount || u.PasskeyCount || 0;
                        var locked = u.isLockedOut || u.IsLockedOut;
                        var devices = u.trustedDeviceCount || u.TrustedDeviceCount || 0;
                        var recoveryRemaining = u.recoveryCodesRemaining || u.RecoveryCodesRemaining || 0;
                        var email = emails[uidPlain.toLowerCase()] || '';
                        // Consolidated 2FA cell — TOTP + passkeys + recovery in one column
                        var twoFa = '';
                        twoFa += totp ? '<span class="tfa-badge on" title="' + escapeHtml(tTotp) + '">TOTP</span> ' : '<span class="tfa-badge off" title="' + escapeHtml(tTotpOff) + '">TOTP</span> ';
                        if (passkeyCount > 0) twoFa += '<span class="tfa-badge on" title="' + escapeHtml(tPasskeys) + '">🔑×' + passkeyCount + '</span> ';
                        twoFa += recoveryRemaining > 0
                            ? '<span class="tfa-badge on" title="' + escapeHtml(tRcLeft) + '">RC×' + recoveryRemaining + '</span>'
                            : '<span class="tfa-badge warn" title="' + escapeHtml(tNoRc) + '">no RC</span>';
                        return '<tr class="tfa-user-row" data-uid="' + uid + '">' +
                            '<td><input type="checkbox" class="tfa-user-select" data-uid="' + uid + '" /></td>' +
                            '<td><strong>' + escapeHtml(u.username || u.Username || tUnknown) + '</strong> ' +
                              '<a href="#" class="tfa-row-toggle" data-uid="' + uid + '" style="font-size:11px;color:#888;text-decoration:none;margin-left:4px;">' + escapeHtml(tDetails) + '</a></td>' +
                            '<td>' + twoFa + '</td>' +
                            '<td>' + devices + '</td>' +
                            '<td><input type="email" class="tfa-input tfa-email" data-uid="' + uidPlain + '" value="' + escapeHtml(email) + '" placeholder="user@example.com" style="width:200px;" /></td>' +
                            '<td>' + (locked ? '<span class="tfa-badge locked">' + escapeHtml(tLocked) + '</span>' : '<span class="tfa-badge on">' + escapeHtml(tOk) + '</span>') + '</td>' +
                            '<td style="white-space:nowrap;">' +
                              '<button class="tfa-btn tfa-btn-primary tfa-toggle" data-id="' + uid + '" data-next="' + !totp + '">' + escapeHtml(totp ? tDisable : tEnable) + '</button> ' +
                              '<button class="tfa-btn tfa-btn-danger tfa-force-logout" data-id="' + uid + '">' + escapeHtml(tForceLogout) + '</button> ' +
                              '<button class="tfa-btn tfa-revoke-all" data-id="' + uid + '">' + escapeHtml(tRevokeAll) + '</button> ' +
                              '<button class="tfa-btn tfa-export-user" data-id="' + uid + '">' + escapeHtml(tExport) + '</button>' +
                            '</td>' +
                            '</tr>' +
                            // Hidden details row — populated lazily on first toggle
                            '<tr class="tfa-user-details" data-uid="' + uid + '" style="display:none;">' +
                              '<td colspan="7" style="background:rgba(0,0,0,0.25);padding:14px;font-size:12px;">' +
                                '<div class="tfa-details-content" data-loaded="0">' + escapeHtml(tClickDetails) + '</div>' +
                              '</td>' +
                            '</tr>';
                    }).join('');
                    body.querySelectorAll('.tfa-force-logout').forEach(function(b) {
                        b.addEventListener('click', function() {
                            if (!confirm(_tr('tfa.admin.users.confirm_force_logout', 'Force-logout this user? All their Jellyfin sessions are terminated and trust state is cleared.'))) return;
                            apiPost('TwoFactorAuth/Users/' + b.dataset.id + '/ForceLogout').then(function(r) {
                                alert(_tr('tfa.admin.users.terminated_prefix', 'Terminated') + ' ' + (r.sessionsTerminated || 0) + ' ' + _tr('tfa.admin.users.sessions_suffix', 'sessions.'));
                                loadUsers();
                            });
                        });
                    });
                    body.querySelectorAll('.tfa-revoke-all').forEach(function(b) {
                        b.addEventListener('click', function() {
                            if (!confirm(_tr('tfa.admin.users.confirm_revoke_all', 'Revoke EVERY trusted browser, paired device, registered device id and app password for this user? They will need to re-do 2FA on every client.'))) return;
                            // v2.5.0: route through stepUpFetch so destructive bulk actions
                            // can be gated by the server's StepUpLevel setting.
                            // First call uses stepUpFetch; remaining two use plain apiPost
                            // since step-up token is valid for the window after first verify.
                            stepUpFetch('TwoFactorAuth/Admin/Bulk', {
                                method: 'POST',
                                headers: getHeaders(),
                                body: JSON.stringify({ action: 'revoke_paired_devices', userIds: [b.dataset.id] }),
                            }).then(function(r) {
                                if (!r.ok) return Promise.reject(r);
                                return Promise.all([
                                    apiPost('TwoFactorAuth/Admin/Bulk', { action: 'revoke_trusted_browsers', userIds: [b.dataset.id] }),
                                    apiPost('TwoFactorAuth/Admin/Bulk', { action: 'force_logout', userIds: [b.dataset.id] }),
                                ]);
                            }).then(function() { alert(_tr('tfa.admin.users.revoked', 'Revoked.')); loadUsers(); })
                              .catch(function() { /* step-up cancelled or server error — silently ignore */ });
                        });
                    });
                    body.querySelectorAll('.tfa-export-user').forEach(function(b) {
                        b.addEventListener('click', function() {
                            downloadGet('TwoFactorAuth/Users/' + encodeURIComponent(b.dataset.id) + '/Export', '2fa-export-' + b.dataset.id + '.json');
                        });
                    });
                    wireUsersRowExtras();
                    body.querySelectorAll('.tfa-row-toggle').forEach(function(t) {
                        t.addEventListener('click', function(e) {
                            e.preventDefault();
                            var uid = t.dataset.uid;
                            var det = body.querySelector('.tfa-user-details[data-uid="' + uid + '"]');
                            if (!det) return;
                            var open = det.style.display !== 'none';
                            det.style.display = open ? 'none' : 'table-row';
                            t.textContent = open ? _tr('tfa.admin.users.details', '▸ details') : _tr('tfa.admin.users.hide', '▾ hide');
                            if (!open) {
                                var content = det.querySelector('.tfa-details-content');
                                if (content && content.dataset.loaded === '0') {
                                    content.dataset.loaded = '1';
                                    content.innerHTML = 'Loading…';
                                    apiGet('TwoFactorAuth/Users/' + uid + '/Export').then(function(exp) {
                                        var trusted = (exp.devices && exp.devices.trusted) || [];
                                        var paired = (exp.devices && exp.devices.paired) || [];
                                        var passkeys = (exp.twoFactor && exp.twoFactor.passkeys) || [];
                                        var apps = (exp.twoFactor && exp.twoFactor.appPasswords) || [];
                                        content.innerHTML =
                                            '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;">' +
                                              renderDetailList(_tr('tfa.admin.users.detail_trusted', 'Trusted browsers') + ' (' + trusted.length + ')', trusted, function(d) { return escapeHtml(d.deviceName) + ' <span class="muted">' + new Date(d.lastUsedAt).toLocaleDateString() + '</span>'; }) +
                                              renderDetailList(_tr('tfa.admin.users.detail_paired', 'Paired devices') + ' (' + paired.length + ')', paired, function(d) { return escapeHtml(d.deviceName) + ' <span class="muted">' + escapeHtml(d.appName || '') + '</span>'; }) +
                                              renderDetailList(_tr('tfa.admin.users.detail_passkeys', 'Passkeys') + ' (' + passkeys.length + ')', passkeys, function(d) { return escapeHtml(d.label || _tr('tfa.admin.users.passkey_default', 'Passkey')) + ' <span class="muted">' + new Date(d.createdAt).toLocaleDateString() + '</span>'; }) +
                                              renderDetailList(_tr('tfa.admin.users.detail_app_pw', 'App passwords') + ' (' + apps.length + ')', apps, function(d) { return escapeHtml(d.label) + ' <span class="muted">' + new Date(d.createdAt).toLocaleDateString() + '</span>'; }) +
                                            '</div>';
                                    }).catch(function() { content.innerHTML = escapeHtml(_tr('tfa.admin.users.details_failed', 'Failed to load details.')); });
                                }
                            }
                        });
                    });
                }

                // Collapsible list helper for the details row — caps visible
                // entries at 3 by default with an "expand" link if more exist.
                function renderDetailList(title, items, fmt) {
                    if (!items.length) return '<div><strong>' + escapeHtml(title) + '</strong><div class="muted">' + escapeHtml(_tr('tfa.admin.common.none', 'none')) + '</div></div>';
                    var head = '<div><strong>' + escapeHtml(title) + '</strong>';
                    var visible = items.slice(0, 3).map(fmt);
                    var hidden = items.slice(3).map(fmt);
                    var html = head;
                    visible.forEach(function(v) { html += '<div>' + v + '</div>'; });
                    if (hidden.length) {
                        var moreId = 'more_' + Math.random().toString(36).slice(2, 8);
                        html += '<div id="' + moreId + '" style="display:none;">';
                        hidden.forEach(function(v) { html += '<div>' + v + '</div>'; });
                        html += '</div>';
                        html += '<a href="#" class="tfa-detail-more" data-target="' + moreId + '" style="font-size:11px;color:#00a4dc;text-decoration:none;">+ ' + hidden.length + ' ' + escapeHtml(_tr('tfa.admin.common.more', 'more')) + '</a>';
                    }
                    html += '</div>';
                    return html;
                }
                // Wire expand links — delegate via panel root since details rows
                // populate lazily.
                page.querySelector('#panel-users').addEventListener('click', function(e) {
                    var t = e.target;
                    if (!t.classList || !t.classList.contains('tfa-detail-more')) return;
                    e.preventDefault();
                    var box = document.getElementById(t.dataset.target);
                    if (!box) return;
                    var open = box.style.display !== 'none';
                    box.style.display = open ? 'none' : 'block';
                    var n = box.querySelectorAll('div').length;
                    t.textContent = open ? ('+ ' + n + ' ' + _tr('tfa.admin.common.more', 'more')) : ('− ' + _tr('tfa.admin.common.collapse', 'collapse'));
                });
                // Original handlers (toggle + email blur) — these were originally
                // inside renderUsersRow; restored here as inline finishers.
                function wireUsersRowExtras() {
                    var body = page.querySelector('#usersBody');
                    body.querySelectorAll('.tfa-toggle').forEach(function(btn) {
                        btn.addEventListener('click', function() {
                            apiPost('TwoFactorAuth/Users/' + btn.dataset.id + '/Toggle', { enabled: btn.dataset.next === 'true' }).then(loadUsers);
                        });
                    });
                    body.querySelectorAll('.tfa-email').forEach(function(input) {
                        input.addEventListener('blur', function() {
                            ApiClient.getPluginConfiguration(pluginId).then(function(cfg) {
                                cfg.UserEmails = cfg.UserEmails || [];
                                var uid = input.dataset.uid;
                                cfg.UserEmails = cfg.UserEmails.filter(function(e) { return ((e.UserId || e.userId || '').toLowerCase() !== uid.toLowerCase()); });
                                var v = input.value.trim();
                                if (v) cfg.UserEmails.push({ UserId: uid, Email: v });
                                return ApiClient.updatePluginConfiguration(pluginId, cfg);
                            });
                        });
                    });
                }

                // ---- TRUSTED DEVICES (all users, grouped, collapsible) ----
                function loadAllDevices() {
                    apiGet('TwoFactorAuth/AllTrustedDevices').then(function(rows) {
                        var body = page.querySelector('#devicesBody');
                        if (!rows || !rows.length) { body.innerHTML = '<tr><td colspan="6" class="tfa-empty">' + escapeHtml(_tr('tfa.admin.devices.empty', 'No trusted devices')) + '</td></tr>'; return; }
                        // Group by user — long unbroken lists are unreadable.
                        var byUser = {};
                        rows.forEach(function(r) {
                            var uid = r.userId || r.UserId;
                            (byUser[uid] = byUser[uid] || { user: r.username || r.Username, devices: [] }).devices.push(r);
                        });
                        var groupHtml = '';
                        Object.keys(byUser).forEach(function(uid) {
                            var g = byUser[uid];
                            var first = g.devices.slice(0, 3);
                            var rest = g.devices.slice(3);
                            var devRow = function(r) {
                                var added = new Date(r.createdAt || r.CreatedAt);
                                var last = new Date(r.lastUsedAt || r.LastUsedAt);
                                var expires = new Date(added.getTime() + 30*24*3600*1000);
                                return '<tr>' +
                                    '<td style="padding-left:20px;">' + escapeHtml(r.deviceName || r.DeviceName) + '</td>' +
                                    '<td>' + added.toLocaleDateString() + '</td>' +
                                    '<td>' + last.toLocaleString() + '</td>' +
                                    '<td>' + expires.toLocaleDateString() + '</td>' +
                                    '<td><button class="tfa-btn tfa-btn-danger tfa-revoke-dev" data-uid="' + uid + '" data-id="' + (r.id || r.Id) + '">' + escapeHtml(_tr('tfa.admin.devices.btn_revoke', 'Revoke')) + '</button></td>' +
                                    '</tr>';
                            };
                            var groupId = 'g_' + String(uid).replace(/-/g,'');
                            groupHtml += '<tr class="tfa-dev-group-row" style="background:rgba(0,164,220,0.08);">' +
                                '<td colspan="5" style="font-weight:700;">' + escapeHtml(g.user) +
                                ' <span class="muted" style="font-weight:normal;font-size:12px;">(' + g.devices.length + ')</span> ' +
                                '<button class="tfa-btn tfa-btn-danger tfa-revoke-user-all" data-uid="' + uid + '" style="margin-left:8px;font-size:11px;padding:2px 8px;">' + escapeHtml(_tr('tfa.admin.devices.btn_revoke_all_for_user', 'Revoke all for user')) + '</button></td></tr>';
                            first.forEach(function(r) { groupHtml += devRow(r); });
                            if (rest.length) {
                                groupHtml += '<tr class="tfa-dev-more-toggle-row"><td colspan="5" style="padding-left:20px;"><a href="#" class="tfa-dev-expand" data-target="' + groupId + '" style="color:#00a4dc;font-size:12px;">+ ' + rest.length + ' ' + escapeHtml(_tr('tfa.admin.common.more', 'more')) + '</a></td></tr>';
                                groupHtml += '<tbody id="' + groupId + '" style="display:none;">';
                                rest.forEach(function(r) { groupHtml += devRow(r); });
                                groupHtml += '</tbody>';
                            }
                        });
                        body.innerHTML = groupHtml;
                        body.querySelectorAll('.tfa-revoke-dev').forEach(function(b) {
                            b.addEventListener('click', function() {
                                if (!confirm(_tr('tfa.admin.devices.confirm_revoke_device', 'Revoke this device?'))) return;
                                apiDelete('TwoFactorAuth/Users/' + b.dataset.uid + '/Devices/' + b.dataset.id).then(loadAllDevices);
                            });
                        });
                        body.querySelectorAll('.tfa-revoke-user-all').forEach(function(b) {
                            b.addEventListener('click', function() {
                                if (!confirm(_tr('tfa.admin.devices.confirm_revoke_all', 'Revoke EVERY trusted browser for this user?'))) return;
                                // v2.5.0: stepUpFetch so the server can enforce a step-up gate.
                                stepUpFetch('TwoFactorAuth/Admin/Bulk', {
                                    method: 'POST',
                                    headers: getHeaders(),
                                    body: JSON.stringify({ action: 'revoke_trusted_browsers', userIds: [b.dataset.uid] }),
                                }).then(function(r) { if (r.ok) loadAllDevices(); });
                            });
                        });
                        body.querySelectorAll('.tfa-dev-expand').forEach(function(a) {
                            a.addEventListener('click', function(e) {
                                e.preventDefault();
                                var box = document.getElementById(a.dataset.target);
                                if (!box) return;
                                var open = box.style.display !== 'none';
                                box.style.display = open ? 'none' : '';
                                var collapseText = '− ' + _tr('tfa.admin.common.collapse', 'collapse');
                                a.textContent = open ? a.textContent.replace(collapseText, '+ ' + box.children.length + ' ' + _tr('tfa.admin.common.more', 'more')) : collapseText;
                            });
                        });
                    }).catch(function() {
                        page.querySelector('#devicesBody').innerHTML = '<tr><td colspan="6" class="tfa-empty">' + escapeHtml(_tr('tfa.admin.common.failed_to_load', 'Failed to load')) + '</td></tr>';
                    });
                }

                // ---- PAIRINGS ----
                function loadPairings() {
                    apiGet('TwoFactorAuth/Pairings').then(function(pairings) {
                        var body = page.querySelector('#pairingsBody');
                        if (!pairings || !pairings.length) { body.innerHTML = '<tr><td colspan="5" class="tfa-empty">' + escapeHtml(_tr('tfa.admin.pairings.empty', 'No pending pairings')) + '</td></tr>'; return; }
                        var tApprove = _tr('tfa.admin.pairings.btn_approve', 'Approve');
                        var tDeny = _tr('tfa.admin.pairings.btn_deny', 'Deny');
                        body.innerHTML = pairings.map(function(p) {
                            var code = p.code || p.Code;
                            var exp = new Date(p.expiresAt || p.ExpiresAt).toLocaleTimeString();
                            return '<tr><td>' + escapeHtml(p.username || p.Username) + '</td><td>' + escapeHtml(p.deviceName || p.DeviceName) + '</td><td style="font-family:monospace;font-weight:700;letter-spacing:2px;">' + code + '</td><td>' + exp + '</td>' +
                                '<td><button class="tfa-btn tfa-btn-success tfa-approve" data-code="' + code + '">' + escapeHtml(tApprove) + '</button> <button class="tfa-btn tfa-btn-danger tfa-deny" data-code="' + code + '">' + escapeHtml(tDeny) + '</button></td></tr>';
                        }).join('');
                        body.querySelectorAll('.tfa-approve').forEach(function(b) { b.addEventListener('click', function() { apiPost('TwoFactorAuth/Pairings/' + b.dataset.code + '/Approve').then(loadPairings); }); });
                        body.querySelectorAll('.tfa-deny').forEach(function(b) { b.addEventListener('click', function() { apiPost('TwoFactorAuth/Pairings/' + b.dataset.code + '/Deny').then(loadPairings); }); });
                    }).catch(function() { page.querySelector('#pairingsBody').innerHTML = '<tr><td colspan="5" class="tfa-empty">' + escapeHtml(_tr('tfa.admin.common.failed_to_load', 'Failed to load')) + '</td></tr>'; });
                }

                // ---- AUDIT ----
                var allAudit = [];
                var auditPage = 0;
                var AUDIT_PAGE_SIZE = 50;
                function loadAudit() {
                    apiGet('TwoFactorAuth/AuditLog?limit=1000').then(function(entries) {
                        allAudit = entries || [];
                        auditPage = 0;
                        renderAudit();
                    }).catch(function() { page.querySelector('#auditBody').innerHTML = '<tr><td colspan="6" class="tfa-empty">' + escapeHtml(_tr('tfa.admin.common.failed_to_load', 'Failed to load')) + '</td></tr>'; });
                }
                function renderAudit() {
                    var q = page.querySelector('#auditFilter').value.toLowerCase();
                    var filtered = q ? allAudit.filter(function(e) { return JSON.stringify(e).toLowerCase().indexOf(q) >= 0; }) : allAudit;
                    var totalPages = Math.max(1, Math.ceil(filtered.length / AUDIT_PAGE_SIZE));
                    if (auditPage >= totalPages) auditPage = totalPages - 1;
                    var slice = filtered.slice(auditPage * AUDIT_PAGE_SIZE, (auditPage + 1) * AUDIT_PAGE_SIZE);
                    var body = page.querySelector('#auditBody');
                    if (!slice.length) { body.innerHTML = '<tr><td colspan="6" class="tfa-empty">' + escapeHtml(_tr('tfa.admin.audit.no_matches', 'No matching entries')) + '</td></tr>'; }
                    else {
                        var resultColors = { 'Success':'on','Failed':'locked','Bypassed':'on','Locked':'locked','ChallengeIssued':'off' };
                        var resultNames = ['Success','Failed','Bypassed','Locked','ChallengeIssued'];
                        body.innerHTML = slice.map(function(e) {
                            var t = new Date(e.timestamp || e.Timestamp).toLocaleString();
                            var r = e.result !== undefined ? e.result : e.Result;
                            var rName = typeof r === 'number' ? (resultNames[r] || r) : r;
                            return '<tr><td style="font-size:12px;">' + t + '</td><td>' + escapeHtml(e.username || e.Username) + '</td><td style="font-family:monospace;font-size:12px;">' + escapeHtml(e.remoteIp || e.RemoteIp) + '</td><td>' + escapeHtml(e.deviceName || e.DeviceName) + '</td><td><span class="tfa-badge ' + (resultColors[rName] || 'off') + '">' + rName + '</span></td><td>' + escapeHtml(e.method || e.Method) + '</td></tr>';
                        }).join('');
                    }
                    page.querySelector('#auditPageInfo').textContent = _tr('tfa.admin.audit.page', 'Page') + ' ' + (auditPage + 1) + ' ' + _tr('tfa.admin.audit.of', 'of') + ' ' + totalPages + ' (' + filtered.length + ' ' + _tr('tfa.admin.audit.entries', 'entries') + ')';
                    page.querySelector('#auditPrev').disabled = auditPage === 0;
                    page.querySelector('#auditNext').disabled = auditPage >= totalPages - 1;
                }
                page.querySelector('#auditFilter').addEventListener('input', function() { auditPage = 0; renderAudit(); });
                // v1.4: users filter + bulk
                page.querySelector('#usersFilter').addEventListener('input', function() { renderUsers(); });
                page.querySelector('#usersSelectAll').addEventListener('change', function(ev) {
                    page.querySelectorAll('.tfa-user-select').forEach(function(c) { c.checked = ev.target.checked; });
                });
                page.querySelector('#usersBulkApply').addEventListener('click', function() {
                    var action = page.querySelector('#usersBulkAction').value;
                    if (!action) { alert(_tr('tfa.admin.users.alert_pick_action', 'Pick a bulk action first.')); return; }
                    var ids = Array.prototype.slice.call(page.querySelectorAll('.tfa-user-select:checked')).map(function(c){return c.dataset.uid;});
                    if (!ids.length) { alert(_tr('tfa.admin.users.alert_select_user', 'Select at least one user.')); return; }
                    if (!confirm(_tr('tfa.admin.users.confirm_apply_prefix', 'Apply') + ' "' + action + '" ' + _tr('tfa.admin.users.confirm_apply_middle', 'to') + ' ' + ids.length + ' ' + _tr('tfa.admin.users.confirm_apply_suffix', 'user(s)?'))) return;
                    // v2.5.0: route through stepUpFetch so the server can enforce a
                    // step-up gate on destructive actions (e.g. reset_2fa).
                    stepUpFetch('TwoFactorAuth/Admin/Bulk', {
                        method: 'POST',
                        headers: getHeaders(),
                        body: JSON.stringify({ action: action, userIds: ids }),
                    }).then(function(r) {
                        if (!r.ok) { r.json().catch(function(){return{};}).then(function(b){ alert(_tr('tfa.admin.users.action_failed', 'Action failed:') + ' ' + (b.message || r.status)); }); return; }
                        return r.json().catch(function(){return{};}).then(function(r) {
                            alert(_tr('tfa.admin.users.processed_prefix', 'Processed') + ' ' + (r.processed || 0) + ' ' + _tr('tfa.admin.users.processed_suffix', 'user(s).'));
                            loadUsers();
                        });
                    });
                });
                // v1.4: audit CSV export
                page.querySelector('#auditExportCsv').addEventListener('click', function() {
                    if (!allAudit.length) { alert(_tr('tfa.admin.audit.nothing_to_export', 'Nothing to export.')); return; }
                    var rows = [['Time','User','IP','DeviceId','DeviceName','Result','Method','Details']];
                    allAudit.forEach(function(e) {
                        rows.push([
                            (e.timestamp || e.Timestamp || ''),
                            (e.username || e.Username || ''),
                            (e.remoteIp || e.RemoteIp || ''),
                            (e.deviceId || e.DeviceId || ''),
                            (e.deviceName || e.DeviceName || ''),
                            String(e.result === undefined ? e.Result : e.result),
                            (e.method || e.Method || ''),
                            (e.details || e.Details || ''),
                        ]);
                    });
                    var csv = rows.map(function(r) { return r.map(function(v) { var s = String(v == null ? '' : v); if (/[",\n]/.test(s)) s = '"' + s.replace(/"/g, '""') + '"'; return s; }).join(','); }).join('\n');
                    var blob = new Blob([csv], { type: 'text/csv' });
                    var a = document.createElement('a');
                    a.href = URL.createObjectURL(blob);
                    a.download = 'jellyfin-2fa-audit.csv';
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                });
                // v1.4: webhook test — auto-save the form first because users
                // get confused when the test button uses last-saved settings
                // instead of what they just typed in.
                page.querySelector('#btnTestWebhook').addEventListener('click', function() {
                    var out = page.querySelector('#webhookTestResult');
                    var url = page.querySelector('#cfgWebhookUrl').value.trim();
                    if (!url) { out.style.color = '#f44336'; out.textContent = '✗ ' + _tr('tfa.admin.settings.webhook_need_url', 'Enter a Webhook URL first.'); return; }
                    out.style.color = '#888'; out.textContent = _tr('tfa.admin.settings.saving_sending', 'Saving + sending…');
                    // Persist current Webhook URL/Secret so the server-side
                    // dispatch uses what the admin sees in the input boxes.
                    ApiClient.getPluginConfiguration(pluginId).then(function(c) {
                        c.WebhookUrl = url;
                        c.WebhookSecret = page.querySelector('#cfgWebhookSecret').value.trim();
                        return ApiClient.updatePluginConfiguration(pluginId, c);
                    }).then(function() {
                        return apiPost('TwoFactorAuth/Admin/WebhookTest');
                    }).then(function(r) {
                        out.style.color = '#4caf50'; out.textContent = '✓ ' + (r.message || _tr('tfa.admin.common.sent', 'Sent'));
                    }).catch(function(e) { out.style.color = '#f44336'; out.textContent = '✗ ' + _tr('tfa.admin.settings.webhook_failed', 'Failed (check server log).'); });
                });
                page.querySelector('#auditPrev').addEventListener('click', function() { if (auditPage > 0) { auditPage--; renderAudit(); } });
                page.querySelector('#auditNext').addEventListener('click', function() { auditPage++; renderAudit(); });

                // ---- SETTINGS ----
                function loadSettings() {
                    ApiClient.getPluginConfiguration(pluginId).then(function(c) {
                        page.querySelector('#cfgEnabled').checked = !!c.Enabled;
                        // v2.4: EnforcementScope dropdown. Legacy RequireForAllUsers=true
                        // upgrades to scope=All. Default Optional for new configs.
                        var scope = c.EnforcementScope || (c.RequireForAllUsers ? 'All' : 'Optional');
                        page.querySelector('#cfgEnforceScope').value = scope;
                        page.querySelector('#cfgHibpEnabled').checked = !!c.HibpEnabled;
                        page.querySelector('#cfgEmailOtp').checked = !!c.EmailOtpEnabled;
                        page.querySelector('#cfgLanBypass').checked = !!c.LanBypassEnabled;
                        page.querySelector('#cfgLanCidrs').value = (c.LanBypassCidrs || []).join('\n');
                        page.querySelector('#cfgTrustFwd').checked = !!c.TrustForwardedFor;
                        page.querySelector('#cfgProxyCidrs').value = (c.TrustedProxyCidrs || []).join('\n');
                        page.querySelector('#cfgMaxFail').value = c.MaxFailedAttempts || 5;
                        page.querySelector('#cfgLockoutMin').value = c.LockoutDurationMinutes || 15;
                        page.querySelector('#cfgAuditMax').value = c.AuditLogMaxEntries || 1000;
                        page.querySelector('#cfgSmtpHost').value = c.SmtpHost || '';
                        page.querySelector('#cfgSmtpPort').value = c.SmtpPort || 587;
                        page.querySelector('#cfgSmtpSsl').checked = c.SmtpUseSsl !== false;
                        page.querySelector('#cfgSmtpUser').value = c.SmtpUsername || '';
                        page.querySelector('#cfgSmtpPass').value = c.SmtpPassword || '';
                        page.querySelector('#cfgSmtpFrom').value = c.SmtpFromAddress || '';
                        page.querySelector('#cfgSmtpFromName').value = c.SmtpFromName || '';
                        page.querySelector('#cfgNtfyUrl').value = c.NtfyUrl || '';
                        page.querySelector('#cfgNtfyTopic').value = c.NtfyTopic || '';
                        page.querySelector('#cfgGotifyUrl').value = c.GotifyUrl || '';
                        page.querySelector('#cfgGotifyToken').value = c.GotifyAppToken || '';
                        page.querySelector('#cfgEmails').value = (c.NotifyEmailAddresses || []).join('\n');
                        page.querySelector('#cfgIssuer').value = c.TotpIssuerName || 'Jellyfin';
                        // v1.4 fields
                        page.querySelector('#cfgWebhookUrl').value = c.WebhookUrl || '';
                        page.querySelector('#cfgWebhookSecret').value = c.WebhookSecret || '';
                        page.querySelector('#cfgGeoAsn').value = c.GeoIpAsnDbPath || '';
                        page.querySelector('#cfgGeoCountry').value = c.GeoIpCountryDbPath || '';
                        page.querySelector('#cfgRpId').value = c.WebAuthnRpId || '';
                        page.querySelector('#cfgRpOrigins').value = (c.WebAuthnOrigins || []).join('\n');
                        page.querySelector('#cfgPreVerify').value = c.PreVerifyWindowSeconds || 120;
                        page.querySelector('#cfgTrustTtl').value = c.TrustCookieTtlDays || 30;
                        page.querySelector('#cfgMaxSess').value = c.DefaultMaxConcurrentSessions || 0;
                        page.querySelector('#cfgDeadline').value = c.EnrollmentDeadline ? String(c.EnrollmentDeadline).slice(0,10) : '';
                        page.querySelector('#cfgHairpin').checked = !!c.NatHairpinSelfIpBypass;
                        // v2.0
                        page.querySelector('#cfgBanEnabled').checked = c.IpBanEnabled !== false;
                        page.querySelector('#cfgBanThreshold').value = c.IpBanFailureThreshold || 10;
                        page.querySelector('#cfgBanWindow').value = c.IpBanFailureWindowMinutes || 10;
                        page.querySelector('#cfgBanDuration').value = c.IpBanDurationHours || 24;
                        page.querySelector('#cfgBanExempt').value = (c.IpBanExemptCidrs || []).join('\n');
                        page.querySelector('#cfgTravelEnabled').checked = c.ImpossibleTravelEnabled !== false;
                        page.querySelector('#cfgTravelKmh').value = c.ImpossibleTravelMaxKmh || 900;
                        page.querySelector('#cfgGeoCity').value = c.GeoIpCityDbPath || '';
                        // v2.5.0 hardening fields
                        page.querySelector('#cfgRequire2faToDisable').checked = !!c.RequireTwoFactorToDisable;
                        page.querySelector('#cfgStepUpLevel').value = (c.StepUpLevel != null ? c.StepUpLevel : 0);
                        var indefEl = page.querySelector('#cfgAllowIndefiniteTrust');
                        if (indefEl) indefEl.checked = !!c.AllowIndefiniteTrust;
                        // [v2.5.7] (issue #48 feature, Gaarindor): per-button login-page visibility.
                        var hideTwoFaEl = page.querySelector('#cfgHideBuiltInTwoFactorButton');
                        if (hideTwoFaEl) hideTwoFaEl.checked = !!c.HideBuiltInTwoFactorButton;
                        var hidePasskeyEl = page.querySelector('#cfgHideBuiltInPasskeyButton');
                        if (hidePasskeyEl) hidePasskeyEl.checked = !!c.HideBuiltInPasskeyButton;
                        // [v2.5.6] (round-5 fix D): tri-state hardened-security
                        // control. Default to "Forced" when the server didn't
                        // emit the property (older config XML).
                        var ssSel = page.querySelector('#cfgSelfServiceStepUp');
                        if (ssSel) ssSel.value = c.SelfServiceStepUpMode || 'Forced';

                        // [v2.5.6] (round-5f): the "Force for all users"
                        // shortcut button + its wiring were removed by user
                        // request — the dropdown above is the single source
                        // of truth for the SelfServiceStepUpMode setting.
                        // v2.5.0 Localization: server-wide default language
                        var dlSel = page.querySelector('#cfgDefaultLanguage');
                        if (dlSel) dlSel.value = c.DefaultLanguage || 'en';
                    });
                }

                // v2.5.0: server-wide DefaultLanguage save handler. Posts the
                // chosen code to /TwoFactorAuth/Admin/DefaultLanguage which
                // validates against the supported-language allowlist before
                // persisting. The pre-login pages read the new value via
                // /TwoFactorAuth/public-config on next load.
                var saveDefLangBtn = page.querySelector('#btnSaveDefaultLang');
                if (saveDefLangBtn) {
                    saveDefLangBtn.addEventListener('click', function() {
                        var sel = page.querySelector('#cfgDefaultLanguage');
                        var status = page.querySelector('#defaultLangStatus');
                        if (!sel || !status) return;
                        var lang = sel.value || 'en';
                        status.style.color = '#888';
                        status.textContent = _tr('tfa.admin.common.saving', 'Saving…');
                        fetch(ApiClient.serverAddress() + '/TwoFactorAuth/Admin/DefaultLanguage', {
                            method: 'POST',
                            headers: getHeaders(),
                            body: JSON.stringify({ defaultLanguage: lang })
                        }).then(function(r) {
                            if (r.ok) {
                                status.style.color = '#4caf50';
                                status.textContent = '✓ ' + _tr('tfa.admin.settings.saved', 'Saved');
                            } else {
                                status.style.color = '#f44336';
                                status.textContent = '✗ ' + _tr('tfa.admin.common.save_failed', 'Save failed');
                            }
                            setTimeout(function() { status.style.color = ''; status.textContent = ''; }, 3500);
                        }).catch(function() {
                            status.style.color = '#f44336';
                            status.textContent = '✗ ' + _tr('tfa.admin.common.save_failed', 'Save failed');
                        });
                    });
                }
                page.querySelector('#btnTestSmtp').addEventListener('click', function() {
                    var to = page.querySelector('#cfgSmtpTestTo').value.trim();
                    var out = page.querySelector('#smtpTestResult');
                    if (!to) { out.style.color = '#f44336'; out.textContent = _tr('tfa.admin.settings.smtp_need_email', 'Enter an email address.'); return; }
                    out.style.color = '#888'; out.textContent = _tr('tfa.admin.settings.smtp_sending', 'Sending...');
                    apiPost('TwoFactorAuth/TestSmtp', { toAddress: to }).then(function(r) {
                        out.style.color = '#4caf50'; out.textContent = '✓ ' + (r.message || _tr('tfa.admin.common.sent', 'Sent'));
                    }).catch(function(r) {
                        out.style.color = '#f44336';
                        var sendFailed = _tr('tfa.admin.settings.smtp_send_failed', 'Send failed');
                        if (r && r.json) { r.json().then(function(b) { out.textContent = '✗ ' + (b.message || sendFailed); }).catch(function(){ out.textContent = '✗ ' + sendFailed; }); }
                        else { out.textContent = '✗ ' + sendFailed; }
                    });
                });
                page.querySelector('#btnSaveSettings').addEventListener('click', function() {
                    ApiClient.getPluginConfiguration(pluginId).then(function(c) {
                        c.Enabled = page.querySelector('#cfgEnabled').checked;
                        // v2.4: write EnforcementScope + keep legacy RequireForAllUsers
                        // synced so a downgrade to v2.3 still honors the "All" intent.
                        var scopeVal = page.querySelector('#cfgEnforceScope').value || 'Optional';
                        c.EnforcementScope = scopeVal;
                        c.RequireForAllUsers = (scopeVal === 'All');
                        c.HibpEnabled = page.querySelector('#cfgHibpEnabled').checked;
                        c.EmailOtpEnabled = page.querySelector('#cfgEmailOtp').checked;
                        c.LanBypassEnabled = page.querySelector('#cfgLanBypass').checked;
                        c.LanBypassCidrs = page.querySelector('#cfgLanCidrs').value.split('\n').map(function(s){return s.trim();}).filter(Boolean);
                        c.TrustForwardedFor = page.querySelector('#cfgTrustFwd').checked;
                        c.TrustedProxyCidrs = page.querySelector('#cfgProxyCidrs').value.split('\n').map(function(s){return s.trim();}).filter(Boolean);
                        c.MaxFailedAttempts = parseInt(page.querySelector('#cfgMaxFail').value) || 5;
                        c.LockoutDurationMinutes = parseInt(page.querySelector('#cfgLockoutMin').value) || 15;
                        c.AuditLogMaxEntries = parseInt(page.querySelector('#cfgAuditMax').value) || 1000;
                        c.SmtpHost = page.querySelector('#cfgSmtpHost').value.trim();
                        c.SmtpPort = parseInt(page.querySelector('#cfgSmtpPort').value) || 587;
                        c.SmtpUseSsl = page.querySelector('#cfgSmtpSsl').checked;
                        c.SmtpUsername = page.querySelector('#cfgSmtpUser').value;
                        c.SmtpPassword = page.querySelector('#cfgSmtpPass').value;
                        c.SmtpFromAddress = page.querySelector('#cfgSmtpFrom').value.trim();
                        c.SmtpFromName = page.querySelector('#cfgSmtpFromName').value.trim();
                        c.NtfyUrl = page.querySelector('#cfgNtfyUrl').value.trim();
                        c.NtfyTopic = page.querySelector('#cfgNtfyTopic').value.trim();
                        c.GotifyUrl = page.querySelector('#cfgGotifyUrl').value.trim();
                        c.GotifyAppToken = page.querySelector('#cfgGotifyToken').value.trim();
                        c.NotifyEmailAddresses = page.querySelector('#cfgEmails').value.split('\n').map(function(s){return s.trim();}).filter(Boolean);
                        c.TotpIssuerName = page.querySelector('#cfgIssuer').value.trim() || 'Jellyfin';
                        // v1.4 fields
                        c.WebhookUrl = page.querySelector('#cfgWebhookUrl').value.trim();
                        c.WebhookSecret = page.querySelector('#cfgWebhookSecret').value.trim();
                        c.GeoIpAsnDbPath = page.querySelector('#cfgGeoAsn').value.trim();
                        c.GeoIpCountryDbPath = page.querySelector('#cfgGeoCountry').value.trim();
                        c.WebAuthnRpId = page.querySelector('#cfgRpId').value.trim();
                        c.WebAuthnOrigins = page.querySelector('#cfgRpOrigins').value.split('\n').map(function(s){return s.trim();}).filter(Boolean);
                        c.PreVerifyWindowSeconds = Math.max(30, Math.min(900, parseInt(page.querySelector('#cfgPreVerify').value) || 120));
                        c.TrustCookieTtlDays = Math.max(1, Math.min(90, parseInt(page.querySelector('#cfgTrustTtl').value) || 30));
                        c.DefaultMaxConcurrentSessions = Math.max(0, Math.min(100, parseInt(page.querySelector('#cfgMaxSess').value) || 0));
                        var dl = page.querySelector('#cfgDeadline').value.trim();
                        c.EnrollmentDeadline = dl ? new Date(dl + 'T00:00:00Z').toISOString() : null;
                        c.NatHairpinSelfIpBypass = page.querySelector('#cfgHairpin').checked;
                        // v2.0
                        c.IpBanEnabled = page.querySelector('#cfgBanEnabled').checked;
                        c.IpBanFailureThreshold = Math.max(3, parseInt(page.querySelector('#cfgBanThreshold').value) || 10);
                        c.IpBanFailureWindowMinutes = Math.max(1, parseInt(page.querySelector('#cfgBanWindow').value) || 10);
                        c.IpBanDurationHours = Math.max(1, parseInt(page.querySelector('#cfgBanDuration').value) || 24);
                        c.IpBanExemptCidrs = page.querySelector('#cfgBanExempt').value.split('\n').map(function(s){return s.trim();}).filter(Boolean);
                        c.ImpossibleTravelEnabled = page.querySelector('#cfgTravelEnabled').checked;
                        c.ImpossibleTravelMaxKmh = Math.max(100, parseInt(page.querySelector('#cfgTravelKmh').value) || 900);
                        c.GeoIpCityDbPath = page.querySelector('#cfgGeoCity').value.trim();
                        // [v2.5.6] (round-5 fix D): persist the tri-state
                        // SelfServiceStepUpMode. Server defaults to "Forced"
                        // for safety when missing, so we explicitly send the
                        // selected value here.
                        var ssSel = page.querySelector('#cfgSelfServiceStepUp');
                        c.SelfServiceStepUpMode = ssSel ? (ssSel.value || 'Forced') : 'Forced';
                        // [v2.5.7] (issue #48 feature, Gaarindor): per-button login-page
                        // visibility. Persisted via the standard plugin config endpoint —
                        // no step-up gate needed because it's a purely cosmetic UI toggle.
                        var hideTwoFaSaveEl = page.querySelector('#cfgHideBuiltInTwoFactorButton');
                        c.HideBuiltInTwoFactorButton = hideTwoFaSaveEl ? hideTwoFaSaveEl.checked : false;
                        var hidePasskeySaveEl = page.querySelector('#cfgHideBuiltInPasskeyButton');
                        c.HideBuiltInPasskeyButton = hidePasskeySaveEl ? hidePasskeySaveEl.checked : false;
                        // v2.5.0: persist hardening toggles through the gated endpoint.
                        // Broader plugin config (other fields) still uses the built-in
                        // updatePluginConfiguration path. Store current config ref so the
                        // HardeningConfig POST can pass StepUpWindowSeconds through unchanged.
                        _currentConfig = c;
                        return ApiClient.updatePluginConfiguration(pluginId, c);
                    }).then(function() {
                        // v2.5.0: also persist hardening fields via the gated endpoint.
                        // This lets the server enforce a step-up gate on these specific fields.
                        var indefEl = page.querySelector('#cfgAllowIndefiniteTrust');
                        var hardening = {
                            RequireTwoFactorToDisable: page.querySelector('#cfgRequire2faToDisable').checked,
                            StepUpLevel: parseInt(page.querySelector('#cfgStepUpLevel').value, 10) || 0,
                            StepUpWindowSeconds: (_currentConfig && _currentConfig.StepUpWindowSeconds) || 300,
                            AllowIndefiniteTrust: indefEl ? indefEl.checked : false,
                        };
                        return stepUpFetch('TwoFactorAuth/Admin/HardeningConfig', {
                            method: 'POST',
                            headers: getHeaders(),
                            body: JSON.stringify(hardening),
                        }).then(function(r) {
                            var s = page.querySelector('#saveStatus');
                            if (r.ok || r.status === 200) {
                                s.style.color = '#4caf50';
                                s.textContent = '✓ ' + _tr('tfa.admin.settings.saved', 'Saved');
                            } else if (r.status === 403) {
                                s.style.color = '#ff9800';
                                s.textContent = '⚠ ' + _tr('tfa.admin.settings.saved_partial_stepup', 'Other settings saved; hardening config requires step-up verification.');
                            } else {
                                s.style.color = '#f44336';
                                s.textContent = '✓ ' + _tr('tfa.admin.settings.saved_with_hardening_error', 'Settings saved (hardening config endpoint error — check server log)');
                            }
                            setTimeout(function() { s.style.color = ''; s.textContent = ''; }, 3500);
                        });
                    });
                });
                var _currentConfig = null;

                // ---- v2.5.0: BACKUP & RESTORE ----
                document.getElementById('btnExportConfigOnly')?.addEventListener('click', async () => {
                    try {
                        const resp = await stepUpFetch(ApiClient.getUrl('TwoFactorAuth/Config/Export?includeSecrets=false'), { method: 'GET' });
                        if (!resp.ok) throw new Error('HTTP ' + resp.status);
                        const blob = await resp.blob();
                        const link = document.createElement('a');
                        link.href = URL.createObjectURL(blob);
                        link.download = '2fa-export-config-' + new Date().toISOString().replace(/[:.]/g, '-') + '.json';
                        document.body.appendChild(link); link.click(); link.remove();
                    } catch (e) { console.error('export failed', e); alert(_tr('tfa.admin.backup.export_failed', 'Export failed:') + ' ' + e.message); }
                });

                document.getElementById('btnExportFull')?.addEventListener('click', async () => {
                    const pass = prompt(_tr('tfa.admin.backup.prompt_passphrase', 'Set a passphrase (>=8 chars). You will need this exact passphrase to restore.'));
                    if (!pass || pass.length < 8) { alert(_tr('tfa.admin.backup.passphrase_too_short', 'Passphrase must be at least 8 characters')); return; }
                    try {
                        const url = ApiClient.getUrl('TwoFactorAuth/Config/Export?includeSecrets=true');
                        const resp = await stepUpFetch(url, {
                            method: 'GET',
                            headers: Object.assign({}, getHeaders(), { 'X-Export-Passphrase': pass })
                        });
                        if (!resp.ok) {
                            const txt = await resp.text();
                            throw new Error('HTTP ' + resp.status + ': ' + txt);
                        }
                        const blob = await resp.blob();
                        const link = document.createElement('a');
                        link.href = URL.createObjectURL(blob);
                        link.download = '2fa-export-full-' + new Date().toISOString().replace(/[:.]/g, '-') + '.json';
                        document.body.appendChild(link); link.click(); link.remove();
                    } catch (e) { alert(_tr('tfa.admin.backup.export_failed', 'Export failed:') + ' ' + e.message); }
                });

                document.getElementById('btnImportConfig')?.addEventListener('click', async () => {
                    const envText = document.getElementById('importEnvelope').value.trim();
                    const passphrase = document.getElementById('importPassphrase').value;
                    if (!envText) { alert(_tr('tfa.admin.backup.need_envelope', 'Paste an export envelope first')); return; }
                    const resultEl = document.getElementById('importResult');
                    resultEl.innerHTML = escapeHtml(_tr('tfa.admin.import_in_progress', 'Importing…'));
                    try {
                        const resp = await stepUpFetch(ApiClient.getUrl('TwoFactorAuth/Config/Import'), {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ envelope: envText, passphrase: passphrase || null })
                        });
                        const data = await resp.json().catch(() => ({}));
                        if (!resp.ok) {
                            resultEl.innerHTML = '<span style="color:#d9534f">' + escapeHtml(_tr('tfa.admin.import_failed', 'Failed:')) + ' ' + escapeHtml(data.message || _tr('tfa.admin.common.unknown_error', 'unknown error')) + '</span>';
                            return;
                        }
                        const warnings = data.warnings || [];
                        resultEl.innerHTML = '<span style="color:#5cb85c">' + escapeHtml(_tr('tfa.admin.import_applied', 'Import applied.')) + '</span>' +
                            (warnings.length > 0 ? '<ul style="margin:6px 0;padding-left:18px;color:#f0ad4e;">' +
                                warnings.map(w => '<li>' + escapeHtml(w) + '</li>').join('') + '</ul>' : '');
                    } catch (e) { resultEl.innerHTML = '<span style="color:#d9534f">' + escapeHtml(_tr('tfa.admin.import_network_error', 'Network error:')) + ' ' + escapeHtml(e.message) + '</span>'; }
                });

                // ---- v2.0 SSO PROVIDERS ----
                var ssoPresets = [];
                var ssoEditingId = null;
                function loadSso() {
                    var loadPresetsP = ssoPresets.length
                        ? Promise.resolve(ssoPresets)
                        : apiGet('TwoFactorAuth/Oidc/Presets').then(function(p) { ssoPresets = p || []; return ssoPresets; });
                    loadPresetsP.then(function() {
                        var sel = page.querySelector('#ssoPreset');
                        sel.innerHTML = ssoPresets.map(function(p) {
                            return '<option value="' + escapeHtml(p.key || p.Key) + '">' + escapeHtml(p.displayName || p.DisplayName) + '</option>';
                        }).join('');
                    });
                    apiGet('TwoFactorAuth/Oidc/Providers').then(function(rows) {
                        var body = page.querySelector('#ssoBody');
                        if (!rows || !rows.length) {
                            body.innerHTML = '<tr><td colspan="5" class="tfa-empty">' + escapeHtml(_tr('tfa.admin.sso.empty', 'No providers yet. Click "Add provider" to set one up.')) + '</td></tr>';
                            return;
                        }
                        var tEnabled = _tr('tfa.admin.sso.status_enabled', 'enabled');
                        var tDisabled = _tr('tfa.admin.sso.status_disabled', 'disabled');
                        var tEdit = _tr('tfa.admin.sso.btn_edit', 'Edit');
                        var tDelete = _tr('tfa.admin.sso.btn_delete', 'Delete');
                        var tIdPrefix = _tr('tfa.admin.sso.id_prefix', 'id:');
                        body.innerHTML = rows.map(function(p) {
                            var status = p.enabled ? '<span class="tfa-badge on">' + escapeHtml(tEnabled) + '</span>' : '<span class="tfa-badge off">' + escapeHtml(tDisabled) + '</span>';
                            return '<tr>'
                                + '<td><strong>' + escapeHtml(p.displayName) + '</strong><br/><span style="font-size:11px;color:#888;">' + escapeHtml(tIdPrefix) + ' ' + escapeHtml(p.id) + '</span></td>'
                                + '<td>' + escapeHtml(p.preset || '') + '</td>'
                                + '<td style="font-family:monospace;font-size:12px;">' + escapeHtml((p.clientId || '').slice(0,18)) + (p.clientId && p.clientId.length > 18 ? '…' : '') + '</td>'
                                + '<td>' + status + '</td>'
                                + '<td><button class="tfa-btn" data-sso-edit="' + escapeHtml(p.id) + '">' + escapeHtml(tEdit) + '</button> '
                                + '<button class="tfa-btn tfa-btn-danger" data-sso-del="' + escapeHtml(p.id) + '">' + escapeHtml(tDelete) + '</button></td>'
                                + '</tr>';
                        }).join('');
                        body.querySelectorAll('[data-sso-edit]').forEach(function(b) {
                            b.addEventListener('click', function() { editSsoProvider(b.dataset.ssoEdit, rows); });
                        });
                        body.querySelectorAll('[data-sso-del]').forEach(function(b) {
                            b.addEventListener('click', function() {
                                if (!confirm(_tr('tfa.admin.sso.confirm_delete', 'Delete this OIDC provider? Users linked to it will lose the link.'))) return;
                                apiDelete('TwoFactorAuth/Oidc/Providers/' + encodeURIComponent(b.dataset.ssoDel)).then(loadSso);
                            });
                        });
                    }).catch(function() {
                        page.querySelector('#ssoBody').innerHTML = '<tr><td colspan="5" class="tfa-empty">' + escapeHtml(_tr('tfa.admin.sso.load_failed', 'Failed to load providers')) + '</td></tr>';
                    });
                }
                function showSsoForm(prov) {
                    page.querySelector('#ssoFormSection').style.display = 'block';
                    page.querySelector('#ssoFormTitle').textContent = prov ? (_tr('tfa.admin.sso.form_title_edit', 'Edit') + ' ' + prov.displayName) : _tr('tfa.admin.sso.form_title_new', 'New provider');
                    page.querySelector('#ssoDisplay').value = prov ? (prov.displayName || '') : '';
                    page.querySelector('#ssoPreset').value = prov ? (prov.preset || 'generic') : 'generic';
                    page.querySelector('#ssoDiscovery').value = prov ? (prov.discoveryUrl || '') : '';
                    page.querySelector('#ssoClientId').value = prov ? (prov.clientId || '') : '';
                    page.querySelector('#ssoClientSecret').value = '';
                    page.querySelector('#ssoScopes').value = prov ? (prov.scopes || 'openid profile email') : 'openid profile email';
                    page.querySelector('#ssoUsernameClaim').value = prov ? (prov.usernameClaim || 'preferred_username') : 'preferred_username';
                    page.querySelector('#ssoAcr').value = prov ? (prov.acrValues || '') : '';
                    page.querySelector('#ssoAllowedGroups').value = prov ? (prov.allowedGroups || '') : '';
                    page.querySelector('#ssoAdminGroups').value = prov ? (prov.adminGroups || '') : '';
                    page.querySelector('#ssoAutoCreate').checked = prov ? !!prov.autoCreateUsers : false;
                    page.querySelector('#ssoRequireMfa').checked = prov ? !!prov.requireIdpMfa : false;
                    page.querySelector('#ssoBypass2fa').checked = prov ? prov.bypassPluginTwoFa !== false : true;
                    page.querySelector('#ssoEnabled').checked = prov ? prov.enabled !== false : true;
                    page.querySelector('#ssoForceHttps').checked = prov ? !!prov.forceHttps : false;
                    // [v2.5.7] (issue #54): per-provider SSRF-guard opt-out.
                    var allowPrivEl = page.querySelector('#ssoAllowPrivate');
                    if (allowPrivEl) allowPrivEl.checked = prov ? !!prov.allowPrivateNetworks : false;
                    ssoEditingId = prov ? prov.id : null;
                    updateSsoHint();
                }
                function editSsoProvider(id, rows) {
                    var prov = (rows || []).find(function(r) { return r.id === id; });
                    if (!prov) return;
                    showSsoForm(prov);
                }
                function updateSsoHint() {
                    var key = page.querySelector('#ssoPreset').value;
                    var hint = (ssoPresets || []).find(function(p) { return (p.key || p.Key) === key; });
                    var box = page.querySelector('#ssoSetupHint');
                    if (hint && (hint.setupHint || hint.SetupHint)) {
                        box.style.display = 'block';
                        box.textContent = hint.setupHint || hint.SetupHint;
                        // Pre-fill discovery / scopes / username claim if blank
                        var d = page.querySelector('#ssoDiscovery');
                        if (!d.value) d.value = hint.discoveryUrl || hint.DiscoveryUrl || '';
                        var s = page.querySelector('#ssoScopes');
                        if (!s.value) s.value = hint.scopes || hint.Scopes || 'openid profile email';
                        var u = page.querySelector('#ssoUsernameClaim');
                        if (!u.value) u.value = hint.usernameClaim || hint.UsernameClaim || 'preferred_username';
                    } else {
                        box.style.display = 'none';
                    }
                }
                page.querySelector('#ssoAddBtn').addEventListener('click', function() { showSsoForm(null); });
                page.querySelector('#ssoCancelBtn').addEventListener('click', function() {
                    page.querySelector('#ssoFormSection').style.display = 'none';
                });
                page.querySelector('#ssoPreset').addEventListener('change', updateSsoHint);
                page.querySelector('#ssoSaveBtn').addEventListener('click', function() {
                    var body = {
                        DisplayName: page.querySelector('#ssoDisplay').value.trim(),
                        Preset: page.querySelector('#ssoPreset').value,
                        DiscoveryUrl: page.querySelector('#ssoDiscovery').value.trim(),
                        ClientId: page.querySelector('#ssoClientId').value.trim(),
                        ClientSecret: page.querySelector('#ssoClientSecret').value,
                        Scopes: page.querySelector('#ssoScopes').value.trim() || 'openid profile email',
                        UsernameClaim: page.querySelector('#ssoUsernameClaim').value.trim() || 'preferred_username',
                        AcrValues: page.querySelector('#ssoAcr').value.trim(),
                        AllowedGroups: page.querySelector('#ssoAllowedGroups').value.trim(),
                        AdminGroups: page.querySelector('#ssoAdminGroups').value.trim(),
                        AutoCreateUsers: page.querySelector('#ssoAutoCreate').checked,
                        RequireIdpMfa: page.querySelector('#ssoRequireMfa').checked,
                        BypassPluginTwoFa: page.querySelector('#ssoBypass2fa').checked,
                        Enabled: page.querySelector('#ssoEnabled').checked,
                        ForceHttps: page.querySelector('#ssoForceHttps').checked,
                        // [v2.5.7] (issue #54): per-provider SSRF-guard opt-out.
                        AllowPrivateNetworks: (page.querySelector('#ssoAllowPrivate') || {}).checked === true,
                    };
                    if (!body.DisplayName) { alert(_tr('tfa.admin.sso.alert_display_required', 'Display name is required.')); return; }
                    if (!body.ClientId) { alert(_tr('tfa.admin.sso.alert_client_id_required', 'Client ID is required.')); return; }
                    var status = page.querySelector('#ssoSaveStatus');
                    status.style.color = '#888'; status.textContent = _tr('tfa.admin.common.saving', 'Saving…');
                    var p = ssoEditingId
                        ? fetch(ApiClient.serverAddress() + '/TwoFactorAuth/Oidc/Providers/' + encodeURIComponent(ssoEditingId),
                            { method: 'PUT', headers: getHeaders(), body: JSON.stringify(body) })
                        : fetch(ApiClient.serverAddress() + '/TwoFactorAuth/Oidc/Providers',
                            { method: 'POST', headers: getHeaders(), body: JSON.stringify(body) });
                    p.then(function(r) {
                        if (!r.ok) throw r;
                        status.style.color = '#4caf50'; status.textContent = '✓ ' + _tr('tfa.admin.settings.saved', 'Saved');
                        setTimeout(function() { status.textContent = ''; }, 2000);
                        page.querySelector('#ssoFormSection').style.display = 'none';
                        loadSso();
                    }).catch(function(err) {
                        status.style.color = '#f44336'; status.textContent = '✗ ' + _tr('tfa.admin.common.save_failed', 'Save failed');
                        if (err && err.text) { err.text().then(function(t) { console.error('[2FA] SSO save:', t); }); }
                    });
                });

                // ---- v2.0 IP BANS ----
                function loadBans() {
                    apiGet('TwoFactorAuth/IpBans').then(function(rows) {
                        var body = page.querySelector('#bansBody');
                        if (!rows || !rows.length) {
                            body.innerHTML = '<tr><td colspan="6" class="tfa-empty">' + escapeHtml(_tr('tfa.admin.no_active_bans', 'No active bans')) + '</td></tr>';
                            return;
                        }
                        var tUnban = _tr('tfa.admin.bans.btn_unban', 'Unban');
                        body.innerHTML = rows.map(function(b) {
                            return '<tr>'
                                + '<td style="font-family:monospace;">' + escapeHtml(b.ip || b.Ip) + '</td>'
                                + '<td style="font-size:12px;">' + new Date(b.bannedAt || b.BannedAt).toLocaleString() + '</td>'
                                + '<td style="font-size:12px;">' + new Date(b.expiresAt || b.ExpiresAt).toLocaleString() + '</td>'
                                + '<td>' + escapeHtml(b.source || b.Source || '') + '</td>'
                                + '<td>' + escapeHtml(b.note || b.Note || '') + '</td>'
                                + '<td><button class="tfa-btn tfa-btn-success" data-unban="' + escapeHtml(b.ip || b.Ip) + '">' + escapeHtml(tUnban) + '</button></td>'
                                + '</tr>';
                        }).join('');
                        body.querySelectorAll('[data-unban]').forEach(function(btn) {
                            btn.addEventListener('click', function() {
                                apiDelete('TwoFactorAuth/IpBans/' + encodeURIComponent(btn.dataset.unban)).then(loadBans);
                            });
                        });
                    }).catch(function() {
                        page.querySelector('#bansBody').innerHTML = '<tr><td colspan="6" class="tfa-empty">' + escapeHtml(_tr('tfa.admin.common.failed_to_load', 'Failed to load')) + '</td></tr>';
                    });
                }
                page.querySelector('#banAddBtn').addEventListener('click', function() {
                    var ip = page.querySelector('#banIp').value.trim();
                    if (!ip) { alert(_tr('tfa.admin.bans.alert_ip_required', 'IP is required.')); return; }
                    var body = {
                        Ip: ip,
                        Note: page.querySelector('#banNote').value.trim(),
                        Hours: parseInt(page.querySelector('#banHours').value) || 24,
                    };
                    apiPost('TwoFactorAuth/IpBans', body).then(function() {
                        page.querySelector('#banIp').value = '';
                        page.querySelector('#banNote').value = '';
                        loadBans();
                    });
                });

                // Overview is the default active tab, but the tab-click handler
                // only loads its data on click. Kick off renderOverview explicitly
                // so the dashboard populates on first paint without a tab toggle.
                page.addEventListener('pageshow', function() {
                    renderOverview();
                    loadUsers();
                    _initAdminLangPicker();
                });
                document.addEventListener('DOMContentLoaded', _initAdminLangPicker);

                // v2.5.0 externalize-fix: the script tag is fetched async, so by
                // the time the IIFE finishes parsing, the SPA's pageshow event has
                // already fired. The pageshow listener above only catches
                // subsequent re-entries. Kick off the initial render directly so
                // the Overview populates on first paint. Small setTimeout lets
                // ApiClient finish initializing its auth state before we hit
                // /Dashboard/Overview (otherwise the first call can race with
                // token rehydration and get an empty response).
                //
                // v2.5.3: gate the initial render on window.tfaI18n.ready so the
                // translation bundle is loaded BEFORE _tr() calls fire. Without
                // the gate, in non-English locales the bundle fetch races
                // renderOverview and "Top action:", "of", "users", etc. return
                // the English fallback because _bundle isn't populated yet. The
                // gate plus the data-i18n-key strip inside renderOverview fixes
                // both halves of the screenshot bug (English Top-action prose +
                // stuck "読み込み中..." for score breakdown / enrollment bars).
                // tfaI18n.ready always resolves (even on bundle fetch failure)
                // so this never hangs.
                setTimeout(function() {
                    var ready = (window.tfaI18n && window.tfaI18n.ready)
                        ? window.tfaI18n.ready
                        : Promise.resolve();
                    ready.then(function() {
                        renderOverview();
                        loadUsers();
                        _initAdminLangPicker();
                    });
                }, 100);
            })();
