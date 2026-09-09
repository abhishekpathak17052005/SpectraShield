(function () {
  'use strict';

  var API_BASE = 'http://localhost:8000';
  var DASHBOARD_BASE = 'http://localhost:5173';
  var DEBUG_LOGS = true;

  function debugLog(stage, meta) {
    if (!DEBUG_LOGS) return;
    try {
      console.log('[SpectraShield][ServiceWorker][' + stage + ']', meta || {});
    } catch (_) {}
  }

  debugLog('SERVICE_WORKER_READY', {
    startedAt: new Date().toISOString()
  });

  chrome.runtime.onInstalled.addListener(function (details) {
    debugLog('ON_INSTALLED', {
      reason: details && details.reason ? details.reason : 'unknown'
    });
  });

  function openOrFocusFrontendTab(targetUrl, callback) {
    if (typeof chrome === 'undefined' || !chrome.tabs) {
      if (callback) callback(null);
      return;
    }

    try {
      chrome.tabs.query({ url: ['*://localhost:5173/*', '*://127.0.0.1:5173/*'] }, function (tabs) {
        if (chrome.runtime.lastError || !tabs || tabs.length === 0) {
          chrome.tabs.create({ url: targetUrl, active: true }, function (newTab) {
            if (callback) callback(newTab ? newTab.id : null);
          });
        } else {
          var existingTab = tabs[0];
          chrome.tabs.update(existingTab.id, { url: targetUrl, active: true }, function (updatedTab) {
            if (chrome.windows && existingTab.windowId) {
              try {
                chrome.windows.update(existingTab.windowId, { focused: true });
              } catch (_) {}
            }
            if (callback) callback(existingTab.id);
          });
        }
      });
    } catch (_) {
      if (chrome.tabs.create) {
        chrome.tabs.create({ url: targetUrl, active: true }, function (newTab) {
          if (callback) callback(newTab ? newTab.id : null);
        });
      } else if (callback) {
        callback(null);
      }
    }
  }

  function openMailInvestigation(caseId, tabPromise) {
    if (!caseId) return;
    var targetUrl = DASHBOARD_BASE + '/mail-intelligence/' + encodeURIComponent(caseId);
    if (tabPromise) {
      tabPromise.then(function (tabId) {
        if (tabId && typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.update) {
          chrome.tabs.update(tabId, { url: targetUrl, active: true }, function (updatedTab) {
            if (chrome.runtime.lastError || !updatedTab) {
              openOrFocusFrontendTab(targetUrl);
            }
          });
        } else {
          openOrFocusFrontendTab(targetUrl);
        }
      }).catch(function () {
        openOrFocusFrontendTab(targetUrl);
      });
    } else {
      openOrFocusFrontendTab(targetUrl);
    }
  }

  function createPendingInvestigationTab(subject, senderEmail, platform, rawText) {
    return new Promise(function (resolve) {
      try {
        var pendingUrl = DASHBOARD_BASE + '/mail-intelligence?analyzing=true' +
          '&subject=' + encodeURIComponent(subject || 'Active Inbound Email') +
          '&sender_email=' + encodeURIComponent(senderEmail || '') +
          '&platform=' + encodeURIComponent(platform || 'gmail') +
          (rawText ? '&raw=' + encodeURIComponent(rawText.slice(0, 500)) : '');

        openOrFocusFrontendTab(pendingUrl, function (tabId) {
          resolve(tabId);
        });
      } catch (_) {
        resolve(null);
      }
    });
  }

  chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
    if (message && message.type === 'SPECTRASHIELD_PING') {
      debugLog('PING_IN', {
        fromTabId: sender && sender.tab ? sender.tab.id : null,
        url: sender && sender.url ? sender.url : null
      });
      sendResponse({ ok: true, pong: true, ts: Date.now() });
      return;
    }

    if (message && message.type === 'OPEN_MAIL_INVESTIGATION') {
      var caseId = message.caseId || message.case_id;
      var targetUrl = message.url || (caseId
        ? DASHBOARD_BASE + '/mail-intelligence/' + encodeURIComponent(caseId)
        : DASHBOARD_BASE + '/mail-intelligence');

      openOrFocusFrontendTab(targetUrl, function (tabId) {
        sendResponse({ ok: true, tabId: tabId });
      });
      return true;
    }

    // ─── EMAIL FORENSIC INTELLIGENCE FLOW ────────────────────────────────────
    if (message && message.type === 'SPECTRASHIELD_ANALYZE_EMAIL') {
      var emailPayload = message.payload || {};
      var startedAtEmail = Date.now();
      debugLog('EMAIL_ANALYZE_IN', {
        subject: emailPayload.subject || null,
        platform: emailPayload.platform || 'gmail',
        urlCount: Array.isArray(emailPayload.urls) ? emailPayload.urls.length : 0
      });

      var tabPromise = null;
      if (message.openDashboard) {
        tabPromise = createPendingInvestigationTab(
          emailPayload.subject,
          (emailPayload.sender && emailPayload.sender.email) || '',
          emailPayload.platform || 'gmail',
          emailPayload.body || emailPayload.email_text || ''
        );
      }

      fetch(API_BASE + '/api/forensics/analyze-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(emailPayload)
      })
      .then(function (res) {
        if (!res.ok) throw new Error('SpectraShield backend returned ' + res.status);
        return res.json();
      })
      .then(function (data) {
        debugLog('EMAIL_ANALYZE_SUCCESS', {
          caseId: data.case_id,
          finalRisk: data.final_risk,
          verdict: data.verdict
        });

        if (message.openDashboard && data.case_id) {
          openMailInvestigation(data.case_id, tabPromise);
        }

        sendResponse({ ok: true, data: data, case_id: data.case_id });
      })
      .catch(function (err) {
        debugLog('EMAIL_ANALYZE_ERROR', { error: err.message });
        sendResponse({ ok: false, error: err && err.message ? err.message : 'SpectraShield backend unavailable.' });
      });

      return true; // asynchronous sendResponse
    }

    // ─── DIRECT ACTIVE GMAIL TAB SCAN REQUEST ────────────────────────────────
    if (message && message.type === 'SCAN_ACTIVE_GMAIL_TAB') {
      debugLog('SCAN_ACTIVE_GMAIL_TAB_IN');
      if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
        chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
          var activeTab = tabs && tabs[0];
          var isGmail = activeTab && activeTab.url && activeTab.url.includes('mail.google.com');

          function triggerExtraction(tabId) {
            chrome.tabs.sendMessage(tabId, { type: 'EXTRACT_ACTIVE_EMAIL' }, function (extractRes) {
              var lastErr = chrome.runtime.lastError;
              if (lastErr || !extractRes || !extractRes.ok || !extractRes.payload) {
                sendResponse({
                  ok: false,
                  error: extractRes && extractRes.error ? extractRes.error : 'Could not read email from tab. Please ensure an email is open in Gmail.'
                });
                return;
              }

              var tabPromise = null;
              if (message.openDashboard) {
                tabPromise = createPendingInvestigationTab(
                  extractRes.payload.subject,
                  (extractRes.payload.sender && extractRes.payload.sender.email) || '',
                  extractRes.payload.platform || 'gmail',
                  extractRes.payload.body || ''
                );
              }

              // Send to backend pipeline
              fetch(API_BASE + '/api/forensics/analyze-email', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(extractRes.payload)
              })
              .then(function (r) {
                if (!r.ok) throw new Error('Backend returned status ' + r.status);
                return r.json();
              })
              .then(function (analysisData) {
                if (message.openDashboard && analysisData.case_id) {
                  openMailInvestigation(analysisData.case_id, tabPromise);
                }
                sendResponse({ ok: true, data: analysisData, case_id: analysisData.case_id });
              })
              .catch(function (err) {
                sendResponse({ ok: false, error: err.message });
              });
            });
          }

          if (isGmail) {
            triggerExtraction(activeTab.id);
          } else {
            chrome.tabs.query({ url: '*://mail.google.com/*' }, function (gmailTabs) {
              if (gmailTabs && gmailTabs.length > 0) {
                triggerExtraction(gmailTabs[0].id);
              } else {
                sendResponse({ ok: false, error: 'No Gmail tab open. Please open Gmail and select an email.' });
              }
            });
          }
        });
      } else {
        sendResponse({ ok: false, error: 'Chrome tabs API unavailable.' });
      }
      return true;
    }

    if (!message || message.type !== 'SPECTRASHIELD_LINKEDIN_ANALYZE') {
      return;
    }

    var payload = message.payload || {};
    var startedAt = Date.now();

    debugLog('REQUEST_IN', {
      fromTabId: sender && sender.tab ? sender.tab.id : null,
      platform: payload.platform || null,
      threadId: payload.thread_id || null,
      textLength: (payload.email_text || '').length,
      linkCount: Array.isArray(payload.urls) ? payload.urls.length : 0
    });

    fetch(API_BASE + '/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }).then(function (res) {
      debugLog('BACKEND_STATUS', {
        status: res.status,
        ok: res.ok,
        latencyMs: Date.now() - startedAt
      });
      if (!res.ok) throw new Error('Backend returned ' + res.status);
      return res.json();
    }).then(function (data) {
      debugLog('RESPONSE_OUT', {
        finalRisk: typeof data.final_risk === 'number' ? data.final_risk : null,
        level: data.level || data.verdict || null,
        cached: !!data.cached,
        latencyMs: Date.now() - startedAt
      });
      sendResponse({ ok: true, data: data });
    }).catch(function (err) {
      debugLog('ERROR', {
        message: (err && err.message) ? err.message : 'Unknown error',
        latencyMs: Date.now() - startedAt
      });
      sendResponse({ ok: false, error: (err && err.message) ? err.message : 'Unknown error' });
    });

    return true;
  });
})();
