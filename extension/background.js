(function () {
  'use strict';

  var API_BASE = 'http://localhost:8000';
  var DEBUG_LOGS = true;

  function debugLog(stage, meta) {
    if (!DEBUG_LOGS) return;
    try {
      console.log('[SpectraShield][LinkedInBridge][' + stage + ']', meta || {});
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

  chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
    if (message && message.type === 'SPECTRASHIELD_PING') {
      debugLog('PING_IN', {
        fromTabId: sender && sender.tab ? sender.tab.id : null,
        url: sender && sender.url ? sender.url : null
      });
      sendResponse({ ok: true, pong: true, ts: Date.now() });
      return;
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
