/**
 * SpectraShield Gmail content script.
 * - Extracts subject/sender only (privacy-first), calls backend with private_mode: true.
 * - Injects risk badges after each subject. Uses a cache so badges persist and reattach when Gmail recycles DOM on scroll.
 */

(function () {
  'use strict';

  var API_BASE = 'http://localhost:8000';
  var BADGE_ATTR = 'data-spectrashield-id';
  var processed = new Set();
  var cache = {};
  var debounceMs = 500;
  var scrollDebounceMs = 350;
  var debounceTimer;
  var scrollTimer;
  var openMailDebounceMs = 450;
  var openMailTimer;
  var threadMeta = {};
  var openMailCache = {};
  var openMailInFlight = new Set();
  var openMailSignatureByThread = {};
  var linkedinProcessedMessages = new WeakSet();
  var linkedinThreadMessageCache = {};
  var linkedinAssetCache = {};
  var linkedinWarnedNoThreadId = false;
  var linkedinLastScanLogAt = 0;
  var linkedinBackgroundObserverStarted = false;
  var linkedinProcessedKeys = new Set();
  var linkedinSignatureByKey = {};
  var linkedinInFlightByKey = {};

  var LINKEDIN_MESSAGE_CONTAINER_SELECTORS = [
    '.msg-s-message-list',
    '.msg-s-message-list-content',
    '[data-view-name="messages-list"]',
    '.msg-conversation-listitem__event-list'
  ];

  var LINKEDIN_BUBBLE_SELECTORS = [
    'div.msg-s-event-listitem__body',
    'li.msg-s-message-list__event',
    '.msg-s-event-listitem'
  ];

  function stableHash(input) {
    var text = String(input || '');
    var hash = 0;
    for (var i = 0; i < text.length; i++) {
      hash = ((hash << 5) - hash) + text.charCodeAt(i);
      hash |= 0;
    }
    return String(Math.abs(hash));
  }

  // ---- Link-level (zero-touch) scanning ----
  var linkProcessed = new WeakSet();
  var urlCache = {}; // href -> { score, verdict, topReason, vtNote, ts }
  var urlCacheTtlMs = 10 * 60 * 1000;

  function scoreToLevel(score) {
    if (score >= 71) return 'malicious';
    if (score >= 31) return 'suspicious';
    return 'safe';
  }

  function topReasonFromIntel(intel) {
    try {
      var ev = intel && intel.evidence;
      if (ev && ev.length > 0) return ev[0].description || ev[0].label || '';
    } catch (_) {}
    return '';
  }

  function analyzeUrl(href) {
    var now = Date.now();
    var cached = urlCache[href];
    if (cached && (now - cached.ts) < urlCacheTtlMs) return Promise.resolve(cached);
    return fetch(API_BASE + '/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email_text: '',
        email_header: null,
        url: href,
        urls: [],
        sender_email: null,
        private_mode: true
      })
    }).then(function (res) {
      if (!res.ok) throw new Error(res.status);
      return res.json();
    }).then(function (data) {
      var intel = data.url_intelligence || null;
      var score = typeof data.final_score === 'number' ? data.final_score :
        (intel && typeof intel.score === 'number' ? intel.score :
          (data.breakdown && typeof data.breakdown.url_score === 'number' ? data.breakdown.url_score : 0));
      var verdict = intel && intel.verdict ? intel.verdict : (score >= 71 ? 'Malicious' : score >= 31 ? 'Suspicious' : 'Safe');
      var topReason = topReasonFromIntel(intel) || (data.reasoning_summary || '');
      var vtNote = '';
      try {
        if (intel && Array.isArray(intel.evidence)) {
          for (var i = 0; i < intel.evidence.length; i++) {
            var ev = intel.evidence[i];
            if (ev && ev.type === 'reputation' && ev.label && ev.label.indexOf('VirusTotal') !== -1) {
              vtNote = ev.description || ev.label;
              break;
            }
          }
        }
      } catch (_) {}
      var out = { score: Math.round(score || 0), verdict: verdict, topReason: topReason, vtNote: vtNote, ts: Date.now() };
      urlCache[href] = out;
      return out;
    });
  }

  function ensureLinkBadge(a, analysis) {
    // avoid breaking layout: insert small inline badge after the <a>
    if (!a || !a.parentNode) return;
    if (a.nextSibling && a.nextSibling.classList && a.nextSibling.classList.contains('spectrashield-link-badge')) return;

    var badge = document.createElement('span');
    badge.className = 'spectrashield-link-badge ' + scoreToLevel(analysis.score);
    badge.textContent = '🛡️';
    badge.setAttribute('aria-label', 'SpectraShield link risk badge');

    badge.addEventListener('mouseenter', function () {
      var tt = document.createElement('div');
      tt.className = 'spectrashield-link-tooltip';
      var status = analysis.verdict || (analysis.score >= 71 ? 'Malicious' : analysis.score >= 31 ? 'Suspicious' : 'Safe');
      var reason = analysis.topReason || 'No strong signals detected.';
      var vt = analysis.vtNote || 'VirusTotal: No verdict / not queried.';
      tt.innerHTML =
        '<div class="row"><div class="label">Status</div><div class="value">' + status + '</div></div>' +
        '<div class="row"><div class="label">Risk Score</div><div class="value">' + analysis.score + '%</div></div>' +
        '<div class="reason"><span class="label">Top Reason:</span> ' + reason + '</div>' +
        '<div class="reason"><span class="label">VirusTotal:</span> ' + vt + '</div>';
      document.body.appendChild(tt);
      var r = badge.getBoundingClientRect();
      tt.style.left = (r.left + r.width / 2) + 'px';
      tt.style.top = (r.top - 10) + 'px';
      tt.style.transform = 'translate(-50%, -100%)';
      badge._linktt = tt;
    });
    badge.addEventListener('mouseleave', function () {
      if (badge._linktt) { badge._linktt.remove(); badge._linktt = null; }
    });

    a.parentNode.insertBefore(badge, a.nextSibling);
  }

  function scanLinks(root) {
    var container = root || document;
    var targets = container.querySelectorAll('a[href]');
    for (var i = 0; i < targets.length; i++) {
      var a = targets[i];
      if (linkProcessed.has(a)) continue;
      var href = a.getAttribute('href') || '';
      if (!href) continue;
      if (/^(mailto:|javascript:|#)/i.test(href)) continue;
      if (!/^https?:\/\//i.test(href)) continue;

      linkProcessed.add(a);
      (function (anchor, u) {
        analyzeUrl(u).then(function (analysis) {
          ensureLinkBadge(anchor, analysis);
        }).catch(function () { /* ignore */ });
      })(a, href);
    }
  }

  // Scan typical email body containers (Gmail .a3s, Outlook .BodyFragment)
  function scanEmailBody(root) {
    var container = root || document;
    var bodies = container.querySelectorAll('.a3s, .BodyFragment');
    if (!bodies.length) {
      // Fallback: scan links in the whole document
      scanLinks(container);
      return;
    }
    for (var i = 0; i < bodies.length; i++) {
      scanLinks(bodies[i]);
    }
  }

  function getRowId(row) {
    var id = row.getAttribute('data-message-id') ||
      row.getAttribute('data-legacy-message-id') ||
      row.getAttribute('data-thread-id') ||
      (row.querySelector('[data-thread-id]') && row.querySelector('[data-thread-id]').getAttribute('data-thread-id')) ||
      row.getAttribute('data-id');
    if (id) return id;
    var sub = getSubject(row);
    var sender = getSender(row);
    if (sub && sub.text) return 'r-' + (sub.text.slice(0, 80) + (sender || '')).replace(/\s/g, '');
    return null;
  }

  function getSubject(row) {
    var sel = [
      'span.bog',
      '.bog span',
      'span[data-thread-id]',
      '.y2',
      '.y6 span',
      '[role="link"] span',
      'span[data-tooltip]'
    ];
    for (var i = 0; i < sel.length; i++) {
      var el = row.querySelector(sel[i]);
      if (el && el.textContent) {
        var t = el.textContent.trim();
        if (t.length > 0 && t.length < 500) return { element: el, text: t };
      }
    }
    return null;
  }

  function getSender(row) {
    var sel = [
      'span[email]',
      'span.yW span[email]',
      '.yW [email]',
      '.yP',
      'td.yX span',
      '.xY span'
    ];
    for (var i = 0; i < sel.length; i++) {
      var el = row.querySelector(sel[i]);
      if (el) {
        var email = el.getAttribute('email') || el.textContent.trim();
        if (email) return email;
      }
    }
    return '';
  }

  function getSnippet(row) {
    var el = row.querySelector('.y2') || row.querySelector('[class*="snippet"]');
    return el ? el.textContent.trim().slice(0, 200) : '';
  }

  /** Extract all http(s) URLs from text. */
  function extractUrlsFromText(text) {
    if (!text || typeof text !== 'string') return [];
    var matches = text.match(/https?:\/\/[^\s\]\)\"\'<>]+/ig);
    if (!matches) return [];
    var urls = [];
    for (var i = 0; i < matches.length; i++) {
      var clean = matches[i].replace(/[\]\)\"\'>]+$/, '');
      if (urls.indexOf(clean) === -1) urls.push(clean);
    }
    return urls;
  }

  /** Get all URLs from row: link hrefs (preferred) or from subject + snippet text. */
  function getAllUrlsFromRow(row, subjectText, snippetText) {
    var urls = [];
    var links = row.querySelectorAll('a[href^="http"]');
    for (var i = 0; i < links.length; i++) {
      var href = links[i].getAttribute('href');
      if (href) {
        var clean = href.split(/[\s\]\)\"\'>]/)[0];
        if (clean && urls.indexOf(clean) === -1) urls.push(clean);
      }
    }
    var combined = [subjectText, snippetText].filter(Boolean).join(' ');
    var textUrls = extractUrlsFromText(combined);
    for (var j = 0; j < textUrls.length; j++) {
      if (urls.indexOf(textUrls[j]) === -1) urls.push(textUrls[j]);
    }
    return urls;
  }

  function getRows() {
    return document.querySelectorAll('tr.zA, tr[role="row"], div[data-message-id]');
  }

  function sanitizeInlineUrl(u) {
    if (!u) return '';
    return u.split(/[\s\]\)\"\'>]/)[0];
  }

  function getCurrentOpenThreadId(openBody) {
    var fromHash = null;
    var hash = window.location.hash || '';
    var m = hash.match(/\/(FM[a-zA-Z0-9_-]+)/);
    if (m && m[1]) fromHash = m[1];

    var container = openBody ? openBody.closest('[data-thread-id]') : null;
    var fromDom = container && container.getAttribute ? container.getAttribute('data-thread-id') : null;

    if (fromDom) return fromDom;
    if (fromHash) return fromHash;

    var h = document.querySelector('h2.hP');
    var subjectText = h && h.textContent ? h.textContent.trim() : '';
    if (subjectText) {
      var keys = Object.keys(threadMeta);
      for (var i = 0; i < keys.length; i++) {
        var id = keys[i];
        var info = threadMeta[id];
        if (info && info.subject === subjectText) return id;
      }
    }

    if (subjectText) return 'open-' + subjectText.slice(0, 100).replace(/\s+/g, '-').toLowerCase();
    return null;
  }

  function ensureOpenSubjectBadge(subjectEl, threadId) {
    if (!subjectEl || !threadId) return null;
    var existing = subjectEl.parentNode && subjectEl.parentNode.querySelector('.spectrashield-open-badge[' + BADGE_ATTR + '="open-' + threadId + '"]');
    if (existing) return existing;

    var badge = document.createElement('span');
    badge.className = 'spectrashield-badge spectrashield-open-badge suspicious';
    badge.setAttribute(BADGE_ATTR, 'open-' + threadId);
    badge.style.marginLeft = '8px';
    badge.style.padding = '0 8px';
    badge.style.width = 'auto';
    badge.style.fontSize = '11px';
    badge.style.fontWeight = '600';
    badge.style.borderRadius = '999px';
    badge.style.lineHeight = '20px';
    badge.textContent = 'Scanning...';
    badge.title = 'Scanning email body and links...';

    badge.addEventListener('mouseenter', function () {
      var info = badge._openInfo;
      if (!info) return;
      var tt = document.createElement('div');
      tt.className = 'spectrashield-link-tooltip';
      var logic = info.logicFlags && info.logicFlags.length ? info.logicFlags.join(', ') : 'None';
      var brand = info.brandMatch || 'None';
      var rep = (typeof info.vtFlagged === 'number' ? info.vtFlagged : 0) + '/' +
        (typeof info.vtTotal === 'number' ? info.vtTotal : 70) + ' engines flagged';
      tt.innerHTML =
        '<div class="row"><div class="label">Unified Score</div><div class="value">' + info.score + '%</div></div>' +
        '<div class="row"><div class="label">Brand Match</div><div class="value">' + brand + '</div></div>' +
        '<div class="row"><div class="label">Logic Flags</div><div class="value">' + logic + '</div></div>' +
        '<div class="row"><div class="label">Global Reputation</div><div class="value">' + rep + '</div></div>' +
        '<div class="reason"><span class="label">Reason:</span> ' + (info.reason || 'No additional details available.') + '</div>';
      document.body.appendChild(tt);
      var r = badge.getBoundingClientRect();
      tt.style.left = (r.left + r.width / 2) + 'px';
      tt.style.top = (r.top - 10) + 'px';
      tt.style.transform = 'translate(-50%, -100%)';
      badge._openTt = tt;
    });

    badge.addEventListener('mouseleave', function () {
      if (badge._openTt) {
        badge._openTt.remove();
        badge._openTt = null;
      }
    });

    badge.addEventListener('click', function (e) {
      e.stopPropagation();
      var context = badge._openContext || (openMailCache[threadId] && openMailCache[threadId].context);
      openSpectraShieldAnalysis(context);
    });

    subjectEl.after(badge);
    return badge;
  }

  function applyOpenBadgeState(badge, level, score, reason, breakdown) {
    if (!badge) return;
    badge.classList.remove('high', 'suspicious', 'safe');
    badge.classList.add(level);

    badge.textContent = 'Risk Score ' + score + '%';
    badge.title = (reason || 'No additional details available.') + ' (Score: ' + score + '%)';
    badge._openInfo = {
      score: score,
      reason: reason,
      brandMatch: breakdown && breakdown.brandMatch ? breakdown.brandMatch : 'None',
      logicFlags: breakdown && breakdown.logicFlags ? breakdown.logicFlags : [],
      vtFlagged: breakdown && typeof breakdown.vtFlagged === 'number' ? breakdown.vtFlagged : 0,
      vtTotal: breakdown && typeof breakdown.vtTotal === 'number' ? breakdown.vtTotal : 70
    };
  }

  function gatherOpenMailData(openBody) {
    if (!openBody) return null;

    var subjectEl = document.querySelector('h2.hP');
    var subject = subjectEl && subjectEl.textContent ? subjectEl.textContent.trim() : '';

    var senderEl = document.querySelector('.gD[email], span[email], .go');
    var sender = senderEl ? (senderEl.getAttribute('email') || senderEl.textContent || '').trim() : '';

    var bodyText = (openBody.innerText || '').trim();
    var links = openBody.querySelectorAll('a[href]');
    var urls = [];
    for (var i = 0; i < links.length; i++) {
      var href = links[i].getAttribute('href');
      if (!href || !/^https?:\/\//i.test(href)) continue;
      var clean = sanitizeInlineUrl(href);
      if (clean && urls.indexOf(clean) === -1) urls.push(clean);
    }

    var textUrls = extractUrlsFromText(bodyText);
    for (var j = 0; j < textUrls.length; j++) {
      if (urls.indexOf(textUrls[j]) === -1) urls.push(textUrls[j]);
    }

    return {
      subjectEl: subjectEl,
      subject: subject,
      sender: sender,
      bodyText: bodyText,
      urls: urls
    };
  }

  function scanOpenedMail() {
    var openBody = document.querySelector('.a3s');
    var openHeader = document.querySelector('.ha');
    if (!openBody && !openHeader) return;
    if (!openBody) return;

    var data = gatherOpenMailData(openBody);
    if (!data || !data.subjectEl) return;

    // Body must be fully loaded enough before scanning.
    if (!data.bodyText && data.urls.length === 0) return;
    if (data.bodyText.length < 20 && data.urls.length === 0) return;

    var threadId = getCurrentOpenThreadId(openBody);
    if (!threadId) return;

    var badge = ensureOpenSubjectBadge(data.subjectEl, threadId);
    if (!badge) return;

    var openContext = {
      emailText: [data.subject, data.bodyText].filter(Boolean).join('\n\n').slice(0, 25000),
      senderEmail: data.sender || '',
      urls: data.urls || []
    };
    badge._openContext = openContext;

    var signature = [data.subject, data.bodyText.length, data.urls.length].join('|');
    if (openMailSignatureByThread[threadId] === signature && openMailCache[threadId]) {
      var cached = openMailCache[threadId];
      if (cached.context) badge._openContext = cached.context;
      applyOpenBadgeState(badge, cached.level, cached.score, cached.reason, cached.breakdown);
      return;
    }

    if (openMailInFlight.has(threadId)) return;
    openMailInFlight.add(threadId);
    openMailSignatureByThread[threadId] = signature;

    badge.textContent = 'Scanning...';
    badge.classList.remove('high', 'safe');
    badge.classList.add('suspicious');
    badge.title = 'Scanning email body and links...';

    analyzeEmail(
      openContext.emailText,
      data.sender,
      data.urls,
      {
        thread_id: threadId,
        opened_mail_body: data.bodyText.slice(0, 25000),
        opened_mail_urls: data.urls
      }
    ).then(function (resp) {
      var openSummary = resp && resp.open_mail_summary ? resp.open_mail_summary : {};
      var riskBreakdown = resp && resp.risk_breakdown ? resp.risk_breakdown : {};
      var scoreRaw = typeof resp.mail_severity_score === 'number' ? resp.mail_severity_score :
        (typeof resp.unified_severity_score === 'number' ? resp.unified_severity_score :
          (typeof resp.final_risk === 'number' ? resp.final_risk : 0));
      var score = Math.round(scoreRaw || 0);
      var level = riskLevel(score);
      var reason = openSummary.reason || resp.reasoning_summary || 'No strong signals detected in opened email body.';
      var maliciousCount = typeof openSummary.malicious_links === 'number' ? openSummary.malicious_links : 0;
      var suspiciousCount = typeof openSummary.suspicious_links === 'number' ? openSummary.suspicious_links : 0;
      if (!openSummary.reason && (maliciousCount > 0 || suspiciousCount > 0)) {
        reason = 'Found ' + maliciousCount + ' phishing and ' + suspiciousCount + ' suspicious links in body.';
      }

      var tooltipBreakdown = {
        brandMatch: riskBreakdown.brand_match || 'None',
        logicFlags: riskBreakdown.logic_flags || [],
        vtFlagged: riskBreakdown.global_reputation && typeof riskBreakdown.global_reputation.flagged === 'number'
          ? riskBreakdown.global_reputation.flagged : 0,
        vtTotal: riskBreakdown.global_reputation && typeof riskBreakdown.global_reputation.total === 'number'
          ? riskBreakdown.global_reputation.total : 70
      };

      openMailCache[threadId] = { level: level, score: score, reason: reason, breakdown: tooltipBreakdown, context: openContext };
      cache[threadId] = {
        level: level,
        score: score,
        emailText: openContext.emailText,
        senderEmail: openContext.senderEmail,
        urls: openContext.urls,
        urlScore: riskBreakdown && typeof riskBreakdown.external_score === 'number' ? riskBreakdown.external_score : undefined
      };
      syncInboxBadgeForThread(threadId, level, score);
      applyOpenBadgeState(badge, level, score, reason, tooltipBreakdown);
    }).catch(function () {
      openMailCache[threadId] = {
        level: 'suspicious',
        score: 35,
        reason: 'Could not complete full body scan.',
        breakdown: { brandMatch: 'Unknown', logicFlags: ['ScanError'], vtFlagged: 0, vtTotal: 70 },
        context: openContext
      };
      cache[threadId] = {
        level: 'suspicious',
        score: 35,
        emailText: openContext.emailText,
        senderEmail: openContext.senderEmail,
        urls: openContext.urls,
        urlScore: undefined
      };
      syncInboxBadgeForThread(threadId, 'suspicious', 35);
      applyOpenBadgeState(
        badge,
        'suspicious',
        35,
        'Could not complete full body scan.',
        { brandMatch: 'Unknown', logicFlags: ['ScanError'], vtFlagged: 0, vtTotal: 70 }
      );
    }).finally(function () {
      openMailInFlight.delete(threadId);
    });
  }

  function scheduleOpenMailScan() {
    clearTimeout(openMailTimer);
    openMailTimer = setTimeout(scanOpenedMail, openMailDebounceMs);
  }

  function rowHasBadgeForId(row, id) {
    var badge = row.querySelector('.spectrashield-badge[' + BADGE_ATTR + '="' + id + '"]');
    return !!badge;
  }

  function removeOrphanBadges(container) {
    if (!container) return;
    var badges = container.querySelectorAll('.spectrashield-badge');
    for (var j = 0; j < badges.length; j++) {
      badges[j].remove();
    }
  }

  function analyzeEmail(emailText, senderEmail, urls, extraPayload) {
    var payload = {
      email_text: emailText,
      email_header: null,
      url: urls && urls.length > 0 ? urls[0] : null,
      urls: urls || [],
      sender_email: senderEmail || null,
      private_mode: true
    };
    if (extraPayload && typeof extraPayload === 'object') {
      for (var key in extraPayload) {
        if (Object.prototype.hasOwnProperty.call(extraPayload, key)) {
          payload[key] = extraPayload[key];
        }
      }
    }
    return fetch(API_BASE + '/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }).then(function (res) {
      if (!res.ok) throw new Error(res.status);
      return res.json();
    });
  }

  function getExtensionAssetUrl(path) {
    if (!path) return '';
    if (linkedinAssetCache[path]) return linkedinAssetCache[path];
    var resolved = '';
    try {
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getURL) {
        resolved = chrome.runtime.getURL(path);
      }
    } catch (_) {}
    linkedinAssetCache[path] = resolved;
    return resolved;
  }

  function isValidExtensionAssetUrl(url) {
    if (!url || typeof url !== 'string') return false;
    if (url.indexOf('chrome-extension://') !== 0) return false;
    if (url.indexOf('chrome-extension://invalid/') === 0) return false;
    return true;
  }

  function analyzeLinkedInViaBackground(payload) {
    return new Promise(function (resolve, reject) {
      try {
        if (!(chrome && chrome.runtime && chrome.runtime.sendMessage)) {
          reject(new Error('runtime messaging unavailable'));
          return;
        }
      } catch (_) {
        reject(new Error('runtime messaging unavailable'));
        return;
      }

      chrome.runtime.sendMessage(
        {
          type: 'SPECTRASHIELD_LINKEDIN_ANALYZE',
          payload: payload
        },
        function (response) {
          var runtimeError = chrome && chrome.runtime ? chrome.runtime.lastError : null;
          if (runtimeError) {
            reject(new Error(runtimeError.message || 'background messaging failed'));
            return;
          }
          if (!response || response.ok !== true) {
            reject(new Error((response && response.error) || 'analysis failed'));
            return;
          }
          resolve(response.data);
        }
      );
    });
  }

  function pingLinkedInBridge() {
    try {
      if (!(chrome && chrome.runtime && chrome.runtime.sendMessage)) {
        console.warn('[SpectraShield][LinkedIn] runtime messaging unavailable at ping stage');
        return;
      }
    } catch (_) {
      console.warn('[SpectraShield][LinkedIn] runtime messaging unavailable at ping stage');
      return;
    }

    chrome.runtime.sendMessage({ type: 'SPECTRASHIELD_PING' }, function (response) {
      var runtimeError = chrome && chrome.runtime ? chrome.runtime.lastError : null;
      if (runtimeError) {
        console.warn('[SpectraShield][LinkedIn] bridge ping failed:', runtimeError.message || runtimeError);
        return;
      }
      if (!response || !response.ok) {
        console.warn('[SpectraShield][LinkedIn] bridge ping negative response');
        return;
      }
      console.log('[SpectraShield][LinkedIn] bridge ping success');
    });
  }

  function riskLevel(finalRisk) {
    if (finalRisk >= 70) return 'high';
    if (finalRisk >= 30) return 'suspicious';
    return 'safe';
  }

  function openSpectraShieldAnalysis(entry) {
    if (!entry) return;
    var params = new URLSearchParams();
    if (entry.emailText) params.set('email_text', entry.emailText);
    if (entry.senderEmail) params.set('sender_email', entry.senderEmail);
    if (entry.urls && entry.urls.length > 0) params.set('url', entry.urls[0]);
    var url = 'http://localhost:5173/#spectra?' + params.toString();
    try {
      window.open(url, '_blank');
    } catch (_) { }
  }

  function getBadgeIcon(level) {
    if (level === 'safe') {
      return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M20 6L9 17l-5-5"/></svg>';
    }
    if (level === 'suspicious') {
      return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/><line x1="12" y1="9" x2="12" y2="13"/></svg>';
    }
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 9v4M12 16h.01"/></svg>';
  }

  function applyInboxBadgeVisual(span, level, score) {
    if (!span) return;
    span.className = 'spectrashield-badge ' + level;
    span.title = (level === 'high' ? 'High risk' : level === 'suspicious' ? 'Suspicious' : 'Safe') + ': ' + score + '%';
    span.innerHTML = getBadgeIcon(level);
  }

  function syncInboxBadgeForThread(threadId, level, score) {
    if (!threadId) return;
    var badges = document.querySelectorAll('.spectrashield-badge[' + BADGE_ATTR + '="' + threadId + '"]');
    for (var i = 0; i < badges.length; i++) {
      applyInboxBadgeVisual(badges[i], level, score);
    }
  }

  function createBadge(level, score, id) {
    var span = document.createElement('span');
    span.setAttribute(BADGE_ATTR, id);
    applyInboxBadgeVisual(span, level, score);
    // Hover tooltip
    span.addEventListener('mouseenter', function () {
      var tt = document.createElement('span');
      tt.className = 'spectrashield-tooltip';
      var tip = (level === 'high' ? 'High risk' : level === 'suspicious' ? 'Suspicious' : 'Safe') + ': ' + score + '%';
      var entry = cache[id];
      if (entry && typeof entry.urlScore === 'number') tip += ' (URL: ' + Math.round(entry.urlScore) + '%)';
      tt.textContent = tip;
      document.body.appendChild(tt);
      var r = span.getBoundingClientRect();
      tt.style.left = (r.left + r.width / 2) + 'px';
      tt.style.top = (r.top - 4) + 'px';
      tt.style.transform = 'translate(-50%, -100%)';
      span._tt = tt;
    });
    span.addEventListener('mouseleave', function () {
      if (span._tt) {
        span._tt.remove();
        span._tt = null;
      }
    });
    // Click → open SpectraShield UI with this email's context (include URL for Scan Link)
    span.addEventListener('click', function (e) {
      e.stopPropagation();
      openSpectraShieldAnalysis(cache[id]);
    });
    return span;
  }

  function injectBadge(subjectInfo, level, score, id) {
    if (!subjectInfo || !subjectInfo.element) return;
    var row = subjectInfo.element.closest('tr') || subjectInfo.element.closest('div[data-message-id]');
    if (row) removeOrphanBadges(row);
    var badge = createBadge(level, score, id);
    subjectInfo.element.after(badge);
  }

  function processRow(row) {
    var id = getRowId(row);
    if (!id) return;

    var subjectInfo = getSubject(row);
    var sender = getSender(row);
    var snippet = getSnippet(row);
    var subjectText = subjectInfo && subjectInfo.text ? subjectInfo.text : '';
    if (subjectText || sender) {
      threadMeta[id] = {
        subject: subjectText || '',
        sender: sender || ''
      };
    }
    var emailText = [subjectText, snippet].filter(Boolean).join(' ').trim();
    var urls = getAllUrlsFromRow(row, subjectText, snippet);

    if (cache[id]) {
      if (!rowHasBadgeForId(row, id) && subjectInfo && document.contains(subjectInfo.element)) {
        injectBadge(subjectInfo, cache[id].level, cache[id].score, id);
      }
      return;
    }

    if (rowHasBadgeForId(row, id)) return;
    if (!emailText && !sender) return;
    if (processed.has(id)) return;

    processed.add(id);

    analyzeEmail(emailText || '(no content)', sender, urls, { thread_id: id })
      .then(function (data) {
        var level = riskLevel(typeof data.final_risk === 'number' ? data.final_risk : 0);
        var score = Math.round(data.final_risk || 0);
        cache[id] = {
          level: level,
          score: score,
          emailText: emailText || '',
          senderEmail: sender || '',
          urls: urls || [],
          urlScore: data.breakdown && typeof data.breakdown.url_score === 'number' ? data.breakdown.url_score : undefined
        };
        if (subjectInfo && subjectInfo.element && document.contains(subjectInfo.element)) {
          if (!rowHasBadgeForId(row, id)) injectBadge(subjectInfo, level, score, id);
        }
      })
      .catch(function () {
        var subject = (subjectInfo && subjectInfo.text || '').toLowerCase();
        var s = (sender || '').toLowerCase();
        var level = 'safe';
        if (/urgent|action required|verify|suspended|confirm your|payroll/.test(subject) || /noreply/.test(s)) level = 'high';
        else if (/click here|limited time|delivery|support/.test(subject) || /delivery|support/.test(s)) level = 'suspicious';
        var score = level === 'high' ? 85 : level === 'suspicious' ? 55 : 15;
        cache[id] = {
          level: level,
          score: score,
          emailText: emailText || '',
          senderEmail: sender || '',
          urls: urls || [],
          urlScore: undefined
        };
        if (subjectInfo && subjectInfo.element && document.contains(subjectInfo.element)) {
          if (!rowHasBadgeForId(row, id)) injectBadge(subjectInfo, level, score, id);
        }
      });
  }

  function processAll() {
    var rows = getRows();
    for (var i = 0; i < rows.length; i++) {
      try {
        processRow(rows[i]);
      } catch (e) { }
    }
  }

  function scheduleProcess() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(processAll, debounceMs);
  }

  function scheduleProcessScroll() {
    clearTimeout(scrollTimer);
    scrollTimer = setTimeout(processAll, scrollDebounceMs);
  }

  function start() {
    var main = document.querySelector('[role="main"]');
    processAll();
    scanEmailBody(document);
    scheduleOpenMailScan();

    if (main) {
      var mo = new MutationObserver(scheduleProcess);
      mo.observe(main, { childList: true, subtree: true });

      var lmo = new MutationObserver(function (mutations) {
        var shouldCheckOpenMail = false;
        for (var i = 0; i < mutations.length; i++) {
          for (var j = 0; j < mutations[i].addedNodes.length; j++) {
            var n = mutations[i].addedNodes[j];
            if (n && n.querySelectorAll) {
              scanEmailBody(n);
              if (
                (n.matches && (n.matches('.a3s') || n.matches('.ha') || n.matches('h2.hP'))) ||
                n.querySelector('.a3s') ||
                n.querySelector('.ha') ||
                n.querySelector('h2.hP')
              ) {
                shouldCheckOpenMail = true;
              }
            }
          }
        }
        if (shouldCheckOpenMail) scheduleOpenMailScan();
      });
      lmo.observe(main, { childList: true, subtree: true });

      main.addEventListener('scroll', scheduleProcessScroll, { passive: true });
      main.addEventListener('scroll', scheduleProcessScroll, { passive: true, capture: true });
      document.addEventListener('scroll', scheduleProcessScroll, { passive: true, capture: true });
    }

    window.addEventListener('hashchange', function () {
      setTimeout(processAll, 600);
      setTimeout(scheduleOpenMailScan, 700);
    });

    window.addEventListener('focus', function () {
      setTimeout(processAll, 200);
      setTimeout(scheduleOpenMailScan, 250);
    });

    setInterval(function () {
      if (document.visibilityState === 'visible') processAll();
      if (document.visibilityState === 'visible') scanEmailBody(document);
      if (document.visibilityState === 'visible') scheduleOpenMailScan();
    }, 2500);
  }

  function getLinkedInThreadId() {
    var href = window.location.href || '';
    var urnMatch = href.match(/messagingThread%3A([^&#/]+)/i);
    if (urnMatch && urnMatch[1]) return urnMatch[1];

    var pathMatch = href.match(/\/messaging\/thread\/([^/?#]+)/i);
    if (pathMatch && pathMatch[1]) return pathMatch[1];

    try {
      var parsed = new URL(href);
      var current = parsed.searchParams.get('currentConversationUrn') || '';
      var normalized = decodeURIComponent(current);
      var normalizedMatch = normalized.match(/messagingThread:([^,\)]+)/i);
      if (normalizedMatch && normalizedMatch[1]) return normalizedMatch[1];

      var pathToken = (parsed.pathname || '').match(/\/messaging\/thread\/([^/?#]+)/i);
      if (pathToken && pathToken[1]) return pathToken[1];
    } catch (_) {}

    return null;
  }

  function linkedinRiskLevel(score) {
    if (score > 70) return 'Hard';
    if (score >= 31) return 'Moderate';
    return 'Safe';
  }

  function linkedinBadgeColor(level) {
    if (level === 'Safe') return '#17a34a';
    if (level === 'Moderate') return '#d29c00';
    return '#dc2626';
  }

  function getLinkedInStableAnchor(messageNode) {
    if (!messageNode) return null;
    var eventLi = messageNode.closest('li.msg-s-message-list__event');
    if (eventLi) return eventLi;
    var group = messageNode.closest('.msg-s-message-group');
    if (group) return group;
    var eventItem = messageNode.closest('.msg-s-event-listitem');
    if (eventItem) return eventItem;
    var groupItem = messageNode.closest('li.msg-s-message-list__event');
    if (groupItem) return groupItem;
    return messageNode;
  }

  function getLinkedInMessageKey(threadId, messageNode, messageText) {
    var stableRoot = getLinkedInStableAnchor(messageNode);
    if (!stableRoot) return null;

    var existing = stableRoot.getAttribute('data-spectra-linkedin-key');
    if (existing) return existing;

    var rootText = (stableRoot.innerText || '').trim().slice(0, 220);
    var domIdentity =
      stableRoot.getAttribute('data-urn') ||
      stableRoot.getAttribute('data-id') ||
      stableRoot.getAttribute('id') ||
      '';
    var key = 'li-' + stableHash([threadId || '', domIdentity, messageText || '', rootText].join('|'));
    stableRoot.setAttribute('data-spectra-linkedin-key', key);
    return key;
  }

  function ensureLinkedInShadowBadge(targetNode, riskData) {
    if (!targetNode || !riskData) return;

    var stableRoot = getLinkedInStableAnchor(targetNode);
    if (!stableRoot) return;

    var existingHosts = stableRoot.querySelectorAll('[data-spectrashield-linkedin-pill]');
    for (var h = 1; h < existingHosts.length; h++) {
      existingHosts[h].remove();
    }

    var host = existingHosts.length ? existingHosts[0] : null;
    if (!host) {
      host = document.createElement('span');
      host.setAttribute('data-spectrashield-linkedin-pill', 'true');
      host.style.marginLeft = '8px';
      host.style.verticalAlign = 'middle';

      var attachTarget =
        stableRoot.querySelector('.msg-s-message-group__meta') ||
        stableRoot.querySelector('time') ||
        stableRoot;

      if (attachTarget && attachTarget.parentNode) {
        attachTarget.parentNode.insertBefore(host, attachTarget.nextSibling);
      } else if (stableRoot.insertBefore) {
        stableRoot.insertBefore(host, stableRoot.firstChild);
      }
    }

    host._spectraContext = riskData && riskData.context ? riskData.context : null;
    var isLoading = !!(riskData && riskData.loading);

    var root = host.shadowRoot || host.attachShadow({ mode: 'open' });

    var cssUrl = getExtensionAssetUrl('content.css');
    if (isValidExtensionAssetUrl(cssUrl) && !root.querySelector('link[data-spectrashield-shadow-css]')) {
      var linkEl = document.createElement('link');
      linkEl.setAttribute('rel', 'stylesheet');
      linkEl.setAttribute('href', cssUrl);
      linkEl.setAttribute('data-spectrashield-shadow-css', '1');
      root.appendChild(linkEl);
    }

    var style = root.querySelector('style[data-spectrashield-inline-style]');
    if (!style) {
      style = document.createElement('style');
      style.setAttribute('data-spectrashield-inline-style', '1');
      style.textContent =
        '.pill{display:inline-flex;align-items:center;gap:6px;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:700;line-height:16px;cursor:default;position:relative;color:#fff;}' +
        '.tooltip{display:none;position:absolute;left:50%;bottom:120%;transform:translateX(-50%);min-width:220px;max-width:280px;padding:8px 10px;border-radius:8px;font-size:11px;line-height:1.45;color:#111827;background:#ffffff;border:1px solid rgba(17,24,39,.14);box-shadow:0 8px 24px rgba(0,0,0,.12);z-index:9999;}' +
        '.pill:hover .tooltip{display:block;}' +
        '.row{display:flex;justify-content:space-between;gap:8px;margin:2px 0;}' +
        '.label{font-weight:600;color:#374151;}' +
        '.value{font-weight:500;color:#111827;text-align:right;}';
      root.appendChild(style);
    }

    var pill = root.querySelector('.pill');
    if (!pill) {
      pill = document.createElement('span');
      pill.className = 'pill';
      pill.style.cursor = 'pointer';
      pill.addEventListener('click', function (e) {
        e.preventDefault();
        e.stopPropagation();
        if (host._spectraLoading) return;
        var context = host._spectraContext;
        if (context) {
          openSpectraShieldAnalysis(context);
        }
      });

      var tooltip = document.createElement('div');
      tooltip.className = 'tooltip';
      tooltip.innerHTML =
        '<div class="row"><span class="label">AI Likelihood</span><span class="value" data-spectra-ai>0%</span></div>' +
        '<div class="row"><span class="label">Manipulation Flags</span><span class="value" data-spectra-manip>0</span></div>' +
        '<div class="row"><span class="label">Brand Safety</span><span class="value" data-spectra-brand>Unknown</span></div>';

      pill.appendChild(tooltip);
      root.appendChild(pill);
    }

    host._spectraLoading = isLoading;
    pill.style.cursor = isLoading ? 'wait' : 'pointer';
    pill.style.background = isLoading ? '#6b7280' : riskData.color;
    var pillText = isLoading ? 'Scanning...' : (riskData.score + '% ' + riskData.level);
    if (pill.firstChild && pill.firstChild.nodeType === 3) {
      pill.firstChild.nodeValue = pillText;
    } else {
      pill.insertBefore(document.createTextNode(pillText), pill.firstChild);
    }

    var aiNode = root.querySelector('[data-spectra-ai]');
    if (aiNode) aiNode.textContent = isLoading ? 'Analyzing...' : (riskData.aiLikelihood + '%');
    var manipNode = root.querySelector('[data-spectra-manip]');
    if (manipNode) manipNode.textContent = isLoading ? 'VirusTotal...' : String(riskData.manipulationFlags);
    var brandNode = root.querySelector('[data-spectra-brand]');
    if (brandNode) brandNode.textContent = isLoading ? 'Link verification in progress' : riskData.brandSafety;
  }

  function extractLinkedInLinks(messageNode) {
    function isSkippableLinkedInHref(href) {
      if (!href) return true;
      var raw = String(href).trim();
      if (!raw) return true;
      if (/^(mailto:|javascript:|#)/i.test(raw)) return true;

      var parsed;
      try {
        parsed = new URL(raw, window.location.origin);
      } catch (_) {
        return true;
      }

      var host = (parsed.hostname || '').toLowerCase();
      var path = (parsed.pathname || '').toLowerCase();

      var isLinkedInHost =
        host === 'linkedin.com' ||
        host === 'www.linkedin.com' ||
        host.endsWith('.linkedin.com');

      if (!isLinkedInHost) {
        return parsed.protocol !== 'http:' && parsed.protocol !== 'https:';
      }

      // Skip internal/profile/navigation links; keep only sender-shared external links.
      if (
        path.indexOf('/in/') === 0 ||
        path.indexOf('/company/') === 0 ||
        path.indexOf('/school/') === 0 ||
        path.indexOf('/pub/') === 0 ||
        path.indexOf('/feed/') === 0 ||
        path.indexOf('/messaging/') === 0 ||
        path.indexOf('/posts/') === 0 ||
        path.indexOf('/groups/') === 0 ||
        path.indexOf('/jobs/') === 0
      ) {
        return true;
      }

      return true;
    }

    var out = [];
    if (!messageNode || !messageNode.querySelectorAll) return out;

    var linkRoot =
      messageNode.querySelector('.msg-s-event-listitem__body') ||
      messageNode.querySelector('.msg-s-event-listitem__message-bubble') ||
      messageNode.querySelector('.msg-s-message-group__message-bubble') ||
      messageNode;

    var anchors = linkRoot.querySelectorAll('a[href]');
    for (var i = 0; i < anchors.length; i++) {
      var a = anchors[i];
      var href = a.getAttribute('href') || '';
      if (!href) continue;
      if (isSkippableLinkedInHref(href)) continue;
      out.push({
        text: (a.innerText || a.textContent || '').trim(),
        href: href
      });
    }
    return out;
  }

  function extractLinkedInMessageText(messageNode) {
    if (!messageNode) return '';

    var candidateSelectors = [
      '.msg-s-event-listitem__body',
      '.msg-s-message-group__message-bubble',
      '.msg-s-event-listitem__message-bubble',
      '.msg-s-event-listitem__message-bubble-container',
      '[data-view-name="message-list-item"]'
    ];

    for (var i = 0; i < candidateSelectors.length; i++) {
      var found = messageNode.querySelector(candidateSelectors[i]);
      if (found) {
        var text = (found.innerText || found.textContent || '').trim();
        if (text) return text;
      }
    }

    return (messageNode.innerText || messageNode.textContent || '').trim();
  }

  function analyzeLinkedInMessage(messageNode) {
    if (!messageNode || linkedinProcessedMessages.has(messageNode)) return;

    var threadId = getLinkedInThreadId();
    if (!threadId) {
      threadId = 'thread-' + btoa((window.location.pathname || 'linkedin').slice(0, 120));
      if (!linkedinWarnedNoThreadId) {
        linkedinWarnedNoThreadId = true;
        try {
          console.warn('[SpectraShield][LinkedIn] unable to parse native thread id; using fallback key');
        } catch (_) {}
      }
    }

    var messageText = extractLinkedInMessageText(messageNode);
    if (!messageText) return;

    var messageKey = getLinkedInMessageKey(threadId, messageNode, messageText);
    if (!messageKey) return;

    if (linkedinInFlightByKey[messageKey]) {
      linkedinProcessedMessages.add(messageNode);
      return;
    }

    var links = extractLinkedInLinks(messageNode);
    var signature = [threadId, messageKey, messageText.slice(0, 180), links.map(function (l) { return l.href; }).join('|')].join('|');

    if (linkedinSignatureByKey[messageKey] === signature && linkedinThreadMessageCache[messageKey]) {
      ensureLinkedInShadowBadge(messageNode, linkedinThreadMessageCache[messageKey]);
      linkedinProcessedMessages.add(messageNode);
      linkedinProcessedKeys.add(messageKey);
      return;
    }

    if (linkedinProcessedKeys.has(messageKey) && linkedinThreadMessageCache[messageKey]) {
      ensureLinkedInShadowBadge(messageNode, linkedinThreadMessageCache[messageKey]);
      linkedinProcessedMessages.add(messageNode);
      return;
    }

    if (links.length > 0) {
      ensureLinkedInShadowBadge(messageNode, {
        loading: true,
        score: 0,
        level: 'Scanning',
        color: '#6b7280',
        aiLikelihood: 0,
        manipulationFlags: 0,
        brandSafety: 'Link verification in progress',
        context: {
          emailText: messageText,
          senderEmail: '',
          urls: links.map(function (l) { return l.href; })
        }
      });
    }

    linkedinInFlightByKey[messageKey] = true;

    analyzeLinkedInViaBackground({
      email_text: messageText,
      email_header: null,
      url: links.length > 0 ? links[0].href : null,
      urls: links.map(function (l) { return l.href; }),
      sender_email: null,
      platform: 'linkedin',
      thread_id: threadId,
      link_pairs: links,
      private_mode: true
    }).then(function (resp) {
      var scoreRaw = typeof resp.final_risk === 'number' ? resp.final_risk :
        (typeof resp.final_score === 'number' ? resp.final_score : 0);
      var score = Math.round(scoreRaw || 0);
      var level = resp.level || linkedinRiskLevel(score);
      var sentinel = resp.linkedin_sentinel || {};
      var manipulationFlags = sentinel.manipulation_flags && sentinel.manipulation_flags.length
        ? sentinel.manipulation_flags.length
        : 0;

      var riskData = {
        score: score,
        level: level,
        color: linkedinBadgeColor(level),
        aiLikelihood: Math.round(typeof sentinel.ai_likelihood === 'number' ? sentinel.ai_likelihood : 0),
        manipulationFlags: manipulationFlags,
        brandSafety: sentinel.brand_safety || 'Clear',
        context: {
          emailText: messageText,
          senderEmail: '',
          urls: links.map(function (l) { return l.href; })
        }
      };

      linkedinThreadMessageCache[messageKey] = riskData;
      linkedinSignatureByKey[messageKey] = signature;
      linkedinProcessedKeys.add(messageKey);
      ensureLinkedInShadowBadge(messageNode, riskData);
      linkedinProcessedMessages.add(messageNode);
    }).catch(function (err) {
      try {
        console.warn('[SpectraShield][LinkedIn] background analyze failed:', (err && err.message) ? err.message : err);
      } catch (_) {}
      var fallback = {
        score: 35,
        level: 'Moderate',
        color: linkedinBadgeColor('Moderate'),
        aiLikelihood: 0,
        manipulationFlags: 0,
        brandSafety: 'Unknown',
        context: {
          emailText: messageText,
          senderEmail: '',
          urls: links.map(function (l) { return l.href; })
        }
      };
      linkedinThreadMessageCache[messageKey] = fallback;
      linkedinSignatureByKey[messageKey] = signature;
      linkedinProcessedKeys.add(messageKey);
      ensureLinkedInShadowBadge(messageNode, fallback);
      linkedinProcessedMessages.add(messageNode);
    }).finally(function () {
      delete linkedinInFlightByKey[messageKey];
    });
  }

  function processLinkedInMessages(root) {
    var scope = root || document;
    var bubbles = [];
    var seenNodes = new Set();

    for (var i = 0; i < LINKEDIN_BUBBLE_SELECTORS.length; i++) {
      var selector = LINKEDIN_BUBBLE_SELECTORS[i];
      if (scope.matches && scope.matches(selector)) {
        if (!seenNodes.has(scope)) {
          seenNodes.add(scope);
          bubbles.push(scope);
        }
      }
    }

    if (scope.querySelectorAll) {
      for (var j = 0; j < LINKEDIN_BUBBLE_SELECTORS.length; j++) {
        var found = scope.querySelectorAll(LINKEDIN_BUBBLE_SELECTORS[j]);
        for (var k = 0; k < found.length; k++) {
          if (!seenNodes.has(found[k])) {
            seenNodes.add(found[k]);
            bubbles.push(found[k]);
          }
        }
      }
    }

    var now = Date.now();
    if (now - linkedinLastScanLogAt > 5000) {
      linkedinLastScanLogAt = now;
      try {
        console.log('[SpectraShield][LinkedIn] scan candidates:', bubbles.length);
      } catch (_) {}
    }

    for (var m = 0; m < bubbles.length; m++) {
      analyzeLinkedInMessage(bubbles[m]);
    }
  }

  function findLinkedInMessageContainer() {
    for (var i = 0; i < LINKEDIN_MESSAGE_CONTAINER_SELECTORS.length; i++) {
      var container = document.querySelector(LINKEDIN_MESSAGE_CONTAINER_SELECTORS[i]);
      if (container) return container;
    }
    return null;
  }

  function startLinkedInFallbackObserver() {
    if (linkedinBackgroundObserverStarted) return;
    linkedinBackgroundObserverStarted = true;

    var bodyObserver = new MutationObserver(function (mutations) {
      for (var i = 0; i < mutations.length; i++) {
        for (var j = 0; j < mutations[i].addedNodes.length; j++) {
          var node = mutations[i].addedNodes[j];
          if (!node || node.nodeType !== 1) continue;
          processLinkedInMessages(node);
        }
      }
    });

    bodyObserver.observe(document.body, { childList: true, subtree: true });
    setInterval(function () {
      if (document.visibilityState !== 'visible') return;
      processLinkedInMessages(document);
    }, 3000);

    try {
      console.log('[SpectraShield][LinkedIn] fallback observer active');
    } catch (_) {}
  }

  function startLinkedInObserver() {
    console.log('[SpectraShield][LinkedIn] starting observer');

    var tryAttach = function () {
      var container = findLinkedInMessageContainer();
      if (!container) {
        return false;
      }

      if (container.getAttribute('data-spectrashield-observer') === '1') {
        processLinkedInMessages(container);
        return true;
      }

      container.setAttribute('data-spectrashield-observer', '1');

      processLinkedInMessages(container);

      var observer = new MutationObserver(function (mutations) {
        for (var i = 0; i < mutations.length; i++) {
          for (var j = 0; j < mutations[i].addedNodes.length; j++) {
            var node = mutations[i].addedNodes[j];
            if (!node || node.nodeType !== 1) continue;
            processLinkedInMessages(node);
          }
        }
      });

      observer.observe(container, { childList: true, subtree: true });
      console.log('[SpectraShield][LinkedIn] observer attached');
      return true;
    };

    if (tryAttach()) return;

    var attachTimer = setInterval(function () {
      if (tryAttach()) clearInterval(attachTimer);
    }, 1000);

    setTimeout(function () {
      clearInterval(attachTimer);
      if (!findLinkedInMessageContainer()) {
        console.warn('[SpectraShield][LinkedIn] message list container not found after wait; fallback observer will continue');
      }
    }, 30000);

    startLinkedInFallbackObserver();
  }

  function waitForGmail() {
    if (document.querySelector('[role="main"]') || document.querySelector('tr.zA')) {
      start();
      return;
    }
    var t = setInterval(function () {
      if (document.querySelector('[role="main"]') || document.querySelector('tr.zA')) {
        clearInterval(t);
        start();
      }
    }, 800);
    setTimeout(function () { clearInterval(t); }, 20000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      var host = window.location.hostname || '';
      if (host.indexOf('mail.google.com') !== -1) {
        waitForGmail();
        return;
      }
      if (host.indexOf('linkedin.com') !== -1 && window.location.href.indexOf('/messaging') !== -1) {
        pingLinkedInBridge();
        startLinkedInObserver();
      }
    });
  } else {
    var host = window.location.hostname || '';
    if (host.indexOf('mail.google.com') !== -1) {
      waitForGmail();
    } else if (host.indexOf('linkedin.com') !== -1 && window.location.href.indexOf('/messaging') !== -1) {
      pingLinkedInBridge();
      startLinkedInObserver();
    }
  }
})();
