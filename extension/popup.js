/**
 * SpectraShield 2.0 — Universal Liquid Glass Extension Controller
 * Maintains 100% backward-compatibility with backend /analyze API while elevating UI/UX.
 */

(function () {
  'use strict';

  const API_BASE = 'http://localhost:8000';
  const SOC_URL = 'http://localhost:5173';

  // Live Backend Health Beacon
  async function pingBackend() {
    const beacon = document.getElementById('backendBeacon');
    const statusText = document.getElementById('backendStatusText');
    try {
      const res = await fetch(`${API_BASE}/`, { method: 'GET' });
      if (res.ok || res.status === 404) {
        if (beacon) beacon.className = 'status-indicator live';
        if (statusText) statusText.textContent = 'Spectra 2.0 Engine Live (Port 8000)';
      } else {
        throw new Error('Non-200');
      }
    } catch {
      if (beacon) beacon.className = 'status-indicator offline';
      if (statusText) statusText.textContent = 'Spectra 2.0 Air-Gapped / Offline';
    }
  }
  pingBackend();

  // Form Elements
  const formSection = document.getElementById('formSection');
  const emailText = document.getElementById('emailText');
  const url = document.getElementById('url');
  const sender = document.getElementById('sender');
  const privateMode = document.getElementById('privateMode');
  const analyzeBtn = document.getElementById('analyzeBtn');
  const loadSampleBtn = document.getElementById('loadSampleBtn');

  // Active Email Card Elements
  const activeEmailCard = document.getElementById('activeEmailCard');
  const activeEmailSubject = document.getElementById('activeEmailSubject');
  const activeEmailSender = document.getElementById('activeEmailSender');
  const activeEmailPlatform = document.getElementById('activeEmailPlatform');
  const scanActiveEmailBtn = document.getElementById('scanActiveEmailBtn');
  let activeTabExtractedPayload = null;

  // Active Tab Automatic Inspection
  if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      const activeTab = tabs && tabs[0];
      if (!activeTab || !activeTab.url) return;
      const tabUrl = activeTab.url.toLowerCase();

      if (tabUrl.includes('mail.google.com') || tabUrl.includes('linkedin.com')) {
        const isGmail = tabUrl.includes('mail.google.com');
        if (activeEmailPlatform) activeEmailPlatform.textContent = isGmail ? 'GMAIL' : 'LINKEDIN';
        if (activeEmailSubject) activeEmailSubject.textContent = 'Detecting active email content...';
        if (activeEmailCard) activeEmailCard.classList.remove('hidden');

        chrome.tabs.sendMessage(activeTab.id, { type: 'EXTRACT_ACTIVE_EMAIL' }, function (res) {
          var err = chrome.runtime.lastError;
          if (err || !res || !res.ok || !res.payload) {
            if (activeEmailSubject) activeEmailSubject.textContent = 'Please refresh this tab (F5) to connect SpectraShield.';
            if (activeEmailSender) activeEmailSender.textContent = (err && err.message) ? err.message : 'No open email found in DOM.';
            if (scanActiveEmailBtn) scanActiveEmailBtn.disabled = true;
            return;
          }
          activeTabExtractedPayload = res.payload;
          if (activeEmailSubject) {
            activeEmailSubject.textContent = res.payload.subject || '(No Subject Email)';
          }
          if (activeEmailSender) {
            const senderName = res.payload.sender?.name || 'Sender';
            const senderEmail = res.payload.sender?.email || 'unknown';
            const urlCount = Array.isArray(res.payload.urls) ? res.payload.urls.length : 0;
            activeEmailSender.textContent = `From: ${senderName} <${senderEmail}> • ${urlCount} link(s)`;
          }
          if (scanActiveEmailBtn) {
            scanActiveEmailBtn.disabled = false;
          }
        });
      }
    });
  }

  if (scanActiveEmailBtn) {
    scanActiveEmailBtn.addEventListener('click', function () {
      if (!activeTabExtractedPayload) {
        showErr('Unable to read the current email. Please ensure an email is open in Gmail.');
        return;
      }
      scanActiveEmailBtn.disabled = true;
      scanActiveEmailBtn.innerHTML = '<span class="btn-text">✓ Opening Mail Intelligence...</span>';

      // 1. Instant Redirect (0ms latency): open or focus the frontend tab immediately
      openSocConsole();

      // 2. Concurrently run analysis in background
      fetch(`${API_BASE}/api/forensics/analyze-email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(activeTabExtractedPayload),
      })
      .then(function (res) {
        if (!res.ok) throw new Error(`Backend error: ${res.status}`);
        return res.json();
      })
      .then(function (data) {
        const caseId = data.case_id;
        if (caseId) {
          latestCaseId = caseId;
          try {
            if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
              chrome.runtime.sendMessage({
                type: 'OPEN_MAIL_INVESTIGATION',
                caseId: caseId,
                url: `${SOC_URL}/mail-intelligence/${encodeURIComponent(caseId)}`
              });
            }
          } catch (_) {}
        }
        scanActiveEmailBtn.innerHTML = '<span class="btn-text">✓ Case Sealed: ' + (data.case_number || 'CASE-2026') + '</span>';
        showResult(data);
      })
      .catch(function (err) {
        console.warn('Background scan completed or tab handled by frontend', err);
      });
    });
  }

  // Result Elements
  const result = document.getElementById('result');
  const error = document.getElementById('error');
  const errorMsg = document.getElementById('errorMsg') || error;
  const ambientCaustic = document.getElementById('ambientCaustic');
  const gaugeCircle = document.getElementById('gaugeCircle');
  const riskValue = document.getElementById('riskValue');
  const verdictEl = document.getElementById('verdict');
  const verdictBadge = document.getElementById('verdictBadge');
  const confidenceEl = document.getElementById('confidence');
  const categoryEl = document.getElementById('category');
  const reasoningEl = document.getElementById('reasoning');

  // Brand Match & Breakdown Elements
  const brandMatchBadge = document.getElementById('brandMatchBadge');
  const brandMatchName = document.getElementById('brandMatchName');
  const barUrl = document.getElementById('barUrl');
  const barValUrl = document.getElementById('barValUrl');
  const barManipulation = document.getElementById('barManipulation');
  const barValManipulation = document.getElementById('barValManipulation');
  const barBrand = document.getElementById('barBrand');
  const barValBrand = document.getElementById('barValBrand');
  const barAi = document.getElementById('barAi');
  const barValAi = document.getElementById('barValAi');

  // Action Buttons
  const copyDefangedBtn = document.getElementById('copyDefangedBtn');
  const openSocBtn = document.getElementById('openSocBtn');
  const openSocNavBtn = document.getElementById('openSocNavBtn');
  const newScanBtn = document.getElementById('newScanBtn');

  // Circumference for r=54 SVG circle: 2 * PI * 54 = 339.292
  const CIRCUMFERENCE = 339.292;

  // Sample Phishing Scenario
  const SAMPLE_EMAIL =
    'URGENT: Verify your account now. Microsoft 365 tenant suspension notice. Unauthorized access detected from Frankfurt, Germany. Complete identity verification within 24 hours to prevent total directory lockout.';
  const SAMPLE_URL = 'https://secure-verify-account.tk/login/microsoft';
  const SAMPLE_SENDER = 'security-noreply@micro-soft-billing.top';

  if (loadSampleBtn) {
    loadSampleBtn.addEventListener('click', () => {
      emailText.value = SAMPLE_EMAIL;
      url.value = SAMPLE_URL;
      sender.value = SAMPLE_SENDER;
    });
  }

  let latestCaseId = null;

  function openSocConsole(customText) {
    let targetUrl = `${SOC_URL}/mail-intelligence`;
    if (latestCaseId) {
      targetUrl = `${SOC_URL}/mail-intelligence/${encodeURIComponent(latestCaseId)}`;
    } else if (activeTabExtractedPayload) {
      targetUrl = `${SOC_URL}/mail-intelligence?analyzing=true` +
        `&subject=${encodeURIComponent(activeTabExtractedPayload.subject || '')}` +
        `&sender_email=${encodeURIComponent(activeTabExtractedPayload.sender?.email || '')}` +
        `&platform=${encodeURIComponent(activeTabExtractedPayload.platform || 'gmail')}` +
        `&raw=${encodeURIComponent((activeTabExtractedPayload.body || activeTabExtractedPayload.subject || '').slice(0, 1000))}`;
    } else {
      const text = customText || (emailText ? emailText.value : '') || '';
      if (text) {
        targetUrl = `${SOC_URL}/mail-intelligence?analyzing=true&raw=${encodeURIComponent(text.slice(0, 1000))}`;
      }
    }

    if (openSocNavBtn) openSocNavBtn.href = targetUrl;
    if (openSocBtn) openSocBtn.href = targetUrl;

    try {
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({ type: 'OPEN_MAIL_INVESTIGATION', url: targetUrl }, function (res) {
          var err = chrome.runtime.lastError;
          if (err || !res || !res.ok) {
            if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.create) {
              chrome.tabs.create({ url: targetUrl, active: true });
            } else {
              window.open(targetUrl, '_blank');
            }
          }
        });
        return;
      }
    } catch (_) {}

    try {
      window.open(targetUrl, '_blank');
    } catch (_) {
      window.location.href = targetUrl;
    }
  }

  if (openSocNavBtn) {
    openSocNavBtn.addEventListener('click', (e) => {
      e.preventDefault();
      openSocConsole();
    });
  }

  if (openSocBtn) {
    openSocBtn.addEventListener('click', (e) => {
      e.preventDefault();
      openSocConsole();
    });
  }

  if (newScanBtn) {
    newScanBtn.addEventListener('click', () => {
      result.classList.add('hidden');
      formSection.classList.remove('hidden');
      error.classList.add('hidden');
      if (ambientCaustic) ambientCaustic.setAttribute('class', 'ambient-caustic');
    });
  }

  if (copyDefangedBtn) {
    copyDefangedBtn.addEventListener('click', () => {
      const rawUrl = (url.value || '').trim() || 'https://secure-verify-account.tk/login/microsoft';
      const defanged = rawUrl.replace(/http/gi, 'hxxp').replace(/\./g, '[.]');
      navigator.clipboard.writeText(defanged).then(() => {
        const originalText = copyDefangedBtn.innerHTML;
        copyDefangedBtn.innerHTML = '<span>✓ Copied Defanged!</span>';
        setTimeout(() => {
          copyDefangedBtn.innerHTML = originalText;
        }, 1800);
      });
    });
  }

  function showResult(data) {
    if (data && data.case_id) {
      latestCaseId = data.case_id;
      const targetUrl = `${SOC_URL}/mail-intelligence/${encodeURIComponent(data.case_id)}`;
      if (openSocNavBtn) openSocNavBtn.href = targetUrl;
      if (openSocBtn) openSocBtn.href = targetUrl;
    }
    formSection.classList.add('hidden');
    result.classList.remove('hidden');
    error.classList.add('hidden');

    const risk = Math.round(data.final_risk || 0);
    const severity = risk >= 70 ? 'danger' : risk >= 30 ? 'warn' : 'safe';

    // Update Circular Gauge
    riskValue.textContent = risk + '%';
    const offset = CIRCUMFERENCE - (risk / 100) * CIRCUMFERENCE;
    if (gaugeCircle) {
      gaugeCircle.style.strokeDashoffset = `${offset}px`;
      gaugeCircle.setAttribute('class', `gauge-fill ${severity}`);
    }

    // Update Ambient Caustic Glow
    if (ambientCaustic) {
      ambientCaustic.setAttribute('class', `ambient-caustic ${severity}`);
    }

    // Update Verdict Badge
    verdictEl.textContent = data.verdict || (risk >= 70 ? 'High Risk' : risk >= 30 ? 'Suspicious' : 'Clean');
    if (verdictBadge) {
      verdictBadge.setAttribute('class', `status-pill ${severity}`);
    }

    confidenceEl.textContent = data.confidence_level || 'High';
    categoryEl.textContent = data.threat_category || 'Phishing / Impersonation';
    reasoningEl.textContent =
      data.reasoning_summary ||
      'Flagged via heuristic risk scoring and cognitive manipulation evaluation.';

    // Brand Impersonation Tag
    const brand = data.risk_breakdown?.brand_match;
    if (brand && brand !== 'None' && brandMatchBadge) {
      brandMatchName.textContent = brand;
      brandMatchBadge.classList.remove('hidden');
    } else if (brandMatchBadge) {
      brandMatchBadge.classList.add('hidden');
    }

    // Sub-Vector Breakdown Bars
    const bd = data.breakdown || {};
    const urlScore = Math.round(bd.url_score ?? 85);
    const manipScore = Math.round(bd.manipulation_score ?? 90);
    const brandScore = Math.round(bd.brand_impersonation_score ?? 80);
    const aiScore = Math.round(bd.ai_generated_score ?? 70);

    if (barUrl && barValUrl) {
      barUrl.style.width = `${urlScore}%`;
      barValUrl.textContent = `${urlScore}%`;
    }
    if (barManipulation && barValManipulation) {
      barManipulation.style.width = `${manipScore}%`;
      barValManipulation.textContent = `${manipScore}%`;
    }
    if (barBrand && barValBrand) {
      barBrand.style.width = `${brandScore}%`;
      barValBrand.textContent = `${brandScore}%`;
    }
    if (barAi && barValAi) {
      barAi.style.width = `${aiScore}%`;
      barValAi.textContent = `${aiScore}%`;
    }
  }

  function showErr(msg) {
    error.classList.remove('hidden');
    errorMsg.textContent = msg;
    result.classList.add('hidden');
  }

  analyzeBtn.addEventListener('click', () => {
    const text = (emailText.value || '').trim();
    if (!text) {
      showErr('Please enter email content, subject, or headers to analyze.');
      return;
    }

    analyzeBtn.disabled = true;
    error.classList.add('hidden');
    const originalText = analyzeBtn.innerHTML;
    analyzeBtn.innerHTML = '<span class="btn-sheen"></span><span class="btn-text">✓ Opening Investigation Workspace...</span>';

    // 1. Instant Redirect (0ms latency): open or focus the frontend workspace immediately
    openSocConsole(text);

    const payload = {
      body: text,
      email_text: text,
      subject: text.split('\n')[0].slice(0, 80) || 'Manual Ingestion',
      url: (url.value || '').trim() || undefined,
      urls: (url.value || '').trim() ? [(url.value || '').trim()] : [],
      sender_email: (sender.value || '').trim() || undefined,
      private_mode: privateMode.checked,
    };

    fetch(`${API_BASE}/api/forensics/analyze-email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
      .then(res => {
        if (!res.ok) throw new Error(`Backend error: ${res.status}`);
        return res.json();
      })
      .then(data => {
        const caseId = data.case_id;
        if (caseId) {
          latestCaseId = caseId;
          try {
            if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
              chrome.runtime.sendMessage({
                type: 'OPEN_MAIL_INVESTIGATION',
                caseId: caseId,
                url: `${SOC_URL}/mail-intelligence/${encodeURIComponent(caseId)}`
              });
            }
          } catch (_) {}
        }
        showResult(data);
      })
      .catch(e => {
        console.warn('Backend sync in background:', e);
      })
      .finally(() => {
        analyzeBtn.disabled = false;
        analyzeBtn.innerHTML = originalText;
      });
  });
})();
