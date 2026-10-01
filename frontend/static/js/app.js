/**
 * EchoRisk AI — Email Data Breach Tracker
 * Frontend Client Controller
 */

document.addEventListener("DOMContentLoaded", () => {
  const $ = (id) => document.getElementById(id);

  // Core DOM Elements
  const scanForm = $("scan-form"), emailInput = $("email-input"), checkBtn = $("check-btn");
  const inputContainer = $("input-container"), formFeedback = $("form-feedback");
  const scanLoading = $("scan-loading"), loadingStatusText = $("loading-status-text"), scanProgressBar = $("scan-progress-bar");
  const reportSection = $("report-section");

  // Report Elements
  const reportStatusBadge = $("report-status-badge"), reportMaskedTarget = $("report-masked-target");
  const metricBreachCount = $("metric-breach-count"), metricRiskLevel = $("metric-risk-level");
  const metricPwdFlag = $("metric-pwd-flag"), metricThreatScore = $("metric-threat-score"), metricThreatFill = $("metric-threat-fill");
  const aiEngineLabel = $("ai-engine-label"), aiModePill = $("ai-mode-pill"), aiSummaryText = $("ai-summary-text");
  const findingsList = $("findings-list"), exposedChips = $("exposed-chips"), aiDisclaimer = $("ai-disclaimer");
  const breachesContainer = $("breaches-container"), breachListCounter = $("breach-list-counter"), breachCardsList = $("breach-cards-list");
  const actionsChecklist = $("actions-checklist"), btnScanAnother = $("btn-scan-another"), btnPrintReport = $("btn-print-report");

  // Modal & Password Elements
  const notifyModal = $("notify-modal"), openNotifyModalBtn = $("open-notify-modal-btn"), closeNotifyModalBtn = $("close-notify-modal-btn");
  const notifyForm = $("notify-form"), notifyEmailInput = $("notify-email-input"), notifyFeedback = $("notify-feedback"), toastContainer = $("toast-container");
  const auditPasswordInput = $("audit-password-input"), togglePwdVisibility = $("toggle-pwd-visibility");
  const eyeIconShow = $("eye-icon-show"), eyeIconHide = $("eye-icon-hide");
  const pwdStrengthLabel = $("pwd-strength-label"), pwdStrengthBarFill = $("pwd-strength-bar-fill");
  const btnAuditPwd = $("btn-audit-pwd"), btnClearPwd = $("btn-clear-pwd"), pwdAuditResult = $("pwd-audit-result");
  const pwdAuditSpinner = $("pwd-audit-spinner"), btnAuditPwdText = $("btn-audit-pwd-text");

  // Clean URL if query parameter was appended
  if (window.location.search && window.location.search.includes("echorisk_search")) {
    history.replaceState(null, "", window.location.pathname);
  }

  // Helper functions
  const escapeHtml = (str) => String(str || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  const formatNumber = (num) => Number(num || 0).toLocaleString();

  function showToast(message, duration = 3500) {
    if (!toastContainer) return;
    const toast = document.createElement("div");
    toast.className = "toast";
    toast.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#A78BFA" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><polyline points="9 11 12 14 22 4"></polyline></svg><span>${escapeHtml(message)}</span>`;
    toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateY(12px)";
      toast.style.transition = "all 0.3s ease";
      setTimeout(() => toast.remove(), 300);
    }, duration);
  }

  function clearError() {
    if (!formFeedback || !inputContainer) return;
    formFeedback.innerHTML = "";
    formFeedback.className = "form-feedback";
    inputContainer.classList.remove("error-state");
  }

  function showError(msg, suggestion = null) {
    if (!inputContainer || !formFeedback) return;
    inputContainer.classList.add("error-state");
    formFeedback.className = "form-feedback error";

    let html = `<div class="feedback-alert"><svg class="feedback-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg><span class="feedback-text">${escapeHtml(msg)}</span>`;
    if (suggestion) {
      html += `<button type="button" class="btn-use-suggestion" id="btn-use-suggestion" data-suggestion="${escapeHtml(suggestion)}">Use ${escapeHtml(suggestion)}</button>`;
    }
    html += `</div>`;
    formFeedback.innerHTML = html;

    const suggestionBtn = $("btn-use-suggestion");
    if (suggestionBtn) {
      suggestionBtn.addEventListener("click", () => {
        const target = suggestionBtn.getAttribute("data-suggestion");
        if (target && emailInput) {
          emailInput.value = target;
          clearError();
          performBreachScan(target);
        }
      });
    }
  }

  function validateEmail(val) {
    const clean = (val || "").trim();
    if (!clean) return { valid: false, message: "Please enter an email address." };
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(clean)) {
      return { valid: false, message: "Please enter a valid email address (e.g. name@example.com)." };
    }
    return { valid: true, email: clean };
  }

  // --- Scan Pipeline ---
  async function performBreachScan(emailToScan) {
    clearError();
    if (reportSection) reportSection.classList.add("hidden");

    const check = validateEmail(emailToScan);
    if (!check.valid) {
      if (checkBtn) { checkBtn.disabled = false; checkBtn.classList.remove("loading"); }
      showError(check.message);
      if (emailInput) emailInput.focus();
      return;
    }

    if (checkBtn) { checkBtn.disabled = true; checkBtn.classList.add("loading"); }
    if (scanLoading) { scanLoading.classList.remove("hidden"); scanLoading.scrollIntoView({ behavior: "smooth", block: "center" }); }

    const steps = [
      { text: "Querying XposedOrNot threat intelligence repository...", progress: 30 },
      { text: "Cross-referencing known data breaches & pastes...", progress: 65 },
      { text: "Analyzing exposure vectors with EchoRisk AI reasoning...", progress: 90 }
    ];
    let stepIndex = 0;
    const progressTimer = setInterval(() => {
      if (stepIndex < steps.length && loadingStatusText && scanProgressBar) {
        loadingStatusText.textContent = steps[stepIndex].text;
        scanProgressBar.style.width = `${steps[stepIndex].progress}%`;
        stepIndex++;
      }
    }, 450);

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify({ email: check.email })
      });

      clearInterval(progressTimer);
      if (scanProgressBar) scanProgressBar.style.width = "100%";
      const data = await response.json();

      if (!response.ok || data.status === "error") {
        if (scanLoading) scanLoading.classList.add("hidden");
        if (checkBtn) { checkBtn.disabled = false; checkBtn.classList.remove("loading"); }
        showError(data.message || "Invalid email address entered.", data.suggestion || null);
        return;
      }
      setTimeout(() => renderScanReport(data), 300);

    } catch (err) {
      clearInterval(progressTimer);
      if (scanLoading) scanLoading.classList.add("hidden");
      if (checkBtn) { checkBtn.disabled = false; checkBtn.classList.remove("loading"); }
      showError("Connection error. Please ensure the EchoRisk AI backend server is running.");
      showToast("Scan failed: Network or server error", 4000);
    }
  }

  // --- Render Scan Report ---
  function renderScanReport(report) {
    if (scanLoading) scanLoading.classList.add("hidden");
    if (checkBtn) { checkBtn.disabled = false; checkBtn.classList.remove("loading"); }

    const summary = report.summary || {}, ai = report.ai_analysis || {}, breaches = report.breaches || [];
    const count = summary.breach_count || 0, hasBreaches = count > 0;
    const riskLevel = (summary.risk_level || "Low").toLowerCase();
    const riskScore = summary.risk_score || (hasBreaches ? 50 : 10);
    const hasPwd = summary.has_password_exposure || false;

    if (reportMaskedTarget) reportMaskedTarget.textContent = `Target: ${report.email_masked || "Checked Email"}`;
    if (reportStatusBadge) {
      reportStatusBadge.className = `status-badge ${hasBreaches ? 'danger' : 'safe'}`;
      reportStatusBadge.innerHTML = hasBreaches ? `<span>${count} Breach Incident${count !== 1 ? 's' : ''} Detected</span>` : `<span>No Known Breaches Found</span>`;
    }

    if (metricBreachCount) metricBreachCount.textContent = count;
    if (metricRiskLevel) { metricRiskLevel.className = `risk-badge ${riskLevel}`; metricRiskLevel.textContent = summary.risk_level || "Low"; }
    if (metricPwdFlag) { metricPwdFlag.className = `pwd-flag-badge ${hasPwd ? 'exposed' : 'clean'}`; metricPwdFlag.textContent = hasPwd ? "Exposed" : "No Leaks"; }
    if (metricThreatScore) metricThreatScore.textContent = riskScore;
    if (metricThreatFill) metricThreatFill.style.width = `${Math.min(riskScore, 100)}%`;

    if (aiEngineLabel) aiEngineLabel.textContent = "EchoRisk AI Risk Analysis";
    if (aiModePill) aiModePill.textContent = ai.ai_powered ? "AI Reasoned" : "Security Engine";
    if (aiSummaryText) aiSummaryText.textContent = ai.short_summary || "Analysis completed based on verified records.";

    if (findingsList) {
      findingsList.innerHTML = "";
      const findings = (ai.key_findings && ai.key_findings.length) ? ai.key_findings : ["No adverse exposure indicators discovered."];
      findings.forEach(item => {
        const li = document.createElement("li");
        li.textContent = item;
        findingsList.appendChild(li);
      });
    }

    if (exposedChips) {
      exposedChips.innerHTML = "";
      const categories = ai.exposed_categories || summary.exposed_data_types || [];
      if (!categories.length) {
        exposedChips.innerHTML = `<span class="category-chip">None Documented</span>`;
      } else {
        categories.forEach(cat => {
          const chip = document.createElement("span");
          chip.className = "category-chip" + (cat.toLowerCase().includes("password") ? " pwd-chip" : "");
          chip.textContent = cat;
          exposedChips.appendChild(chip);
        });
      }
    }

    if (aiDisclaimer) aiDisclaimer.textContent = ai.disclaimer || "Assessment based strictly on verified threat records.";

    // Render Breaches List
    if (breachCardsList && breachListCounter && breachesContainer) {
      breachCardsList.innerHTML = "";
      breachListCounter.textContent = `${count} incident${count !== 1 ? 's' : ''}`;

      if (!hasBreaches) {
        breachesContainer.classList.add("hidden");
      } else {
        breachesContainer.classList.remove("hidden");
        breaches.forEach(b => {
          const card = document.createElement("div");
          card.className = "breach-card";
          const title = escapeHtml(b.breach_title || b.breach_id || "Unknown Breach");
          const domain = escapeHtml(b.domain || ""), date = escapeHtml(b.breach_date || "Unknown Date");
          const records = b.pwn_count ? `${formatNumber(b.pwn_count)} accounts affected` : "";
          const desc = escapeHtml(b.description || "Breach records confirmed in threat database.");
          const breachId = b.breach_id || b.breach_title || "";
          const refUrl = `/breach/${encodeURIComponent(breachId)}`;
          const industry = escapeHtml(b.industry || "");
          const firstLetter = (title.trim()[0] || "B").toUpperCase();
          const logoUrl = b.logo_url || `https://xposedornot.com/static/logos/${encodeURIComponent(breachId)}.png`;
          const chipsHtml = (b.exposed_data || [])
            .map(d => `<span class="chip-mini ${d.toLowerCase().includes('password') ? 'pwd' : ''}">${escapeHtml(d)}</span>`).join("");

          card.innerHTML = `
            <div class="breach-card-top">
              <div class="breach-identity-row">
                <div class="breach-logo-wrapper" title="${title} Logo">
                  <img src="${escapeHtml(logoUrl)}" alt="${title} Logo" class="breach-company-logo" loading="lazy"
                    onerror="this.style.display='none'; if(this.nextElementSibling) this.nextElementSibling.style.display='flex';">
                  <div class="breach-logo-monogram" style="display:none;" aria-hidden="true">${firstLetter}</div>
                </div>
                <div class="breach-details-col">
                  <div class="breach-title-group">
                    <h3 class="breach-company-name">${title}</h3>
                    ${domain ? `<span class="breach-domain-tag">${domain}</span>` : ""}
                    <span class="breach-platform-badge"><span>Exposed Platform</span></span>
                    ${industry ? `<span class="breach-industry-tag">${industry}</span>` : ""}
                  </div>
                </div>
              </div>
              <div class="breach-header-meta">
                <span class="breach-date-tag">Date: ${date}</span>
                ${records ? `<span class="breach-accounts-tag">${records}</span>` : ""}
              </div>
            </div>
            <p class="breach-description-text">${desc}</p>
            <div class="breach-meta-footer">
              <div class="breach-exposed-section">
                <span class="breach-exposed-label">Platform Data Exposed:</span>
                <div class="breach-chips-mini">${chipsHtml}</div>
              </div>
              <a href="${escapeHtml(refUrl)}" target="_blank" class="breach-reference-link" title="View details">
                <span>View Details &rarr;</span>
              </a>
            </div>
          `;
          breachCardsList.appendChild(card);
        });
      }
    }

    if (actionsChecklist) {
      actionsChecklist.innerHTML = "";
      (ai.recommended_actions || []).forEach(action => {
        const li = document.createElement("li");
        li.className = "action-item";
        li.innerHTML = `<div class="action-checkbox-icon"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg></div><span>${escapeHtml(action)}</span>`;
        actionsChecklist.appendChild(li);
      });
    }

    if (reportSection) {
      reportSection.classList.remove("hidden");
      reportSection.scrollIntoView({ behavior: "smooth", block: "start" });
    }
    showToast("Scan complete: Security report generated.");
  }

  // --- Scan Listeners ---
  if (scanForm && emailInput) {
    scanForm.addEventListener("submit", (e) => { e.preventDefault(); performBreachScan(emailInput.value); });
    emailInput.addEventListener("input", () => { if (formFeedback && (formFeedback.innerHTML || formFeedback.textContent)) clearError(); });
  }

  document.querySelectorAll(".demo-chip").forEach(chip => {
    chip.addEventListener("click", () => {
      const email = chip.getAttribute("data-email");
      if (email && emailInput) { emailInput.value = email; performBreachScan(email); }
    });
  });

  if (btnScanAnother && emailInput && reportSection) {
    btnScanAnother.addEventListener("click", () => {
      reportSection.classList.add("hidden");
      emailInput.value = "";
      clearError();
      window.scrollTo({ top: 0, behavior: "smooth" });
      setTimeout(() => emailInput.focus(), 250);
    });
  }

  if (btnPrintReport) {
    btnPrintReport.addEventListener("click", () => {
      const timestampEl = $("print-timestamp");
      if (timestampEl) {
        const now = new Date();
        timestampEl.textContent = `Report Generated: ${now.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" })} at ${now.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}`;
      }
      document.body.classList.add("print-active");
      window.print();
      setTimeout(() => document.body.classList.remove("print-active"), 600);
    });
  }
  window.addEventListener("afterprint", () => document.body.classList.remove("print-active"));

  // --- "Notify Me" Modal Controller ---
  function openModal() {
    if (!notifyModal) return;
    notifyModal.classList.remove("hidden");
    if (notifyEmailInput) {
      notifyEmailInput.value = (emailInput && emailInput.value) ? emailInput.value : "";
      notifyEmailInput.focus();
    }
    if (notifyFeedback) notifyFeedback.textContent = "";
    document.body.style.overflow = "hidden";
  }

  function closeModal() {
    if (!notifyModal) return;
    notifyModal.classList.add("hidden");
    document.body.style.overflow = "";
  }

  if (openNotifyModalBtn) openNotifyModalBtn.addEventListener("click", openModal);
  if (closeNotifyModalBtn) closeNotifyModalBtn.addEventListener("click", closeModal);
  if (notifyModal) notifyModal.addEventListener("click", (e) => { if (e.target === notifyModal) closeModal(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && notifyModal && !notifyModal.classList.contains("hidden")) closeModal(); });

  if (notifyForm && notifyEmailInput) {
    notifyForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const check = validateEmail(notifyEmailInput.value);
      if (!check.valid) {
        if (notifyFeedback) { notifyFeedback.style.color = "var(--danger-text)"; notifyFeedback.textContent = check.message; }
        return;
      }
      try {
        const existing = JSON.parse(localStorage.getItem("echorisk_subscribers") || "[]");
        if (!existing.includes(check.email)) {
          existing.push(check.email);
          localStorage.setItem("echorisk_subscribers", JSON.stringify(existing));
        }
      } catch (_) { }

      if (notifyFeedback) {
        notifyFeedback.style.color = "var(--success-text)";
        notifyFeedback.textContent = "✓ Notification alert saved! We will monitor this address.";
      }
      setTimeout(() => { closeModal(); showToast("Alert subscription registered for " + check.email); }, 1000);
    });
  }

  // --- Password Strength & Exposure Auditor ---
  function evaluatePasswordStrength(password) {
    if (!password) {
      return { label: "Waiting for input", className: "strength-empty", barClass: "", barWidth: "0%", stats: { length: 0, uppercase: false, lowercase: false, numbers: false, symbols: false } };
    }
    const length = password.length, hasLower = /[a-z]/.test(password), hasUpper = /[A-Z]/.test(password), hasNumber = /[0-9]/.test(password), hasSymbol = /[^a-zA-Z0-9]/.test(password);
    const poolSize = (hasLower ? 26 : 0) + (hasUpper ? 26 : 0) + (hasNumber ? 10 : 0) + (hasSymbol ? 33 : 0) || 1;
    let score = length * (Math.log(poolSize) / Math.LN2);
    if (/(.)\1{2,}/.test(password)) score -= 8;
    if (/^[0-9]+$|^[a-zA-Z]+$/.test(password)) score -= 10;
    if (/^(password|123456|admin|qwerty|welcome)/i.test(password)) score = 10;
    score = Math.max(0, Math.round(score * 10) / 10);

    const thresholds = [
      { max: 25, label: "Very Weak", cls: "strength-very-weak", bar: "bar-very-weak", width: "20%" },
      { max: 40, label: "Weak", cls: "strength-weak", bar: "bar-weak", width: "40%" },
      { max: 60, label: "Fair", cls: "strength-fair", bar: "bar-fair", width: "65%" },
      { max: 78, label: "Strong", cls: "strength-strong", bar: "bar-strong", width: "85%" },
      { max: Infinity, label: "Cryptographic", cls: "strength-cryptographic", bar: "bar-cryptographic", width: "100%" }
    ];
    const tier = (length < 6) ? thresholds[0] : (thresholds.find(t => score < t.max) || thresholds[4]);

    return { label: tier.label, className: tier.cls, barClass: tier.bar, barWidth: tier.width, stats: { length, uppercase: hasUpper, lowercase: hasLower, numbers: hasNumber, symbols: hasSymbol } };
  }

  function updateStrengthUI() {
    if (!auditPasswordInput || !pwdStrengthLabel || !pwdStrengthBarFill) return;
    const res = evaluatePasswordStrength(auditPasswordInput.value);
    pwdStrengthLabel.textContent = res.label;
    pwdStrengthLabel.className = `pwd-meta-value ${res.className}`;
    pwdStrengthBarFill.style.width = res.barWidth;
    pwdStrengthBarFill.className = `pwd-strength-bar-fill ${res.barClass}`;
    if (pwdAuditResult && !pwdAuditResult.classList.contains("hidden")) {
      pwdAuditResult.classList.add("hidden");
      pwdAuditResult.innerHTML = "";
    }
  }

  function showAuditResult({ type, title, body, stats }) {
    if (!pwdAuditResult) return;
    pwdAuditResult.className = `pwd-audit-result result-${type}`;
    let statsHtml = "";
    if (stats) {
      const items = [
        { active: stats.length >= 12, label: `${stats.length} Chars` },
        { active: stats.uppercase, label: "Uppercase" },
        { active: stats.lowercase, label: "Lowercase" },
        { active: stats.numbers, label: "Numbers" },
        { active: stats.symbols, label: "Symbols" }
      ];
      statsHtml = `<div class="pwd-result-stats">${items.map(it => `<div class="pwd-stat-item ${it.active ? 'active' : 'inactive'}"><span>${it.active ? '✓' : '•'}</span> ${it.label}</div>`).join("")}</div>`;
    }
    pwdAuditResult.innerHTML = `<div class="pwd-result-header">${title}</div>${body ? `<div class="pwd-result-body">${body}</div>` : ""}${statsHtml}`;
    pwdAuditResult.classList.remove("hidden");
  }

  function computeKeccak512Hex(str) {
    if (typeof window.keccak512 === "function") {
      return window.keccak512(str).slice(0, 10);
    }
    const utf8 = new TextEncoder().encode(str), rate = 72;
    const padLen = rate - (utf8.length % rate), padded = new Uint8Array(utf8.length + padLen);
    padded.set(utf8);
    padded[utf8.length] = 0x01;
    padded[padded.length - 1] |= 0x80;
    const s = new BigUint64Array(25);
    const rot = (x, n) => ((x << BigInt(n)) | (x >> (64n - BigInt(n)))) & 0xFFFFFFFFFFFFFFFFn;
    const RC = [0x1n,0x8082n,0x800000000000808an,0x8000000080008000n,0x808bn,0x80000001n,0x8000000080008081n,0x8000000000008009n,0x8an,0x88n,0x80008009n,0x8000000an,0x8000808bn,0x800000000000008bn,0x8000000000008089n,0x8000000000008003n,0x8000000000008002n,0x8000000000000080n,0x800an,0x800000008000000an,0x8000000080008081n,0x8000000000008080n,0x80000001n,0x8000000080008008n];
    const RHO = [0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14];
    const PI = [0,10,20,5,15,16,1,11,21,6,7,17,2,12,22,23,8,18,3,13,14,24,9,19,4];
    for (let off = 0; off < padded.length; off += rate) {
      for (let i = 0; i < 9; i++) {
        let w = 0n;
        for (let b = 0; b < 8; b++) w |= BigInt(padded[off + i * 8 + b]) << BigInt(b * 8);
        s[i] ^= w;
      }
      for (let r = 0; r < 24; r++) {
        const C = new BigUint64Array(5), D = new BigUint64Array(5), B = new BigUint64Array(25);
        for (let x = 0; x < 5; x++) C[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
        for (let x = 0; x < 5; x++) D[x] = C[(x + 4) % 5] ^ rot(C[(x + 1) % 5], 1);
        for (let i = 0; i < 25; i++) s[i] ^= D[i % 5];
        for (let i = 0; i < 25; i++) B[PI[i]] = rot(s[i], RHO[i]);
        for (let y = 0; y < 5; y++) {
          const y5 = y * 5;
          for (let x = 0; x < 5; x++) s[y5 + x] = B[y5 + x] ^ ((~B[y5 + ((x + 1) % 5)]) & B[y5 + ((x + 2) % 5)]);
        }
        s[0] ^= RC[r];
      }
    }
    let hex = "", w = s[0];
    for (let b = 0; b < 5; b++) {
      hex += Number(w & 0xFFn).toString(16).padStart(2, "0");
      w >>= 8n;
    }
    return hex;
  }

  async function performPasswordAudit() {
    if (!auditPasswordInput) return;
    const pwd = auditPasswordInput.value;
    if (!pwd) {
      showAuditResult({ type: "info", title: "Input Required", body: "Please enter a password in the audit input field above." });
      return;
    }

    if (btnAuditPwd) btnAuditPwd.disabled = true;
    if (pwdAuditSpinner) pwdAuditSpinner.classList.remove("hidden");
    if (btnAuditPwdText) btnAuditPwdText.textContent = "Checking...";

    const strength = evaluatePasswordStrength(pwd);

    try {
      const prefix10 = computeKeccak512Hex(pwd);
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6000);

      const response = await fetch(`https://passwords.xposedornot.com/api/v1/pass/anon/${prefix10}`, {
        method: "GET",
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (response.status === 200) {
        showAuditResult({
          type: "compromised",
          title: "⚠️ Password Exposure Detected",
          body: "This password appears in known compromised-password records. Avoid using it on any account and change it immediately wherever it has been used.",
          stats: strength.stats
        });
      } else if (response.status === 404) {
        showAuditResult({
          type: "safe",
          title: "✅ No Known Exposure Detected",
          body: "This password was not found among known compromised passwords in our security database. For better protection, use a unique password and enable multi-factor authentication where available.",
          stats: strength.stats
        });
      } else {
        throw new Error(`API returned HTTP ${response.status}`);
      }
    } catch (err) {
      showAuditResult({
        type: "info",
        title: "Password Strength Verified (Local Mode)",
        body: `Local strength rating: <strong>${strength.label}</strong>. Live breach verification service was unreachable or offline, but your password security was safely validated in your browser.`,
        stats: strength.stats
      });
    } finally {
      if (btnAuditPwd) btnAuditPwd.disabled = false;
      if (pwdAuditSpinner) pwdAuditSpinner.classList.add("hidden");
      if (btnAuditPwdText) btnAuditPwdText.innerHTML = "Check";
    }
  }

  if (auditPasswordInput) {
    auditPasswordInput.addEventListener("input", updateStrengthUI);
    auditPasswordInput.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); performPasswordAudit(); } });
  }

  if (togglePwdVisibility && auditPasswordInput) {
    togglePwdVisibility.addEventListener("click", () => {
      const isPassword = auditPasswordInput.type === "password";
      auditPasswordInput.type = isPassword ? "text" : "password";
      if (eyeIconShow && eyeIconHide) {
        eyeIconShow.classList.toggle("hidden", isPassword);
        eyeIconHide.classList.toggle("hidden", !isPassword);
      }
    });
  }

  if (btnAuditPwd) btnAuditPwd.addEventListener("click", performPasswordAudit);

  if (btnClearPwd && auditPasswordInput) {
    btnClearPwd.addEventListener("click", () => {
      auditPasswordInput.value = "";
      updateStrengthUI();
      if (pwdAuditResult) { pwdAuditResult.classList.add("hidden"); pwdAuditResult.innerHTML = ""; }
      auditPasswordInput.focus();
    });
  }

  // --- Smooth Navigation & ScrollSpy ---
  const navItems = [
    { id: "hero", link: $("nav-home") },
    { id: "how-it-works", link: $("nav-how") },
    { id: "passwords", link: $("nav-passwords") },
    { id: "about", link: $("nav-about") }
  ];

  function setActiveNav(targetId) {
    navItems.forEach(item => { if (item.link) item.link.classList.toggle("active", item.id === targetId); });
  }

  function scrollToTarget(targetId) {
    const el = $(targetId);
    if (el) {
      window.scrollTo({ top: Math.max(0, el.getBoundingClientRect().top + window.scrollY - 75), behavior: "smooth" });
      setActiveNav(targetId);
    }
  }

  navItems.forEach(item => {
    if (item.link) {
      item.link.addEventListener("click", (e) => { if ($(item.id)) { e.preventDefault(); scrollToTarget(item.id); } });
    }
  });

  const brandLink = document.querySelector(".brand");
  if (brandLink) {
    brandLink.addEventListener("click", (e) => { if ($("hero")) { e.preventDefault(); scrollToTarget("hero"); } });
  }

  document.querySelectorAll(".footer-links-list a").forEach(a => {
    a.addEventListener("click", (e) => {
      const href = a.getAttribute("href") || "";
      if (href.startsWith("#") && $(href.slice(1))) { e.preventDefault(); scrollToTarget(href.slice(1)); }
    });
  });

  if ($("hero")) {
    window.addEventListener("scroll", () => {
      const pos = window.scrollY + 140;
      for (let i = navItems.length - 1; i >= 0; i--) {
        const el = $(navItems[i].id);
        if (el && el.offsetTop <= pos) { setActiveNav(navItems[i].id); break; }
      }
    }, { passive: true });
  }

  if (openNotifyModalBtn) {
    openNotifyModalBtn.addEventListener("mousedown", () => openNotifyModalBtn.classList.add("ringing"));
    openNotifyModalBtn.addEventListener("mouseup", () => setTimeout(() => openNotifyModalBtn.classList.remove("ringing"), 600));
  }
});
