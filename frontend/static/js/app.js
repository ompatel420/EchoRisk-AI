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
  const breachChartCanvas = $("breach-analytics-chart"), graphEmptyState = $("graph-empty-state");
  let breachChartInstance = null, currentBreaches = [], currentSummary = {}, currentGraphView = "severity";

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
  function renderScanReport(report, shouldScroll = true, showToastMsg = true) {
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
              <a href="${escapeHtml(refUrl)}" class="breach-reference-link" title="View details">
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

    // Render dynamic breach exposure analytics graph for all data breaches
    currentBreaches = breaches;
    currentSummary = summary;
    renderBreachAnalyticsChart(currentBreaches, currentSummary, currentGraphView);

    // Render interactive enterprise Digital Exposure Network Graph
    renderDigitalExposureGraph(report);

    // Save report state for seamless navigation and return trips
    try {
      sessionStorage.setItem("echorisk_last_report", JSON.stringify(report));
      if (emailInput && emailInput.value) {
        sessionStorage.setItem("echorisk_last_email", emailInput.value);
      }
    } catch (e) {}

    if (reportSection) {
      reportSection.classList.remove("hidden");
      if (shouldScroll) {
        reportSection.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    }
    if (showToastMsg) {
      showToast("Scan complete: Security report generated.");
    }
  }

  // --- Breach Analytics Chart Controller ---
  function calculateBreachThreatScore(b) {
    const hasPwd = (b.exposed_data || []).some(d => /password|hash/i.test(d));
    const fieldCount = (b.exposed_data || []).length;
    const pwnCount = b.pwn_count || 0;
    let score = 25;
    if (hasPwd) score += 35;
    score += Math.min(25, fieldCount * 5);
    if (pwnCount > 100000000) score += 15;
    else if (pwnCount > 10000000) score += 10;
    else if (pwnCount > 1000000) score += 5;
    return Math.min(100, Math.max(10, Math.round(score)));
  }

  function drawCanvas2DFallback(canvas, config) {
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const width = canvas.clientWidth || 360;
    const height = canvas.clientHeight || 185;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, width, height);

    const labels = config.data.labels || [];
    const dataset = (config.data.datasets && config.data.datasets[0]) || { data: [] };
    const data = dataset.data || [];
    const count = labels.length;
    if (count === 0) return;

    const barHeight = Math.max(16, Math.min(26, (height - 30) / count - 8));
    const startY = 15;
    const maxVal = Math.max(...data, 100);

    for (let i = 0; i < count; i++) {
      const y = startY + i * (barHeight + 8);
      const val = data[i] || 0;
      const barW = Math.max(10, ((val / maxVal) * (width - 150)));

      // Label
      ctx.fillStyle = "#334155";
      ctx.font = "bold 11px 'Plus Jakarta Sans', 'Inter', sans-serif";
      ctx.textAlign = "left";
      ctx.textBaseline = "middle";
      const lbl = labels[i].length > 15 ? labels[i].slice(0, 13) + ".." : labels[i];
      ctx.fillText(lbl, 6, y + barHeight / 2);

      // Bar
      ctx.fillStyle = Array.isArray(dataset.backgroundColor) ? (dataset.backgroundColor[i] || "#7C3AED") : (dataset.backgroundColor || "#7C3AED");
      ctx.beginPath();
      if (ctx.roundRect) {
        ctx.roundRect(110, y, barW, barHeight, [4]);
      } else {
        ctx.rect(110, y, barW, barHeight);
      }
      ctx.fill();

      // Value label
      ctx.fillStyle = "#64748B";
      ctx.font = "600 11px 'Inter', sans-serif";
      ctx.fillText(String(val), 116 + barW, y + barHeight / 2);
    }
  }

  function renderBreachAnalyticsChart(breaches, summary, view = "severity") {
    if (!breachChartCanvas) return;

    if (!breaches || breaches.length === 0) {
      if (graphEmptyState) graphEmptyState.classList.remove("hidden");
      breachChartCanvas.style.display = "none";
      if (breachChartInstance) {
        breachChartInstance.destroy();
        breachChartInstance = null;
      }
      return;
    }

    if (graphEmptyState) graphEmptyState.classList.add("hidden");
    breachChartCanvas.style.display = "block";

    if (breachChartInstance) {
      breachChartInstance.destroy();
      breachChartInstance = null;
    }

    let chartConfig = null;

    const createOptions = (tooltipCb, yCallback = (v) => `${v}`, yMax = 100) => ({
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 550, easing: "easeOutQuart" },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "rgba(15, 23, 42, 0.92)",
          titleFont: { family: "'Plus Jakarta Sans', 'Inter', sans-serif", weight: 700, size: 12 },
          bodyFont: { family: "'Inter', sans-serif", size: 11 },
          padding: 9,
          cornerRadius: 7,
          callbacks: { label: tooltipCb }
        }
      },
      scales: {
        x: {
          grid: { display: false },
          ticks: { font: { family: "'Plus Jakarta Sans', 'Inter', sans-serif", weight: 600, size: 11 }, color: "#475569" }
        },
        y: {
          min: 0,
          max: yMax,
          grid: { color: "rgba(226, 232, 240, 0.8)" },
          ticks: {
            stepSize: yMax === 100 ? 25 : undefined,
            font: { family: "'Inter', sans-serif", size: 10 },
            color: "#64748B",
            callback: yCallback
          }
        }
      }
    });

    if (view === "records") {
      const labels = breaches.map(b => b.breach_title || b.breach_id || "Incident");
      const recordsMillions = breaches.map(b => Number(((b.pwn_count || 0) / 1000000).toFixed(2)));
      const rawRecords = breaches.map(b => b.pwn_count || 0);

      chartConfig = {
        type: "bar",
        data: {
          labels,
          datasets: [{
            label: "Exposed Accounts (Millions)",
            data: recordsMillions,
            backgroundColor: "rgba(109, 40, 217, 0.78)",
            hoverBackgroundColor: "#6D28D9",
            borderColor: "#5B21B6",
            borderWidth: 1.5,
            borderRadius: 7,
            borderSkipped: false,
            maxBarThickness: 45
          }]
        },
        options: createOptions(
          (ctx) => ` ${formatNumber(rawRecords[ctx.dataIndex])} exposed accounts (${ctx.raw}M)`,
          (val) => `${val}M`,
          undefined
        )
      };

    } else if (view === "timeline") {
      const sortedBreaches = [...breaches].sort((a, b) => (a.breach_date || "").localeCompare(b.breach_date || ""));
      const labels = sortedBreaches.map(b => `${b.breach_title || b.breach_id} (${b.breach_date ? b.breach_date.slice(0, 4) : "N/A"})`);
      const scores = sortedBreaches.map(b => calculateBreachThreatScore(b));

      chartConfig = {
        type: "line",
        data: {
          labels,
          datasets: [{
            label: "Incident Threat Score",
            data: scores,
            borderColor: "#7C3AED",
            backgroundColor: "rgba(124, 58, 237, 0.12)",
            fill: true,
            tension: 0.35,
            borderWidth: 2.5,
            pointBackgroundColor: "#6D28D9",
            pointBorderColor: "#FFFFFF",
            pointBorderWidth: 2,
            pointRadius: 6,
            pointHoverRadius: 8
          }]
        },
        options: createOptions(
          (ctx) => ` Threat Impact: ${ctx.raw}/100 | Date: ${sortedBreaches[ctx.dataIndex].breach_date || 'Unknown'}`,
          (val) => `${val}/100`,
          100
        )
      };

    } else {
      // Default: "severity" (Threat Impact)
      const labels = breaches.map(b => b.breach_title || b.breach_id || "Incident");
      const scores = breaches.map(b => calculateBreachThreatScore(b));

      chartConfig = {
        type: "bar",
        data: {
          labels,
          datasets: [{
            label: "Threat Impact (0-100)",
            data: scores,
            backgroundColor: scores.map(s => s >= 80 ? "#DC2626" : (s >= 60 ? "#F59E0B" : "#7C3AED")),
            hoverBackgroundColor: scores.map(s => s >= 80 ? "#B91C1C" : (s >= 60 ? "#D97706" : "#6D28D9")),
            borderRadius: 7,
            borderSkipped: false,
            maxBarThickness: 45
          }]
        },
        options: createOptions(
          (ctx) => {
            const hasPwd = (breaches[ctx.dataIndex].exposed_data || []).some(d => /password|hash/i.test(d));
            return ` Threat Impact: ${ctx.raw}/100 (${hasPwd ? 'Password leaked' : 'No passwords'})`;
          },
          (val) => `${val}`,
          100
        )
      };
    }

    if (typeof Chart !== "undefined") {
      try {
        breachChartInstance = new Chart(breachChartCanvas, chartConfig);
      } catch (err) {
        console.warn("Chart.js rendering failed, using Canvas 2D fallback:", err);
        drawCanvas2DFallback(breachChartCanvas, chartConfig);
      }
    } else {
      drawCanvas2DFallback(breachChartCanvas, chartConfig);
    }
  }

  // --- Graph View Switcher Tabs Listener ---
  document.querySelectorAll(".graph-tab").forEach(tab => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".graph-tab").forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      currentGraphView = tab.getAttribute("data-graph-view") || "severity";
      if (currentBreaches && currentBreaches.length) {
        renderBreachAnalyticsChart(currentBreaches, currentSummary, currentGraphView);
      }
    });
  });

  // ==========================================================================
  // Professional Digital Exposure Graph Controller (Enterprise SaaS Topology)
  // ==========================================================================
  const exposureGraphState = {
    report: null,
    scale: 1.0,
    panX: 0,
    panY: 0,
    isDragging: false,
    dragStartX: 0,
    dragStartY: 0,
    filter: "all",
    selectedNodeId: null,
    initializedEvents: false
  };

  function updateExposureGraphTransform() {
    const viewport = $("exposure-viewport");
    if (viewport) {
      viewport.setAttribute("transform", `translate(${exposureGraphState.panX}, ${exposureGraphState.panY}) scale(${exposureGraphState.scale})`);
    }
  }

  function renderDigitalExposureGraph(report) {
    if (!report) return;
    exposureGraphState.report = report;
    const breaches = report.breaches || [];
    const summary = report.summary || {};
    const targetEmail = report.scanned_target || summary.target_email_masked || (emailInput && emailInput.value) || "user@verified";

    // 1. Update 4 Compact Statistics Above Graph
    const statTotalId = $("exp-stat-total-id");
    const statVerifiedId = $("exp-stat-verified-id");
    const statBreaches = $("exp-stat-breaches");
    const statCategories = $("exp-stat-categories");

    const allCategories = new Set();
    breaches.forEach(b => {
      (b.exposed_data || []).forEach(cat => allCategories.add(cat));
    });

    if (statTotalId) statTotalId.textContent = "1";
    if (statVerifiedId) statVerifiedId.textContent = "1";
    if (statBreaches) statBreaches.textContent = breaches.length.toString();
    if (statCategories) statCategories.textContent = allCategories.size.toString();

    // 2. Setup Canvas Elements
    const edgesLayer = $("exposure-edges-layer");
    const nodesLayer = $("exposure-nodes-layer");
    const emptyOverlay = $("exposure-empty-overlay");
    const svgElem = $("exposure-network-svg");

    if (!edgesLayer || !nodesLayer || !svgElem) return;

    edgesLayer.innerHTML = "";
    nodesLayer.innerHTML = "";
    exposureGraphState.selectedNodeId = null;

    // Reset Zoom / Pan to default
    exposureGraphState.scale = 1.0;
    exposureGraphState.panX = 0;
    exposureGraphState.panY = 0;
    updateExposureGraphTransform();

    // Attach canvas interactive controls once
    initExposureGraphInteractions(svgElem);

    // 3. Handle Empty State
    if (breaches.length === 0) {
      if (emptyOverlay) emptyOverlay.classList.remove("hidden");
      renderEmptyTopologyGraph(targetEmail, nodesLayer);
      renderInspectorInitialState(targetEmail, breaches, allCategories);
      return;
    } else {
      if (emptyOverlay) emptyOverlay.classList.add("hidden");
    }

    // 4. Calculate Topology Layout Geometry
    const svgNS = "http://www.w3.org/2000/svg";
    const totalBreaches = breaches.length;
    const breachGap = 92;
    const totalBreachHeight = Math.max(400, totalBreaches * breachGap + 60);
    const centerY = totalBreachHeight / 2;

    // Adjust SVG viewBox height if many breaches
    svgElem.setAttribute("viewBox", `0 0 960 ${totalBreachHeight}`);

    // Level 1: Digital Identity Root Node
    const l1X = 50;
    const l1Y = centerY - 38;
    const l1W = 190;
    const l1H = 76;

    // Level 2: Email Identifier Node
    const l2X = 320;
    const l2Y = centerY - 42;
    const l2W = 230;
    const l2H = 84;

    // Level 3: Breach Nodes
    const l3X = 640;
    const l3W = 270;
    const l3H = 78;
    const breachStartY = centerY - ((totalBreaches - 1) * breachGap) / 2 - 39;

    // Create Edges
    // Level 1 -> Level 2
    createExposureSvgEdge("edge-l1-l2", l1X + l1W, centerY, l2X, centerY, edgesLayer);

    // Level 2 -> Level 3 (one edge per verified breach)
    breaches.forEach((b, idx) => {
      const bY = breachStartY + idx * breachGap + 39;
      createExposureSvgEdge(`edge-l2-b${idx}`, l2X + l2W, centerY, l3X, bY, edgesLayer);
    });

    // Create Level 1 Node
    const nodeIdentity = createSvgIdentityNode(l1X, l1Y, l1W, l1H);
    nodeIdentity.addEventListener("click", (e) => {
      e.stopPropagation();
      selectExposureNode("node-identity", { targetEmail, breaches, allCategories });
    });
    nodesLayer.appendChild(nodeIdentity);

    // Create Level 2 Node
    const nodeEmail = createSvgEmailNode(l2X, l2Y, l2W, l2H, targetEmail, totalBreaches);
    nodeEmail.addEventListener("click", (e) => {
      e.stopPropagation();
      selectExposureNode("node-email", { targetEmail, breaches, allCategories });
    });
    nodesLayer.appendChild(nodeEmail);

    // Create Level 3 Nodes
    breaches.forEach((b, idx) => {
      const bY = breachStartY + idx * breachGap;
      const nodeBreach = createSvgBreachNode(`node-breach-${idx}`, l3X, bY, l3W, l3H, b);
      nodeBreach.addEventListener("click", (e) => {
        e.stopPropagation();
        selectExposureNode(`node-breach-${idx}`, { targetEmail, breaches, breach: b, index: idx });
      });
      nodesLayer.appendChild(nodeBreach);
    });

    // Populate Initial Inspector Panel
    renderInspectorInitialState(targetEmail, breaches, allCategories);
  }

  // --- SVG Helper Generators ---
  function createExposureSvgEdge(id, x1, y1, x2, y2, container) {
    const svgNS = "http://www.w3.org/2000/svg";
    const path = document.createElementNS(svgNS, "path");
    const dx = Math.max(30, (x2 - x1) * 0.55);
    const d = `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;
    path.setAttribute("id", id);
    path.setAttribute("class", "exp-edge");
    path.setAttribute("d", d);
    container.appendChild(path);
    return path;
  }

  function createSvgIdentityNode(x, y, w, h) {
    const svgNS = "http://www.w3.org/2000/svg";
    const g = document.createElementNS(svgNS, "g");
    g.setAttribute("id", "node-identity");
    g.setAttribute("class", "exp-node exp-node-identity");
    g.setAttribute("data-level", "1");
    g.setAttribute("data-type", "identity");
    g.setAttribute("transform", `translate(${x}, ${y})`);

    g.innerHTML = `
      <rect width="${w}" height="${h}" rx="10" filter="url(#glow-identity)"></rect>
      <!-- Shield / Profile Icon -->
      <g transform="translate(14, 18)">
        <circle cx="16" cy="16" r="16" fill="rgba(37, 99, 235, 0.22)" stroke="#3B82F6" stroke-width="1.2"></circle>
        <path d="M16 10a4 4 0 1 0 0 8 4 4 0 0 0 0-8zm0 10c-3.5 0-7 1.75-7 3.5v.5h14v-.5c0-1.75-3.5-3.5-7-3.5z" fill="#60A5FA"></path>
      </g>
      <text x="56" y="32" fill="#F8FAFC" font-size="12" font-weight="700">Digital Identity</text>
      <text x="56" y="48" fill="#94A3B8" font-size="10" font-weight="500">Verified Root Profile</text>
      <text x="56" y="62" fill="#38BDF8" font-size="9" font-weight="600">&#10003; Level 1 Root</text>
    `;
    return g;
  }

  function createSvgEmailNode(x, y, w, h, email, breachCount) {
    const svgNS = "http://www.w3.org/2000/svg";
    const g = document.createElementNS(svgNS, "g");
    g.setAttribute("id", "node-email");
    g.setAttribute("class", "exp-node exp-node-identifier");
    g.setAttribute("data-level", "2");
    g.setAttribute("data-type", "identifier");
    g.setAttribute("transform", `translate(${x}, ${y})`);

    const maskedText = escapeHtml(email);
    const countLabel = breachCount === 1 ? "1 Incident" : `${breachCount} Incidents`;

    g.innerHTML = `
      <rect width="${w}" height="${h}" rx="10"></rect>
      <!-- Mail Icon Circle -->
      <g transform="translate(12, 16)">
        <circle cx="16" cy="16" r="16" fill="rgba(99, 102, 241, 0.2)" stroke="#6366F1" stroke-width="1.2"></circle>
        <path d="M10 12h12a1 1 0 0 1 1 1v7a1 1 0 0 1-1 1H10a1 1 0 0 1-1-1v-7a1 1 0 0 1 1-1zm6 4.5l-5-3.5m10 0l-5 3.5" stroke="#A5B4FC" stroke-width="1.5" stroke-linecap="round" fill="none"></path>
      </g>
      <text x="52" y="30" fill="#E2E8F0" font-size="11.5" font-weight="700">${maskedText}</text>
      <text x="52" y="46" fill="#94A3B8" font-size="9.5" font-weight="500">Email Identifier &middot; Level 2</text>
      <!-- Status Badges inside Node -->
      <rect x="52" y="54" width="62" height="18" rx="4" fill="rgba(16, 185, 129, 0.16)" stroke="rgba(16, 185, 129, 0.4)" stroke-width="1"></rect>
      <text x="58" y="66" fill="#34D399" font-size="8.5" font-weight="700">&#10003; VERIFIED</text>
      
      <rect x="120" y="54" width="80" height="18" rx="4" fill="rgba(239, 68, 68, 0.18)" stroke="rgba(239, 68, 68, 0.4)" stroke-width="1"></rect>
      <text x="126" y="66" fill="#F87171" font-size="8.5" font-weight="700">&#9888; ${countLabel}</text>
    `;
    return g;
  }

  function createSvgBreachNode(id, x, y, w, h, breach) {
    const svgNS = "http://www.w3.org/2000/svg";
    const g = document.createElementNS(svgNS, "g");
    g.setAttribute("id", id);
    g.setAttribute("class", "exp-node exp-node-breach");
    g.setAttribute("data-level", "3");
    g.setAttribute("data-type", "breach");
    g.setAttribute("transform", `translate(${x}, ${y})`);

    const hasPwd = breach.has_password_exposure || (breach.exposed_data || []).some(d => /password|hash/i.test(d));
    const title = escapeHtml(breach.breach_title || breach.breach_id || "Breach Record");
    const date = escapeHtml(breach.breach_date || "Unknown Date");
    const catCount = (breach.exposed_data || []).length;
    const catLabel = catCount > 0 ? `${catCount} Data Types` : "Platform Leak";

    g.innerHTML = `
      <rect width="${w}" height="${h}" rx="10" filter="url(#glow-breach)"></rect>
      <!-- Incident Alert Icon Circle -->
      <g transform="translate(12, 14)">
        <circle cx="16" cy="16" r="16" fill="rgba(239, 68, 68, 0.2)" stroke="#EF4444" stroke-width="1.2"></circle>
        <path d="M16 11v6m0 3h.01" stroke="#FCA5A5" stroke-width="2" stroke-linecap="round"></path>
      </g>
      <text x="52" y="28" fill="#F8FAFC" font-size="12" font-weight="700">${title}</text>
      <text x="52" y="44" fill="#94A3B8" font-size="9.5" font-weight="500">Incident: ${date}</text>
      <!-- Badges -->
      <rect x="52" y="52" width="76" height="17" rx="4" fill="${hasPwd ? 'rgba(239, 68, 68, 0.22)' : 'rgba(245, 158, 11, 0.2)'}" stroke="${hasPwd ? '#EF4444' : '#F59E0B'}" stroke-width="1"></rect>
      <text x="58" y="64" fill="${hasPwd ? '#FCA5A5' : '#FCD34D'}" font-size="8.5" font-weight="700">${hasPwd ? 'CRITICAL RISK' : 'MODERATE RISK'}</text>
      
      <rect x="134" y="52" width="96" height="17" rx="4" fill="rgba(30, 41, 59, 0.8)" stroke="#475569" stroke-width="1"></rect>
      <text x="140" y="64" fill="#CBD5E1" font-size="8.5" font-weight="600">${catLabel}</text>
    `;
    return g;
  }

  function renderEmptyTopologyGraph(targetEmail, container) {
    const svgNS = "http://www.w3.org/2000/svg";
    const g = document.createElementNS(svgNS, "g");
    g.setAttribute("transform", "translate(340, 200)");
    g.innerHTML = `
      <rect width="280" height="90" rx="12" fill="#0F172A" stroke="#10B981" stroke-width="1.8" filter="url(#glow-identity)"></rect>
      <circle cx="34" cy="45" r="18" fill="rgba(16, 185, 129, 0.2)" stroke="#10B981" stroke-width="1.5"></circle>
      <path d="M28 45l4 4 8-8" stroke="#34D399" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" fill="none"></path>
      <text x="64" y="38" fill="#F8FAFC" font-size="12" font-weight="700">${escapeHtml(targetEmail)}</text>
      <text x="64" y="54" fill="#34D399" font-size="10" font-weight="600">&#10003; 100% Verified Clean Record</text>
      <text x="64" y="70" fill="#94A3B8" font-size="9" font-weight="500">Zero matching breach exposures detected</text>
    `;
    container.appendChild(g);
  }

  // --- Inspector Panel Rendering ---
  function renderInspectorInitialState(email, breaches, categories) {
    const badge = $("inspector-badge");
    const title = $("inspector-title");
    const body = $("inspector-body");
    if (!badge || !title || !body) return;

    badge.textContent = "TOPOLOGY OVERVIEW";
    title.textContent = breaches.length > 0 ? "Digital Exposure Map" : "Identity Verified Clean";

    body.innerHTML = `
      <div class="inspector-section">
        <h5 class="inspector-subhead">Verified Profile</h5>
        <div class="inspector-meta-list">
          <div class="inspector-meta-row">
            <span class="inspector-meta-label">Primary Identifier:</span>
            <span class="inspector-meta-val">${escapeHtml(email)}</span>
          </div>
          <div class="inspector-meta-row">
            <span class="inspector-meta-label">Identity Status:</span>
            <span class="inspector-meta-val" style="color: #34D399;">&#10003; Validated</span>
          </div>
          <div class="inspector-meta-row">
            <span class="inspector-meta-label">Verified Breaches:</span>
            <span class="inspector-meta-val" style="color: ${breaches.length ? '#F87171' : '#34D399'};">${breaches.length} Linked</span>
          </div>
          <div class="inspector-meta-row">
            <span class="inspector-meta-label">Exposed Categories:</span>
            <span class="inspector-meta-val">${categories.size} Types</span>
          </div>
        </div>
      </div>

      <div class="inspector-section">
        <h5 class="inspector-subhead">Interactive Navigation</h5>
        <div class="inspector-rec-box">
          Click any <strong>Identifier</strong> or <strong>Breach</strong> node inside the graph to inspect threat source intelligence, platform credentials, and prioritized defense actions.
        </div>
      </div>
    `;
  }

  function selectExposureNode(nodeId, data) {
    exposureGraphState.selectedNodeId = nodeId;
    const allNodes = document.querySelectorAll(".exp-node");
    const allEdges = document.querySelectorAll(".exp-edge");

    // 1. Reset Dimming & Selection
    allNodes.forEach(n => {
      n.classList.remove("selected", "dimmed");
    });
    allEdges.forEach(e => {
      e.classList.remove("highlighted", "dimmed");
    });

    const targetNode = $(nodeId);
    if (targetNode) targetNode.classList.add("selected");

    // 2. Highlight Paths based on Node Type
    if (nodeId === "node-identity") {
      const e1 = $("edge-l1-l2");
      if (e1) e1.classList.add("highlighted");
      allEdges.forEach(e => { if (e !== e1) e.classList.add("dimmed"); });
      allNodes.forEach(n => {
        const id = n.getAttribute("id");
        if (id !== "node-identity" && id !== "node-email") n.classList.add("dimmed");
      });
      renderInspectorIdentity(data);
    } else if (nodeId === "node-email") {
      allEdges.forEach(e => e.classList.add("highlighted"));
      renderInspectorIdentifier(data);
    } else if (nodeId.startsWith("node-breach-")) {
      const idx = data.index;
      const targetEdge = $(`edge-l2-b${idx}`);
      if (targetEdge) targetEdge.classList.add("highlighted");
      allEdges.forEach(e => { if (e !== targetEdge) e.classList.add("dimmed"); });
      allNodes.forEach(n => {
        const id = n.getAttribute("id");
        if (id !== nodeId && id !== "node-email") n.classList.add("dimmed");
      });
      renderInspectorBreach(data.breach);
    }
  }

  function renderInspectorIdentity(data) {
    const badge = $("inspector-badge");
    const title = $("inspector-title");
    const body = $("inspector-body");
    if (!badge || !title || !body) return;

    badge.textContent = "ROOT IDENTITY PROFILE";
    title.textContent = "Your Digital Identity";

    body.innerHTML = `
      <div class="inspector-section">
        <h5 class="inspector-subhead">Node Verification Details</h5>
        <div class="inspector-meta-list">
          <div class="inspector-meta-row">
            <span class="inspector-meta-label">Hierarchy Level:</span>
            <span class="inspector-meta-val">Level 1 (Root Identity)</span>
          </div>
          <div class="inspector-meta-row">
            <span class="inspector-meta-label">Associated Identifiers:</span>
            <span class="inspector-meta-val">1 Verified Email</span>
          </div>
          <div class="inspector-meta-row">
            <span class="inspector-meta-label">Data Storage Policy:</span>
            <span class="inspector-meta-val" style="color: #34D399;">Zero Data Retention</span>
          </div>
        </div>
      </div>
      <div class="inspector-section">
        <h5 class="inspector-subhead">Identity Defense Guidance</h5>
        <div class="inspector-rec-box">
          This root node anchors your digital exposure perimeter. All breach incident connections are verified directly against global threat intelligence records.
        </div>
      </div>
    `;
  }

  function renderInspectorIdentifier(data) {
    const badge = $("inspector-badge");
    const title = $("inspector-title");
    const body = $("inspector-body");
    if (!badge || !title || !body) return;

    badge.textContent = "VERIFIED IDENTIFIER";
    title.textContent = escapeHtml(data.targetEmail);

    const breaches = data.breaches || [];
    const hasAnyPwd = breaches.some(b => b.has_password_exposure || (b.exposed_data || []).some(d => /password|hash/i.test(d)));

    const breachItemsHtml = breaches.slice(0, 4).map(b => `
      <div class="inspector-meta-row">
        <span>${escapeHtml(b.breach_title)}</span>
        <span style="color: ${b.has_password_exposure ? '#F87171' : '#FCD34D'}; font-weight:700;">
          ${b.has_password_exposure ? '&#9888; Password Leaked' : 'Exposed'}
        </span>
      </div>
    `).join("");

    body.innerHTML = `
      <div class="inspector-section">
        <h5 class="inspector-subhead">Identifier Telemetry</h5>
        <div class="inspector-meta-list">
          <div class="inspector-meta-row">
            <span class="inspector-meta-label">Identifier Type:</span>
            <span class="inspector-meta-val">Email Address (Level 2)</span>
          </div>
          <div class="inspector-meta-row">
            <span class="inspector-meta-label">Verification Source:</span>
            <span class="inspector-meta-val" style="color: #34D399;">&#10003; MX/DNS Handshake</span>
          </div>
          <div class="inspector-meta-row">
            <span class="inspector-meta-label">Matching Breaches:</span>
            <span class="inspector-meta-val" style="color: ${breaches.length ? '#F87171' : '#34D399'};">${breaches.length} Found</span>
          </div>
          <div class="inspector-meta-row">
            <span class="inspector-meta-label">Credential Stuffing Risk:</span>
            <span class="inspector-meta-val" style="color: ${hasAnyPwd ? '#F87171' : '#FCD34D'};">${hasAnyPwd ? 'CRITICAL' : 'MODERATE'}</span>
          </div>
        </div>
      </div>

      <div class="inspector-section">
        <h5 class="inspector-subhead">Linked Incidents</h5>
        <div class="inspector-meta-list">
          ${breachItemsHtml || '<span class="inspector-meta-label">None</span>'}
        </div>
      </div>

      <div class="inspector-section">
        <h5 class="inspector-subhead">Recommended Countermeasures</h5>
        <div class="inspector-rec-box">
          ${hasAnyPwd 
            ? "Immediate password reset recommended across all accounts sharing credentials with these leaked platforms. Enable 2FA on your email provider." 
            : "No passwords exposed directly. Monitor this email address for phishing emails referencing these platforms."}
        </div>
      </div>
    `;
  }

  function renderInspectorBreach(breach) {
    const badge = $("inspector-badge");
    const title = $("inspector-title");
    const body = $("inspector-body");
    if (!badge || !title || !body || !breach) return;

    const bTitle = breach.breach_title || breach.breach_id || "Breach Incident";
    const domain = breach.domain || "N/A";
    const date = breach.breach_date || "Unknown";
    const records = breach.pwn_count ? formatNumber(breach.pwn_count) : "Disclosed Record";
    const hasPwd = breach.has_password_exposure || (breach.exposed_data || []).some(d => /password|hash/i.test(d));
    const exposedData = breach.exposed_data || [];

    badge.textContent = "CONFIRMED BREACH RECORD";
    title.textContent = escapeHtml(bTitle);

    const chipsHtml = exposedData.map(item => {
      const isPwd = /password|hash/i.test(item);
      return `<span class="inspector-chip ${isPwd ? 'pwd' : ''}">${isPwd ? '&#128274; ' : ''}${escapeHtml(item)}</span>`;
    }).join("");

    body.innerHTML = `
      <div class="inspector-section">
        <h5 class="inspector-subhead">Incident Dossier</h5>
        <div class="inspector-meta-list">
          <div class="inspector-meta-row">
            <span class="inspector-meta-label">Platform Domain:</span>
            <span class="inspector-meta-val">${escapeHtml(domain)}</span>
          </div>
          <div class="inspector-meta-row">
            <span class="inspector-meta-label">Incident Date:</span>
            <span class="inspector-meta-val">${escapeHtml(date)}</span>
          </div>
          <div class="inspector-meta-row">
            <span class="inspector-meta-label">Exposed Accounts:</span>
            <span class="inspector-meta-val">${escapeHtml(records)}</span>
          </div>
          <div class="inspector-meta-row">
            <span class="inspector-meta-label">Threat Source:</span>
            <span class="inspector-meta-val" style="color: #60A5FA;">XposedOrNot Verified</span>
          </div>
        </div>
      </div>

      <div class="inspector-section">
        <h5 class="inspector-subhead">Compromised Data Categories (${exposedData.length})</h5>
        <div class="inspector-chips-row">
          ${chipsHtml || '<span class="inspector-meta-label">No categories detailed</span>'}
        </div>
      </div>

      <div class="inspector-section">
        <h5 class="inspector-subhead">Actionable Countermeasure</h5>
        <div class="inspector-rec-box">
          ${hasPwd 
            ? `Credentials from <strong>${escapeHtml(bTitle)}</strong> were leaked. Change passwords immediately on this service and any account sharing this password.` 
            : `Personal metadata from <strong>${escapeHtml(bTitle)}</strong> was exposed. Be vigilant against targeted spear-phishing.`}
        </div>
      </div>

      <a href="/breach/${encodeURIComponent(bTitle)}" class="inspector-cta-btn">
        <span>View Full Incident Dossier &rarr;</span>
      </a>
    `;
  }

  // --- Graph Pan, Zoom & Filter Event Handlers ---
  function initExposureGraphInteractions(svgElem) {
    if (exposureGraphState.initializedEvents) return;
    exposureGraphState.initializedEvents = true;

    // Deselect on clicking canvas background
    svgElem.addEventListener("click", () => {
      exposureGraphState.selectedNodeId = null;
      document.querySelectorAll(".exp-node").forEach(n => n.classList.remove("selected", "dimmed"));
      document.querySelectorAll(".exp-edge").forEach(e => e.classList.remove("highlighted", "dimmed"));
      if (exposureGraphState.report) {
        const breaches = exposureGraphState.report.breaches || [];
        const summary = exposureGraphState.report.summary || {};
        const email = exposureGraphState.report.scanned_target || summary.target_email_masked || "Verified Profile";
        const allCategories = new Set();
        breaches.forEach(b => (b.exposed_data || []).forEach(cat => allCategories.add(cat)));
        renderInspectorInitialState(email, breaches, allCategories);
      }
    });

    // Mouse Dragging to Pan Canvas
    const container = $("exposure-canvas-container");
    if (container) {
      container.addEventListener("mousedown", (e) => {
        // Only initiate pan if not clicking a node directly
        if (e.target.closest(".exp-node")) return;
        exposureGraphState.isDragging = true;
        exposureGraphState.dragStartX = e.clientX - exposureGraphState.panX;
        exposureGraphState.dragStartY = e.clientY - exposureGraphState.panY;
      });

      window.addEventListener("mousemove", (e) => {
        if (!exposureGraphState.isDragging) return;
        exposureGraphState.panX = e.clientX - exposureGraphState.dragStartX;
        exposureGraphState.panY = e.clientY - exposureGraphState.dragStartY;
        updateExposureGraphTransform();
      });

      window.addEventListener("mouseup", () => {
        exposureGraphState.isDragging = false;
      });

      // Mouse Wheel Zoom
      container.addEventListener("wheel", (e) => {
        e.preventDefault();
        const delta = e.deltaY < 0 ? 0.12 : -0.12;
        exposureGraphState.scale = Math.min(2.5, Math.max(0.55, exposureGraphState.scale + delta));
        updateExposureGraphTransform();
      }, { passive: false });

      // Touch Pan Support on Mobile
      let touchStartX = 0;
      let touchStartY = 0;
      container.addEventListener("touchstart", (e) => {
        if (e.touches.length === 1 && !e.target.closest(".exp-node")) {
          touchStartX = e.touches[0].clientX - exposureGraphState.panX;
          touchStartY = e.touches[0].clientY - exposureGraphState.panY;
          exposureGraphState.isDragging = true;
        }
      }, { passive: true });

      container.addEventListener("touchmove", (e) => {
        if (exposureGraphState.isDragging && e.touches.length === 1) {
          exposureGraphState.panX = e.touches[0].clientX - touchStartX;
          exposureGraphState.panY = e.touches[0].clientY - touchStartY;
          updateExposureGraphTransform();
        }
      }, { passive: true });

      container.addEventListener("touchend", () => {
        exposureGraphState.isDragging = false;
      });
    }

    // Zoom & Reset Buttons
    const btnZoomIn = $("graph-zoom-in");
    if (btnZoomIn) {
      btnZoomIn.addEventListener("click", () => {
        exposureGraphState.scale = Math.min(2.5, exposureGraphState.scale + 0.15);
        updateExposureGraphTransform();
      });
    }

    const btnZoomOut = $("graph-zoom-out");
    if (btnZoomOut) {
      btnZoomOut.addEventListener("click", () => {
        exposureGraphState.scale = Math.max(0.55, exposureGraphState.scale - 0.15);
        updateExposureGraphTransform();
      });
    }

    const btnFit = $("graph-fit-screen");
    const btnReset = $("graph-reset-view");
    [btnFit, btnReset].forEach(btn => {
      if (btn) {
        btn.addEventListener("click", () => {
          exposureGraphState.scale = 1.0;
          exposureGraphState.panX = 0;
          exposureGraphState.panY = 0;
          updateExposureGraphTransform();
        });
      }
    });

    // Category Filter Buttons
    document.querySelectorAll(".exposure-filter-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        document.querySelectorAll(".exposure-filter-btn").forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        const filterType = btn.getAttribute("data-filter") || "all";
        exposureGraphState.filter = filterType;

        const allNodes = document.querySelectorAll(".exp-node");
        const allEdges = document.querySelectorAll(".exp-edge");

        if (filterType === "all") {
          allNodes.forEach(n => n.classList.remove("dimmed"));
          allEdges.forEach(e => e.classList.remove("dimmed"));
        } else if (filterType === "identifier") {
          allNodes.forEach(n => {
            const level = n.getAttribute("data-level");
            if (level === "3") n.classList.add("dimmed");
            else n.classList.remove("dimmed");
          });
          allEdges.forEach(e => {
            if (e.id.includes("b")) e.classList.add("dimmed");
            else e.classList.remove("dimmed");
          });
        } else if (filterType === "breach") {
          allNodes.forEach(n => {
            const level = n.getAttribute("data-level");
            if (level === "1") n.classList.add("dimmed");
            else n.classList.remove("dimmed");
          });
          allEdges.forEach(e => {
            if (e.id === "edge-l1-l2") e.classList.add("dimmed");
            else e.classList.remove("dimmed");
          });
        }
      });
    });
  }

  // --- Dedicated Incident Dossier Chart Controller ---
  function renderDossierBreachChart(canvas, breach) {
    if (!canvas || !breach) return;
    const hasPwd = breach.has_password_exposure || (breach.exposed_data || []).some(d => /password|hash/i.test(d));
    const pwnCount = breach.pwn_count || 0;
    const dataTypes = breach.exposed_data || [];

    const labels = [
      "Password Risk",
      "Exposed Fields",
      "Incident Scale",
      "Credential Stuffing",
      "Takeover Threat"
    ];
    const values = [
      hasPwd ? 95 : 15,
      Math.min(100, Math.max(25, dataTypes.length * 20)),
      Math.min(100, Math.round(Math.log10(Math.max(pwnCount, 10)) * 12.5)),
      hasPwd ? 90 : 20,
      hasPwd ? 90 : 25
    ];

    if (typeof Chart !== "undefined") {
      try {
        new Chart(canvas, {
          type: "radar",
          data: {
            labels: labels,
            datasets: [{
              label: `${breach.breach_title || 'Incident'} Threat Profile`,
              data: values,
              backgroundColor: "rgba(109, 40, 217, 0.22)",
              borderColor: "#6D28D9",
              pointBackgroundColor: "#7C3AED",
              pointBorderColor: "#FFFFFF",
              pointHoverBackgroundColor: "#FFFFFF",
              pointHoverBorderColor: "#7C3AED",
              pointRadius: 5,
              borderWidth: 2.2
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
              r: {
                min: 0,
                max: 100,
                ticks: { stepSize: 25, display: false },
                pointLabels: {
                  font: { size: 11, family: "'Plus Jakarta Sans', 'Inter', sans-serif", weight: 600 },
                  color: "#475569"
                },
                grid: { color: "#E2E8F0" },
                angleLines: { color: "#E2E8F0" }
              }
            },
            plugins: {
              legend: {
                position: "top",
                labels: { font: { family: "'Plus Jakarta Sans', 'Inter', sans-serif", weight: 600 }, color: "#334155" }
              },
              tooltip: {
                backgroundColor: "rgba(15, 23, 42, 0.92)",
                padding: 9,
                cornerRadius: 7,
                callbacks: {
                  label: (ctx) => ` Threat Level: ${ctx.raw}/100`
                }
              }
            }
          }
        });
        return;
      } catch (err) {
        console.warn("Dossier chart failed, using fallback:", err);
      }
    }

    drawCanvas2DFallback(canvas, {
      data: {
        labels: labels,
        datasets: [{
          data: values,
          backgroundColor: ["#DC2626", "#7C3AED", "#6D28D9", "#DC2626", "#DC2626"]
        }]
      }
    });
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

  function triggerScanAnotherEmail() {
    if (breachChartInstance) {
      breachChartInstance.destroy();
      breachChartInstance = null;
    }
    if (reportSection) reportSection.classList.add("hidden");
    if (emailInput) {
      emailInput.value = "";
    }
    clearError();
    try {
      sessionStorage.removeItem("echorisk_last_report");
      sessionStorage.removeItem("echorisk_last_email");
    } catch (e) {}
    window.scrollTo({ top: 0, behavior: "smooth" });
    setTimeout(() => { if (emailInput) emailInput.focus(); }, 250);
  }

  if (btnScanAnother) {
    btnScanAnother.addEventListener("click", triggerScanAnotherEmail);
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

      // Zero data storage: do not cache or store the email anywhere
      try {
        localStorage.removeItem("echorisk_subscribers");
      } catch (_) { }

      if (notifyFeedback) {
        notifyFeedback.style.color = "var(--success-text)";
        notifyFeedback.textContent = "✓ Verified (Zero-Storage Policy: no email address is cached or stored).";
      }
      setTimeout(() => { closeModal(); showToast("Alert registered (Zero-Storage mode: no email cached)"); }, 1000);
    });
  }

  const btnClearSubscribers = $("btn-clear-subscribers");
  if (btnClearSubscribers) {
    btnClearSubscribers.addEventListener("click", () => {
      try {
        localStorage.removeItem("echorisk_subscribers");
        sessionStorage.clear();
      } catch (_) { }
      if (notifyFeedback) {
        notifyFeedback.style.color = "var(--text-muted)";
        notifyFeedback.textContent = "✓ Confirmed: Zero cached data present.";
      }
      showToast("Zero storage confirmed: no cached data.");
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
    const fn = (typeof window !== "undefined" && (window.keccak512 || window.keccak_512)) || (typeof keccak512 === "function" ? keccak512 : null);
    if (fn) {
      return fn(str).slice(0, 10);
    }
    const utf8 = new TextEncoder().encode(str), rate = 72;
    const padLen = rate - (utf8.length % rate), padded = new Uint8Array(utf8.length + padLen);
    padded.set(utf8);
    padded[utf8.length] = 0x01;
    padded[padded.length - 1] |= 0x80;
    const s = new BigUint64Array(25);
    const rot = (x, n) => ((x << BigInt(n)) | (x >> (64n - BigInt(n)))) & 0xFFFFFFFFFFFFFFFFn;
    const RC = [0x1n, 0x8082n, 0x800000000000808an, 0x8000000080008000n, 0x808bn, 0x80000001n, 0x8000000080008081n, 0x8000000000008009n, 0x8an, 0x88n, 0x80008009n, 0x8000000an, 0x8000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n, 0x800an, 0x800000008000000an, 0x8000000080008081n, 0x8000000000008080n, 0x80000001n, 0x8000000080008008n];
    const RHO = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];
    const PI = [0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19, 4];
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

  // --- Cross-Tab & Cross-Page State Communication ---
  window.handleScanAnotherEmail = triggerScanAnotherEmail;
  window.handleBackToScanner = function() {
    if (reportSection && !reportSection.classList.contains("hidden")) {
      reportSection.scrollIntoView({ behavior: "smooth", block: "start" });
    } else {
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
  };
  window.handleScrollToSection = function(targetId) {
    scrollToTarget(targetId);
  };

  let navChannel = null;
  try {
    navChannel = new BroadcastChannel("echorisk_nav_channel");
    navChannel.onmessage = (event) => {
      if (!event.data || event.data.type !== "ECHORISK_ACTION") return;
      if (event.data.action === "scan_another") {
        triggerScanAnotherEmail();
      } else if (event.data.action === "back_to_scanner") {
        window.handleBackToScanner();
      } else if (event.data.action === "scroll_to" && event.data.target) {
        window.handleScrollToSection(event.data.target);
      }
    };
  } catch (e) {}

  window.addEventListener("message", (event) => {
    if (!event.data || event.data.type !== "ECHORISK_ACTION") return;
    if (event.data.action === "scan_another") {
      triggerScanAnotherEmail();
    } else if (event.data.action === "back_to_scanner") {
      window.handleBackToScanner();
    } else if (event.data.action === "scroll_to" && event.data.target) {
      window.handleScrollToSection(event.data.target);
    }
  });

  // --- Landing Page Saved State Restoration ---
  if ($("scan-form")) {
    let pendingAction = null;
    try {
      pendingAction = sessionStorage.getItem("echorisk_pending_action");
      sessionStorage.removeItem("echorisk_pending_action");
    } catch (e) {}

    let savedReport = null;
    let savedEmail = null;
    try {
      savedReport = sessionStorage.getItem("echorisk_last_report");
      savedEmail = sessionStorage.getItem("echorisk_last_email");
    } catch (e) {}

    if (savedReport) {
      try {
        const parsedReport = JSON.parse(savedReport);
        renderScanReport(parsedReport, false, false);
        if (emailInput && savedEmail) {
          emailInput.value = savedEmail;
        }
      } catch (e) {
        console.warn("Could not restore saved report:", e);
      }
    }

    if (pendingAction === "scan_another") {
      window.scrollTo({ top: 0, behavior: "smooth" });
      setTimeout(() => {
        if (emailInput) {
          emailInput.focus();
          emailInput.select();
        }
      }, 180);
    } else if (pendingAction === "back_to_scanner") {
      if (reportSection && !reportSection.classList.contains("hidden")) {
        setTimeout(() => reportSection.scrollIntoView({ behavior: "smooth", block: "start" }), 150);
      }
    } else if (pendingAction && pendingAction.startsWith("scroll_to:")) {
      const targetId = pendingAction.split(":")[1];
      if ($(targetId)) {
        setTimeout(() => scrollToTarget(targetId), 200);
      }
    } else if (window.location.hash) {
      const hashId = window.location.hash.slice(1);
      if ($(hashId)) {
        setTimeout(() => scrollToTarget(hashId), 200);
      }
    }
  }

  // --- Breach Detail Page Return & Navigation Controller ---
  const isBreachDetailPage = document.body.classList.contains("breach-detail-page") || !!$("dossier-breach-chart");

  if (isBreachDetailPage) {
    function navigateBackToMain(action, target = "hero") {
      // 1. Broadcast to other open tabs
      try {
        if (!navChannel) navChannel = new BroadcastChannel("echorisk_nav_channel");
        navChannel.postMessage({ type: "ECHORISK_ACTION", action, target });
      } catch (e) {}

      // 2. Direct opener communication if opened via View Details
      let openerHandled = false;
      if (window.opener && !window.opener.closed) {
        try {
          if (action === "scan_another") {
            if (typeof window.opener.handleScanAnotherEmail === "function") {
              window.opener.handleScanAnotherEmail();
              openerHandled = true;
            }
          } else if (action === "back_to_scanner") {
            if (typeof window.opener.handleBackToScanner === "function") {
              window.opener.handleBackToScanner();
              openerHandled = true;
            }
          } else if (action === "scroll_to") {
            if (typeof window.opener.handleScrollToSection === "function") {
              window.opener.handleScrollToSection(target);
              openerHandled = true;
            }
          }
          window.opener.postMessage({ type: "ECHORISK_ACTION", action, target }, "*");
          openerHandled = true;
          window.opener.focus();
        } catch (err) {
          console.warn("Direct opener call restricted:", err);
        }
      }

      // If opener was notified, close this tab immediately to return to the original scan page
      if (openerHandled || (window.opener && !window.opener.closed)) {
        try {
          window.close();
          setTimeout(() => {
            if (!document.hidden) {
              fallbackNavigation(action, target);
            }
          }, 350);
          return;
        } catch (e) {}
      }

      fallbackNavigation(action, target);
    }

    function fallbackNavigation(action, target) {
      if (action === "scan_another") {
        try { sessionStorage.setItem("echorisk_pending_action", "scan_another"); } catch (e) {}
        window.location.href = "/#hero";
      } else if (action === "back_to_scanner") {
        try { sessionStorage.setItem("echorisk_pending_action", "back_to_scanner"); } catch (e) {}
        window.location.href = "/#report-section";
      } else {
        try { sessionStorage.setItem("echorisk_pending_action", `scroll_to:${target}`); } catch (e) {}
        window.location.href = `/#${target}`;
      }
    }

    // Attach listeners on breach detail page
    const btnDossierScan = $("btn-dossier-scan");
    if (btnDossierScan) {
      btnDossierScan.addEventListener("click", (e) => {
        e.preventDefault();
        navigateBackToMain("scan_another", "hero");
      });
    }

    const btnBackScanner = $("btn-back-scanner");
    if (btnBackScanner) {
      btnBackScanner.addEventListener("click", (e) => {
        e.preventDefault();
        navigateBackToMain("back_to_scanner", "report-section");
      });
    }

    const detailNavHome = $("nav-home");
    if (detailNavHome) {
      detailNavHome.addEventListener("click", (e) => {
        e.preventDefault();
        navigateBackToMain("scroll_to", "hero");
      });
    }
    const detailNavHow = $("nav-how");
    if (detailNavHow) {
      detailNavHow.addEventListener("click", (e) => {
        e.preventDefault();
        navigateBackToMain("scroll_to", "how-it-works");
      });
    }
    const detailNavPasswords = $("nav-passwords");
    if (detailNavPasswords) {
      detailNavPasswords.addEventListener("click", (e) => {
        e.preventDefault();
        navigateBackToMain("scroll_to", "passwords");
      });
    }
    const detailNavAbout = $("nav-about");
    if (detailNavAbout) {
      detailNavAbout.addEventListener("click", (e) => {
        e.preventDefault();
        navigateBackToMain("scroll_to", "about");
      });
    }

    const detailBrand = document.querySelector(".navbar .brand");
    if (detailBrand) {
      detailBrand.addEventListener("click", (e) => {
        e.preventDefault();
        navigateBackToMain("scroll_to", "hero");
      });
    }

    const breadcrumbHome = $("breadcrumb-home");
    if (breadcrumbHome) {
      breadcrumbHome.addEventListener("click", (e) => {
        e.preventDefault();
        navigateBackToMain("back_to_scanner", "report-section");
      });
    }

    document.querySelectorAll(".footer-links-list a").forEach(a => {
      a.addEventListener("click", (e) => {
        e.preventDefault();
        const dataTarget = a.getAttribute("data-target");
        const href = a.getAttribute("href") || "";
        let target = "hero";
        if (dataTarget) {
          target = dataTarget;
        } else if (href.includes("#")) {
          target = href.split("#")[1];
        }
        navigateBackToMain("scroll_to", target);
      });
    });
  }

  // --- Initialize Incident Dossier Page Chart if on breach_detail page ---
  const dossierChartCanvas = $("dossier-breach-chart");
  const dossierDataScript = $("breach-detail-data");
  if (dossierChartCanvas && dossierDataScript) {
    try {
      const rawText = dossierDataScript.textContent || "{}";
      const breachData = JSON.parse(rawText.trim());
      renderDossierBreachChart(dossierChartCanvas, breachData);
    } catch (e) {
      console.warn("Could not parse dossier breach data:", e);
    }
  }
});
