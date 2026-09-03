const scenarios = [
  { id: "generic_local_web_validation", label: "Full controlled chain (live loopback fixture)" },
  { id: "public_app_validation", label: "Public application validation (fixture / DVWA lab)" },
];

const progressStages = [
  "Target validation", "Reconnaissance", "Service discovery",
  "Vulnerability discovery", "Active validation", "MITRE mapping",
  "Attack-path analysis", "Persistence",
];

const $ = (selector) => document.querySelector(selector);

async function requestJson(url, options = {}) {
  let response;
  try {
    response = await fetch(url, options);
  } catch (_error) {
    throw new Error("Backend is unavailable. Confirm that Obsidian Recon is running.");
  }
  let body;
  try {
    body = await response.json();
  } catch (_error) {
    throw new Error("The backend returned an unreadable response.");
  }
  if (!response.ok) {
    const detail = body.detail;
    const message = typeof detail === "string"
      ? detail
      : detail?.message || "The backend could not complete this request.";
    const error = new Error(message);
    error.code = typeof detail === "object" ? detail?.code : null;
    error.detail = detail;
    throw error;
  }
  return body;
}

function postJson(url, body) {
  return requestJson(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

function statusClass(value) {
  const normalized = String(value || "unknown").toLowerCase().replaceAll("_", "-");
  if (["confirmed", "completed", "ready"].includes(normalized)) return "success";
  if (["failed", "verification-failed", "rejected", "unavailable", "expired"].includes(normalized)) return "danger";
  if (["manual-review", "degraded", "not-configured"].includes(normalized)) return "warning";
  return normalized;
}

function displayStatus(value) {
  return String(value || "unknown").replaceAll("_", " ");
}

function findingValidationPairs(data) {
  if (data.finding) {
    const technique = data.technique || {};
    return [{
      finding: {
        ...data.finding,
        mitre_technique_id:
          data.finding.mitre_technique_id || technique.technique_id,
        mitre_technique_name:
          data.finding.mitre_technique_name || technique.technique_name,
      },
      validation: data.validation_result || {},
    }];
  }
  if (data.validations && !Array.isArray(data.validations)) {
    return Object.values(data.validations).map((item) => ({
      finding: item.finding || {},
      validation: item.validation_result || {},
    }));
  }
  const findings = Array.isArray(data.findings) ? data.findings : [];
  const validations = Array.isArray(data.validations) ? data.validations : [];
  return findings.map((finding, index) => ({
    finding,
    validation: validations[index] || finding.validations?.at(-1) || {},
  }));
}

function resultChains(data) {
  if (Array.isArray(data.chains)) return data.chains;
  if (Array.isArray(data.chain_result?.chains)) return data.chain_result.chains;
  return [];
}

function techniqueFor(finding) {
  if (finding.mitre_technique_id) {
    return {
      id: finding.mitre_technique_id,
      name: finding.mitre_technique_name,
      tactic: finding.mitre_tactic,
    };
  }
  const mapping = Array.isArray(finding.mitre_mappings)
    ? finding.mitre_mappings[0]
    : null;
  return { id: mapping?.technique_id, name: mapping?.technique_name, tactic: mapping?.tactic };
}

function computeSummary(data) {
  const pairs = findingValidationPairs(data);
  const presentations = Array.isArray(data.finding_presentations)
    ? data.finding_presentations
    : [];
  const statuses = pairs.map(({ finding, validation }) =>
    validation.status || finding.validation_status || finding.status || "detected");
  const techniques = new Set(
    pairs.map(({ finding }) => techniqueFor(finding).id).filter(Boolean),
  );
  const assets = new Set(pairs.map(({ finding }) => finding.asset_id).filter(Boolean));
  if (data.asset?.asset_id) assets.add(data.asset.asset_id);
  return {
    status: data.status || data.overall_status || "completed",
    assets: assets.size,
    services: Array.isArray(data.services) ? data.services.length : null,
    candidates: pairs.length,
    confirmed: statuses.filter((status) => status === "confirmed").length,
    rejected: statuses.filter((status) => status === "rejected").length,
    manualReview: statuses.filter((status) => status === "manual_review").length,
    techniques: techniques.size,
    chains: resultChains(data).length,
    highRisk: presentations.filter((item) => item.risk?.rating === "High").length,
    criticalRisk: presentations.filter((item) => item.risk?.rating === "Critical").length,
  };
}

function addSummaryCard(container, label, value, tone = "") {
  const card = document.createElement("article");
  card.className = `summary-card ${tone}`.trim();
  const number = document.createElement("strong");
  number.textContent = value === null ? "—" : String(value);
  const caption = document.createElement("span");
  caption.textContent = label;
  card.append(number, caption);
  container.append(card);
}

function createStatusPill(status) {
  const pill = document.createElement("span");
  pill.className = `status-pill ${statusClass(status)}`;
  pill.textContent = displayStatus(status);
  return pill;
}

function renderSummary(data) {
  const summary = computeSummary(data);
  const container = $("#summary-cards");
  container.replaceChildren();
  [
    ["Scan status", displayStatus(summary.status), statusClass(summary.status)],
    ["Assets", summary.assets], ["Services", summary.services],
    ["Candidate findings", summary.candidates],
    ["Confirmed", summary.confirmed, "success"],
    ["Rejected", summary.rejected, "danger"],
    ["Manual review", summary.manualReview, "warning"],
    ["MITRE techniques", summary.techniques], ["Attack chains", summary.chains],
    ["High risk", summary.highRisk, "warning"],
    ["Critical risk", summary.criticalRisk, "danger"],
  ].forEach(([label, value, tone]) => addSummaryCard(container, label, value, tone));
}

function appendLabeledText(container, label, value) {
  if (value === null || value === undefined || value === "") return;
  const block = document.createElement("div");
  block.className = "detail-field";
  const heading = document.createElement("strong");
  heading.textContent = label;
  const content = document.createElement("span");
  content.textContent = String(value);
  block.append(heading, content);
  container.append(block);
}

function appendList(container, headingText, values) {
  if (!Array.isArray(values) || values.length === 0) return;
  const section = document.createElement("section");
  const heading = document.createElement("h4");
  heading.textContent = headingText;
  const list = document.createElement("ul");
  values.forEach((value) => {
    const item = document.createElement("li");
    item.textContent = value;
    list.append(item);
  });
  section.append(heading, list);
  container.append(section);
}

function createRiskPill(rating) {
  const pill = document.createElement("span");
  const normalized = String(rating || "Not rated").toLowerCase().replaceAll(" ", "-");
  pill.className = `risk-pill risk-${normalized}`;
  pill.textContent = rating || "Not rated";
  return pill;
}

function renderProofDetails(presentation) {
  const details = document.createElement("details");
  details.className = "proof-details";
  const summary = document.createElement("summary");
  summary.textContent = presentation?.poc?.available
    ? "VIEW PROOF OF CONCEPT"
    : "VIEW EVIDENCE";
  const panel = document.createElement("div");
  panel.className = "proof-panel";
  if (!presentation) {
    const note = document.createElement("p");
    note.textContent = "Human-readable presentation data is unavailable for this persisted result.";
    panel.append(note);
    details.append(summary, panel);
    return details;
  }

  const location = presentation.location || {};
  const validation = presentation.validation || {};
  const poc = presentation.poc || {};
  const risk = presentation.risk || {};
  const mitre = presentation.mitre;
  const proofIntro = document.createElement("p");
  proofIntro.className = "proof-intro";
  proofIntro.textContent = `${poc.label || "Evidence"} · ${poc.subtitle || "Evidence and reproduction steps."}`;
  panel.append(proofIntro);
  const overview = document.createElement("div");
  overview.className = "detail-grid";
  appendLabeledText(overview, "Target", location.target);
  appendLabeledText(overview, "Endpoint", location.endpoint);
  appendLabeledText(overview, "HTTP method", location.http_method);
  appendLabeledText(overview, "Parameter", location.parameter_name);
  appendLabeledText(overview, "Parameter location", location.parameter_location);
  appendLabeledText(overview, "Verification method", poc.verification_method);
  appendLabeledText(overview, "Validator method", validation.method);
  appendLabeledText(overview, "Validation", displayStatus(validation.status));
  appendLabeledText(overview, "Confidence", typeof validation.confidence === "number" ? `${Math.round(validation.confidence * 100)}%` : null);
  panel.append(overview);

  if (Array.isArray(poc.detection_methods) && poc.detection_methods.length) {
    const methodsSection = document.createElement("section");
    const methodsHeading = document.createElement("h4");
    methodsHeading.textContent = "Detection methods";
    const methodsGrid = document.createElement("div");
    methodsGrid.className = "detection-method-grid";
    poc.detection_methods.forEach((method) => {
      const card = document.createElement("article");
      card.className = "detection-method-card";
      const name = document.createElement("strong");
      name.textContent = method.name;
      card.append(name, createStatusPill(method.state));
      appendLabeledText(card, "Result", method.summary || displayStatus(method.reason));
      methodsGrid.append(card);
    });
    methodsSection.append(methodsHeading, methodsGrid);
    panel.append(methodsSection);
  }

  appendList(panel, "Reproduction steps", poc.steps);
  if (Array.isArray(poc.requests) && poc.requests.length) {
    const requests = document.createElement("section");
    const heading = document.createElement("h4");
    heading.textContent = "Controlled request shapes";
    requests.append(heading);
    poc.requests.forEach((request) => {
      const label = document.createElement("strong");
      label.textContent = request.label;
      const block = document.createElement("pre");
      block.textContent = request.request;
      requests.append(label, block);
    });
    panel.append(requests);
  }
  appendLabeledText(panel, "Request detail", poc.request_note);
  appendLabeledText(panel, "Observed evidence", JSON.stringify(poc.observed_evidence || {}, null, 2));
  appendLabeledText(panel, "Interpretation", poc.interpretation);
  appendLabeledText(panel, "Safety note", poc.safety_note);
  if (mitre) {
    appendLabeledText(panel, "MITRE ATT&CK", `${mitre.technique_id} — ${mitre.technique_name} · ${mitre.tactic}`);
  } else {
    appendLabeledText(panel, "MITRE ATT&CK", "Unmapped");
  }
  appendList(panel, "Technical impact", risk.technical_impact);
  if (risk.cia) {
    appendLabeledText(panel, "CIA impact", `Confidentiality: ${risk.cia.confidentiality} · Integrity: ${risk.cia.integrity} · Availability: ${risk.cia.availability}`);
  }
  appendLabeledText(panel, "Business-risk rationale", risk.rationale);
  if (risk.business) {
    appendLabeledText(panel, "Confidentiality impact", risk.business.confidentiality);
    appendLabeledText(panel, "Integrity impact", risk.business.integrity);
    appendLabeledText(panel, "Availability impact", risk.business.availability);
    appendList(panel, "Potential business consequences", risk.business.consequences);
  }
  appendLabeledText(panel, "Scope", risk.scope_note);
  appendLabeledText(panel, "CVSS", risk.cvss);
  appendLabeledText(panel, "Rating notice", risk.notice);
  details.append(summary, panel);
  return details;
}

function renderFindings(data) {
  const pairs = findingValidationPairs(data);
  const presentations = new Map(
    (data.finding_presentations || []).map((item) => [item.finding_id, item]),
  );
  const body = $("#findings-body");
  body.replaceChildren();
  $("#finding-count").textContent = String(pairs.length);
  $("#findings-empty").hidden = pairs.length !== 0;
  $(".table-wrap").hidden = pairs.length === 0;
  pairs.forEach(({ finding, validation }) => {
    const status = validation.status || finding.validation_status || finding.status || "detected";
    const technique = techniqueFor(finding);
    const presentation = presentations.get(finding.finding_id || finding.id);
    const row = document.createElement("tr");
    const findingCell = document.createElement("td");
    const name = document.createElement("strong");
    name.textContent = displayStatus(finding.vulnerability_type || "Unknown finding");
    const id = document.createElement("small");
    id.textContent = finding.finding_id || finding.id || "";
    findingCell.append(name, id);
    row.append(findingCell);
    [
      finding.severity || "—",
      finding.endpoint || "—",
    ].forEach((value) => {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.append(cell);
    });
    const statusCell = document.createElement("td");
    statusCell.append(createStatusPill(status));
    row.append(statusCell);
    const confidenceCell = document.createElement("td");
    const confidence = validation.confidence ?? finding.validation_confidence;
    confidenceCell.textContent = typeof confidence === "number"
      ? `${Math.round(confidence * 100)}%`
      : "—";
    row.append(confidenceCell);
    const mitreCell = document.createElement("td");
    mitreCell.textContent = technique.id
      ? `${technique.id}${technique.name ? `\n${technique.name}` : ""}${(presentation?.mitre?.tactic || technique.tactic) ? `\n${presentation?.mitre?.tactic || technique.tactic}` : ""}`
      : "Unmapped";
    row.append(mitreCell);
    const riskCell = document.createElement("td");
    riskCell.append(createRiskPill(presentation?.risk?.rating));
    row.append(riskCell);
    const proofCell = document.createElement("td");
    const proofLabel = document.createElement("span");
    proofLabel.className = "poc-label";
    proofLabel.textContent = presentation?.poc?.label || "Unavailable";
    proofCell.append(proofLabel);
    proofCell.append(renderProofDetails(presentation));
    row.append(proofCell);
    body.append(row);
  });
}

function renderChains(data) {
  const chains = resultChains(data);
  const attackFlow = data.attack_flow || {};
  const multiStage = Array.isArray(attackFlow.multi_stage_paths)
    ? attackFlow.multi_stage_paths
    : [];
  const standalone = Array.isArray(attackFlow.standalone_findings)
    ? attackFlow.standalone_findings
    : [];
  const presentedChains = [...multiStage, ...standalone];
  const list = $("#chain-list");
  list.replaceChildren();
  $("#chain-count").textContent = String(chains.length);
  $("#chains-empty").hidden = chains.length !== 0;
  if (multiStage.length) {
    const multiHeading = document.createElement("h4");
    multiHeading.className = "flow-group-heading";
    multiHeading.textContent = "Multi-stage attack paths";
    list.append(multiHeading);
  }
  presentedChains.forEach((chain, chainIndex) => {
    if (chainIndex === multiStage.length && standalone.length) {
      const standaloneHeading = document.createElement("h4");
      standaloneHeading.className = "flow-group-heading";
      standaloneHeading.textContent = "Standalone validated findings";
      list.append(standaloneHeading);
    }
    const card = document.createElement("article");
    card.className = "chain-card";
    const header = document.createElement("div");
    header.className = "chain-header";
    const title = document.createElement("div");
    const heading = document.createElement("strong");
    heading.textContent = chain.chain_id || chain.id || "Attack path";
    const confidence = document.createElement("small");
    confidence.textContent = typeof chain.confidence === "number"
      ? `${Math.round(chain.confidence * 100)}% confidence`
      : "";
    title.append(heading, confidence);
    const badges = document.createElement("div");
    badges.className = "chain-badges";
    badges.append(createRiskPill(chain.cumulative_risk), createStatusPill(chain.status));
    header.append(title, badges);
    const flow = document.createElement("div");
    flow.className = "chain-flow";
    const steps = Array.isArray(chain.steps) ? [...chain.steps] : [];
    steps.sort((left, right) => (left.step_number || 0) - (right.step_number || 0));
    steps.forEach((step, index) => {
      const node = document.createElement("div");
      node.className = `chain-node ${step.mitre_technique_id ? "technique" : "context"}`;
      const kicker = document.createElement("span");
      kicker.textContent = step.mitre_technique_id || "Environmental context";
      const nodeTitle = document.createElement("strong");
      nodeTitle.textContent = step.mitre_technique_name
        || displayStatus(step.vulnerability_type || step.capability || "Observed condition");
      const detail = step.finding_presentation || {};
      const location = detail.location || {};
      const metadata = document.createElement("small");
      metadata.textContent = [location.endpoint || step.target, displayStatus(step.validation_status)]
        .filter(Boolean).join(" · ");
      node.append(kicker, nodeTitle, metadata);
      if (step.mitre_technique_id) {
        appendLabeledText(node, "Tactic", detail.mitre?.tactic || step.mitre_tactic);
        appendLabeledText(node, "Finding", displayStatus(detail.vulnerability_type || step.vulnerability_type));
        appendLabeledText(node, "Endpoint", location.endpoint);
        appendLabeledText(node, "HTTP method", location.http_method);
        appendLabeledText(node, "Parameter", location.parameter_name);
        appendLabeledText(node, "Parameter location", location.parameter_location);
        appendLabeledText(node, "Validation", displayStatus(detail.validation?.status || step.validation_status));
        appendLabeledText(node, "Confidence", typeof (detail.validation?.confidence ?? step.validation_confidence) === "number" ? `${Math.round((detail.validation?.confidence ?? step.validation_confidence) * 100)}%` : null);
        appendLabeledText(node, "PoC available", detail.poc?.available ? "Yes" : "No");
        appendList(node, "Technical outcome", (step.provides || []).map(displayStatus));
        appendLabeledText(node, "Controlled-lab note", detail.poc?.safety_note);
      } else {
        appendLabeledText(node, "Type", "Environmental Context");
        appendLabeledText(node, "Target", step.target);
        appendLabeledText(node, "Observed", (step.provides || []).includes("discovered_services") ? "Reachable web service" : "Observed environmental condition");
        appendList(node, "Capabilities", (step.provides || []).map(displayStatus));
      }
      flow.append(node);
      if (index < steps.length - 1) {
        const connector = document.createElement("div");
        connector.className = "chain-connector";
        const nextStep = steps[index + 1];
        const dependency = (chain.dependencies || []).filter((item) =>
          item.provider_finding_id === step.finding_id
          && item.consumer_finding_id === nextStep.finding_id);
        const capability = dependency.length
          ? dependency.map((item) => `${displayStatus(item.capability)} (${item.requirement})`).join(", ")
          : Array.isArray(step.provides) && step.provides.length
            ? step.provides.map(displayStatus).join(", ")
            : step.capability;
        const label = document.createElement("span");
        label.textContent = dependency.length
          ? `PROVIDES ${capability} · SATISFIES PREREQUISITE FOR NEXT STEP`
          : capability || "enables";
        connector.append(label, document.createTextNode("↓"));
        flow.append(connector);
      }
    });
    const impact = document.createElement("div");
    impact.className = "chain-impact";
    appendLabeledText(impact, "Attack path impact", chain.impact_summary);
    appendLabeledText(impact, "Cumulative business risk", chain.cumulative_risk);
    appendList(impact, "Capabilities gained", (chain.cumulative_capabilities || []).map(displayStatus));
    appendList(impact, "Potential business impact", chain.potential_business_impact);
    appendLabeledText(impact, "Rating notice", chain.notice);
    card.append(header, flow, impact);
    list.append(card);
  });
  if (!presentedChains.length) {
    chains.forEach((chain) => {
      const card = document.createElement("article");
      card.className = "chain-card";
      const title = document.createElement("strong");
      title.textContent = chain.chain_id || chain.id || "Attack path";
      const note = document.createElement("p");
      note.textContent = "Human-readable attack-flow detail is unavailable for this persisted response.";
      card.append(title, note);
      list.append(card);
    });
  }
}

function renderResults(data, modeLabel) {
  renderSummary(data);
  renderFindings(data);
  renderChains(data);
  $("#result-mode").className =
    `status-pill ${statusClass(data.status || data.overall_status)}`;
  $("#result-mode").textContent = modeLabel;
  $("#raw-json").textContent = JSON.stringify(data, null, 2);
  $("#results").hidden = false;
  $("#results").scrollIntoView({ behavior: "smooth", block: "start" });
}

function setButtonLoading(button, loading, idleText, busyText) {
  button.disabled = loading;
  button.textContent = loading ? busyText : idleText;
}

function populateScenarios() {
  scenarios.forEach((scenario) => {
    const option = document.createElement("option");
    option.value = scenario.id;
    option.textContent = scenario.label;
    $("#scenario").append(option);
  });
}

function initializeProgress() {
  const list = $("#progress-stages");
  list.replaceChildren();
  progressStages.forEach((stage) => {
    const item = document.createElement("li");
    item.dataset.state = "queued";
    const label = document.createElement("span");
    label.textContent = stage;
    const state = document.createElement("small");
    state.textContent = "queued";
    item.append(label, state);
    list.append(item);
  });
}

function setProgress(state) {
  const overall = $("#overall-progress");
  overall.className = `status-pill ${statusClass(state)}`;
  overall.textContent = displayStatus(state);
  $("#progress-stages").querySelectorAll("li").forEach((item) => {
    item.dataset.state = state === "running" ? "queued" : state;
    item.querySelector("small").textContent = state === "running" ? "queued" : state;
  });
}

async function refreshHealth() {
  const container = $("#health-components");
  container.replaceChildren();
  try {
    const health = await requestJson("/api/readiness");
    Object.entries(health.components || {}).forEach(([name, component]) => {
      const item = document.createElement("div");
      item.className = "health-item";
      const dot = document.createElement("span");
      dot.className = `health-dot ${statusClass(component.status)}`;
      const text = document.createElement("span");
      const label = document.createElement("strong");
      label.textContent = name === "postgresql"
        ? "PostgreSQL"
        : name[0].toUpperCase() + name.slice(1);
      const state = document.createElement("small");
      state.textContent = displayStatus(component.status);
      text.append(label, state);
      item.append(dot, text);
      container.append(item);
    });
  } catch (error) {
    const item = document.createElement("div");
    item.className = "health-item";
    const dot = document.createElement("span");
    dot.className = "health-dot danger";
    const text = document.createElement("span");
    text.textContent = error instanceof Error ? error.message : "Health check unavailable";
    item.append(dot, text);
    container.append(item);
  }
}

function activateTab(panelId) {
  document.querySelectorAll(".tab").forEach((tab) => {
    const active = tab.dataset.tab === panelId;
    tab.classList.toggle("is-active", active);
    tab.setAttribute("aria-selected", String(active));
  });
  document.querySelectorAll(".tab-panel").forEach((panel) => {
    panel.hidden = panel.id !== panelId;
  });
}

async function loadPersistedScan(scanId) {
  const encoded = encodeURIComponent(scanId);
  const [scan, findings, chains] = await Promise.all([
    requestJson(`/api/scans/${encoded}`),
    requestJson(`/api/scans/${encoded}/findings`),
    requestJson(`/api/scans/${encoded}/chains`),
  ]);
  return {
    scan_id: scan.id,
    status: scan.status,
    target_url: scan.target_url,
    findings,
    validations: findings.map((finding) => finding.validations?.at(-1) || {}),
    chains,
  };
}

let activeVerificationId = null;

function renderTargetVerification(verification) {
  activeVerificationId = verification.id || null;
  const panel = $("#verification-panel");
  const status = $("#verification-status");
  status.className = `status-pill ${statusClass(verification.status)}`;
  status.textContent = displayStatus(verification.status);
  $("#verification-message").textContent = verification.message || "";
  $("#verification-origin").textContent = verification.canonical_origin || "—";
  $("#verification-name").textContent = verification.txt_record_name || "—";
  $("#verification-value").textContent = verification.txt_record_value || "No longer required";
  $("#verification-expiry").textContent = verification.expires_at
    ? new Date(verification.expires_at).toLocaleString()
    : "—";
  const verified = verification.status === "verified";
  const expired = verification.status === "expired";
  $("#verify-dns-button").hidden = verified || expired;
  $("#regenerate-verification-button").hidden = !expired;
  if (verified) {
    $("#scan-button").textContent = "RUN SECURITY SCAN";
  }
  panel.hidden = false;
}

async function createTargetVerification() {
  const verification = await postJson("/api/target-verifications", {
    target_url: $("#scan-target").value,
  });
  renderTargetVerification(verification);
  return verification;
}

$("#scan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("#scan-button");
  const message = $("#scan-message");
  $("#results").hidden = true;
  $("#progress-section").hidden = false;
  initializeProgress();
  setProgress("running");
  message.className = "status-message";
  message.textContent = "Scan running. Waiting for the synchronous backend pipeline…";
  setButtonLoading(button, true, "START SCAN", "SCANNING…");
  try {
    const data = await postJson("/api/scans/run", {
      target_url: $("#scan-target").value,
      authorized: $("#scan-authorized").checked,
    });
    setProgress("completed");
    renderResults(data, "Real scan");
    $("#scan-id").value = data.scan_id || "";
    message.textContent = `Scan ${data.scan_id || ""} completed and persisted.`;
    refreshHealth();
  } catch (error) {
    setProgress("failed");
    message.className = "status-message error";
    if (error?.code === "target_verification_required") {
      $("#progress-section").hidden = true;
      try {
        await createTargetVerification();
        message.className = "status-message";
        message.textContent = "Add the DNS TXT record shown below, then select Verify DNS.";
      } catch (verificationError) {
        message.textContent = verificationError instanceof Error
          ? verificationError.message
          : "Could not create a DNS verification challenge.";
      }
    } else {
      message.textContent = error instanceof Error ? error.message : "Scan failed.";
    }
  } finally {
    setButtonLoading(button, false, "START SCAN", "SCANNING…");
  }
});

$("#verify-dns-button").addEventListener("click", async () => {
  const button = $("#verify-dns-button");
  const message = $("#scan-message");
  if (!activeVerificationId) return;
  setButtonLoading(button, true, "VERIFY DNS", "VERIFYING…");
  try {
    const verification = await postJson(
      `/api/target-verifications/${encodeURIComponent(activeVerificationId)}/verify`,
      {},
    );
    renderTargetVerification(verification);
    message.className = verification.status === "verified"
      ? "status-message"
      : "status-message error";
    message.textContent = verification.status === "verified"
      ? "Domain verified. You can now run the security scan."
      : verification.message;
  } catch (error) {
    message.className = "status-message error";
    message.textContent = error instanceof Error ? error.message : "DNS verification failed.";
  } finally {
    setButtonLoading(button, false, "VERIFY DNS", "VERIFYING…");
  }
});

$("#regenerate-verification-button").addEventListener("click", async () => {
  const message = $("#scan-message");
  try {
    const verification = await createTargetVerification();
    message.className = "status-message";
    message.textContent = verification.message;
  } catch (error) {
    message.className = "status-message error";
    message.textContent = error instanceof Error ? error.message : "Could not create a new challenge.";
  }
});

$("#scan-target").addEventListener("input", () => {
  activeVerificationId = null;
  $("#verification-panel").hidden = true;
  $("#scan-button").textContent = "START SCAN";
});

$("#demo-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("#demo-button");
  const message = $("#demo-message");
  $("#results").hidden = true;
  message.className = "status-message";
  message.textContent = "Running controlled deterministic validation…";
  setButtonLoading(button, true, "RUN CONTROLLED DEMO", "RUNNING…");
  try {
    const data = await postJson("/api/test-harness/run", {
      target_url: $("#demo-target").value,
      scenario: $("#scenario").value,
      authorized: $("#demo-authorized").checked,
    });
    renderResults(data, "Controlled Lab Demonstration");
    $("#scan-id").value = data.scan_id || "";
    message.textContent = "Controlled lab pipeline completed.";
  } catch (error) {
    message.className = "status-message error";
    message.textContent = error instanceof Error ? error.message : "Controlled demo failed.";
  } finally {
    setButtonLoading(button, false, "RUN CONTROLLED DEMO", "RUNNING…");
  }
});

$("#lookup-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("#lookup-button");
  const message = $("#lookup-message");
  message.className = "status-message";
  message.textContent = "Loading persisted scan…";
  setButtonLoading(button, true, "LOAD SCAN", "LOADING…");
  try {
    const data = await loadPersistedScan($("#scan-id").value.trim());
    renderResults(data, "Persisted scan");
    message.textContent = `Loaded ${data.scan_id}.`;
  } catch (error) {
    message.className = "status-message error";
    message.textContent = error instanceof Error ? error.message : "Could not load scan.";
  } finally {
    setButtonLoading(button, false, "LOAD SCAN", "LOADING…");
  }
});

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => activateTab(tab.dataset.tab));
});
$("#refresh-health").addEventListener("click", refreshHealth);

populateScenarios();
initializeProgress();
refreshHealth();
