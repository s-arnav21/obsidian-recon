const scenarios = [
  {
    id: "generic_local_web_validation",
    label: "Generic local web validation (live loopback)",
  },
  {
    id: "public_app_validation",
    label: "Public application validation (fixture / DVWA lab)",
  },
];

const form = document.querySelector("#harness-form");
const scenarioSelect = document.querySelector("#scenario");
const runButton = document.querySelector("#run-button");
const statusMessage = document.querySelector("#status-message");
const results = document.querySelector("#results");
const resultCards = document.querySelector("#result-cards");
const resultMode = document.querySelector("#result-mode");
const rawJson = document.querySelector("#raw-json");

function populateScenarios() {
  scenarios.forEach((scenario) => {
    const option = document.createElement("option");
    option.value = scenario.id;
    option.textContent = scenario.label;
    scenarioSelect.append(option);
  });
}

async function postTestHarnessRun(requestBody) {
  const response = await fetch("/api/test-harness/run", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(requestBody),
  });
  const body = await response.json();
  if (!response.ok) {
    const detail = typeof body.detail === "string"
      ? body.detail
      : "The backend rejected the request.";
    throw new Error(detail);
  }
  return body;
}

function displayValue(value) {
  if (value === null || value === undefined || value === "") {
    return "—";
  }
  if (typeof value === "object") {
    return JSON.stringify(value, null, 2);
  }
  return String(value);
}

function addResultCard(label, value) {
  const card = document.createElement("article");
  card.className = "result-card";
  const heading = document.createElement("h3");
  heading.textContent = label;
  const content = document.createElement("p");
  content.textContent = displayValue(value);
  card.append(heading, content);
  resultCards.append(card);
}

function renderResult(data) {
  if (data.validations && typeof data.validations === "object") {
    renderGenericResult(data);
    return;
  }

  const finding = data.finding || {};
  const validation = data.validation_result || {};
  const technique = data.technique || {};
  const chain = data.chain_result || {};
  const firstChain = Array.isArray(chain.chains) ? chain.chains[0] : null;

  resultCards.replaceChildren();
  [
    ["Validation status", validation.status],
    ["Confidence", validation.confidence],
    ["Vulnerability type", finding.vulnerability_type],
    ["MITRE technique", technique.technique_id
      ? `${technique.technique_id} — ${technique.technique_name}`
      : null],
    ["MITRE tactic", technique.tactic],
    ["Target", finding.target],
    ["Finding ID", finding.finding_id],
    ["Scan ID", finding.scan_id],
    ["Asset ID", finding.asset_id],
    ["Evidence", validation.evidence],
    ["Evidence references", data.evidence_refs],
    ["Capabilities gained", firstChain?.capabilities_gained],
    ["Attack-chain status", chain.status],
    ["Attack-chain steps", firstChain?.steps],
  ].forEach(([label, value]) => addResultCard(label, value));

  resultMode.textContent = data.mode || "result";
  rawJson.textContent = JSON.stringify(data, null, 2);
  results.hidden = false;
}

function renderGenericResult(data) {
  const validations = Object.entries(data.validations || {});
  const chain = data.chain_result || {};

  resultCards.replaceChildren();
  addResultCard("Overall pipeline status", data.overall_status);
  addResultCard("Attack-chain status", chain.status);

  validations.forEach(([name, item]) => {
    const finding = item.finding || {};
    const validation = item.validation_result || {};
    const technique = finding.mitre_technique_id
      ? `${finding.mitre_technique_id} — ${finding.mitre_technique_name}`
      : "Unresolved";
    addResultCard(`${name.replaceAll("_", " ")} finding`, {
      vulnerability_type: finding.vulnerability_type,
      validation_status: validation.status,
      confidence: validation.confidence,
      validator: validation.validator,
      scanner_template_id: finding.template_id,
      mitre_technique: technique,
      capabilities: finding.provides,
    });
  });

  addResultCard("Attack chains", chain.chains);
  addResultCard(
    "Chain steps",
    Array.isArray(chain.chains)
      ? chain.chains.map((item) => ({
        chain_id: item.chain_id,
        status: item.status,
        steps: item.steps,
      }))
      : null,
  );

  resultMode.textContent = data.mode || "result";
  rawJson.textContent = JSON.stringify(data, null, 2);
  results.hidden = false;
}

function setLoading(isLoading) {
  runButton.disabled = isLoading;
  runButton.textContent = isLoading ? "RUNNING…" : "RUN TEST";
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  results.hidden = true;
  statusMessage.className = "status-message";
  statusMessage.textContent = "Running configured backend validation…";
  setLoading(true);

  const requestBody = {
    target_url: document.querySelector("#target-url").value,
    scenario: scenarioSelect.value,
    authorized: document.querySelector("#authorized").checked,
  };

  try {
    const data = await postTestHarnessRun(requestBody);
    renderResult(data);
    statusMessage.textContent = `${data.mode || "Backend"} pipeline completed.`;
  } catch (error) {
    statusMessage.className = "status-message error";
    statusMessage.textContent = error instanceof Error
      ? error.message
      : "Unexpected request error.";
  } finally {
    setLoading(false);
  }
});

populateScenarios();
