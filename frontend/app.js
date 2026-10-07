const stats = document.getElementById("stats");
const timeline = document.getElementById("timeline");
const stages = document.getElementById("stages");
const entities = document.getElementById("entities");
const response = document.getElementById("response");
const risk = document.getElementById("risk");
const confidence = document.getElementById("confidence");
const graph = document.getElementById("graph");
const reconstruction = document.getElementById("reconstruction");
const reconstructionPill = document.getElementById("reconstructionPill");
const attackIntel = document.getElementById("attackIntel");
const incidentBanner = document.getElementById("incidentBanner");
const pill = document.getElementById("statusPill");
const scenarioSelect = document.getElementById("scenarioSelect");
const phase2Report = document.getElementById("phase2Report");
const phase2Pill = document.getElementById("phase2Pill");
const liveBtn = document.getElementById("liveBtn");
const liveStatus = document.getElementById("liveStatus");
const liveStream = document.getElementById("liveStream");
let liveSocket = null;
let currentAnalysis = null;
const simulateInvestigatorBtn = document.getElementById("simulateInvestigatorBtn");
const investigatorStatus = document.getElementById("investigatorStatus");
const investigatorOutput = document.getElementById("investigatorOutput");

function esc(value) {
  return String(value ?? "").replace(/[&<>"]/g, c => ({
    "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;"
  }[c]));
}

function pretty(name) {
  return String(name).replaceAll("_", " ").replace(/\b\w/g, c => c.toUpperCase());
}

function stat(label, value, tone = "") {
  return `<div class="stat ${tone}"><span>${esc(label)}</span><strong>${esc(value)}</strong></div>`;
}

function pct(value) {
  return `${Math.round((Number(value) || 0) * 100)}%`;
}

function renderGraph(nodes, edges) {
  if (!nodes?.length) {
    graph.innerHTML = '<div class="empty">No validated incident, so no causal entity graph was created.</div>';
    return;
  }

  const width = Math.max(900, nodes.length * 150);
  const height = 330;
  const positions = {};
  const lanes = {User:70, Device:145, IP:220, Application:220, Resource:295};
  const groups = {};

  nodes.forEach(n => {
    groups[n.type] ||= [];
    groups[n.type].push(n);
  });

  for (const [type, group] of Object.entries(groups)) {
    group.forEach((n, i) => {
      positions[n.id] = {
        x: group.length === 1 ? width / 2 : 90 + i * (width - 140) / Math.max(1, group.length - 1),
        y: lanes[type] || 165
      };
    });
  }

  const lines = (edges || []).map(e => {
    const a = positions[e.source], b = positions[e.target];
    if (!a || !b) return "";
    return `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="#4b5d7b" stroke-width="2" marker-end="url(#arrow)" />
      <text x="${(a.x+b.x)/2}" y="${(a.y+b.y)/2-7}" class="edge-label">${esc(e.relation)}</text>`;
  }).join("");

  const circles = nodes.map(n => {
    const p = positions[n.id];
    return `<g>
      <circle cx="${p.x}" cy="${p.y}" r="27" class="node-circle node-${String(n.type).toLowerCase()}" />
      <text x="${p.x}" y="${p.y+4}" text-anchor="middle" class="node-type">${esc(n.type)}</text>
      <text x="${p.x}" y="${p.y+48}" text-anchor="middle" class="node-label">${esc(n.label).slice(0,30)}</text>
    </g>`;
  }).join("");

  graph.innerHTML = `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Attack entity graph">
    <defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto"><path d="M0,0 L0,6 L8,3 z" fill="#4b5d7b"/></marker></defs>
    ${lines}${circles}
  </svg>`;
}

function renderConfidence(incident) {
  const rows = [
    ["Chain completeness", incident.chain_completeness],
    ["Corroboration", incident.corroboration_score],
    ["Temporal consistency", incident.temporal_score],
    ["Entity consistency", incident.entity_consistency_score],
  ];
  confidence.innerHTML = rows.map(([label, value]) => `
    <div class="confidence-row">
      <div><span>${esc(label)}</span><b>${pct(value)}</b></div>
      <div class="mini-meter"><i style="width:${Math.round((value || 0) * 100)}%"></i></div>
    </div>
  `).join("");
}

function renderReconstruction(item) {
  if (!item) {
    reconstructionPill.textContent = "NOT AVAILABLE";
    reconstructionPill.className = "pill";
    reconstruction.innerHTML = '<div class="empty">No deterministic reconstruction because the system did not validate an incident.</div>';
    return;
  }

  reconstructionPill.textContent = item.temporal_valid ? "CAUSAL PATH VALID" : "PATH INVALID";
  reconstructionPill.className = item.temporal_valid ? "pill safe" : "pill danger";

  const selected = (item.selected_event_ids || []).map(id => `<span class="evidence-chip">${esc(id)}</span>`).join("");
  const decoys = (item.decoy_event_ids || []).length
    ? (item.decoy_event_ids || []).map(id => `<span class="decoy-chip">${esc(id)}</span>`).join("")
    : '<span class="muted">None</span>';

  const edges = (item.edges || []).map(e => `
    <div class="recon-edge">
      <div><b>${esc(e.source_event_id)}</b> → <b>${esc(e.target_event_id)}</b></div>
      <span>${esc(e.relation)}</span>
      <small>${esc((e.reasons || []).join(" · "))}</small>
    </div>
  `).join("");

  reconstruction.innerHTML = `
    <div class="recon-summary">
      <div><span>Reconstruction score</span><strong>${pct(item.reconstruction_score)}</strong></div>
      <div><span>Entity conflicts</span><strong>${esc(item.entity_conflicts)}</strong></div>
      <div><span>Selected evidence</span><strong>${esc((item.selected_event_ids || []).length)}</strong></div>
    </div>
    <div class="recon-block"><div class="evidence-title">CAUSAL BACKBONE</div><div class="chip-row">${selected}</div></div>
    <div class="recon-block"><div class="evidence-title">DECOYS REJECTED</div><div class="chip-row">${decoys}</div></div>
    <div class="recon-block"><div class="evidence-title">EDGE REASONS</div>${edges || '<div class="muted">No reconstruction edges recorded.</div>'}</div>
    <p class="recon-explanation">${esc(item.explanation || "No explanation recorded.")}</p>
  `;
}

function renderAttackIntel(items) {
  if (!items?.length) {
    attackIntel.innerHTML = '<div class="empty">No ATT&CK enrichment attached to this result.</div>';
    return;
  }

  attackIntel.innerHTML = items.map(t => `
    <div class="intel-card">
      <div class="intel-top"><b>${esc(t.technique_id)}</b><span>${pct(t.mapping_confidence)}</span></div>
      <strong>${esc(t.name)}</strong>
      <div class="intel-tactic">${esc(t.tactic)}</div>
      <p>${esc(t.rationale)}</p>
      <div class="intel-evidence">${(t.evidence_event_ids || []).map(id => `<span>${esc(id)}</span>`).join("")}</div>
    </div>
  `).join("");
}

function renderResponse(actions) {
  response.innerHTML = (actions || []).map((x, i) => `
    <div class="response-step"><b>${i + 1}</b><span>${esc(x)}</span></div>
  `).join("") || '<div class="empty">No response recommendations attached.</div>';
}

function render(data) {
  currentAnalysis = data;
  simulateInvestigatorBtn.disabled = !data.incidents?.length;
  stats.innerHTML = [
    stat("Events processed", data.total_events),
    stat("Strong signals", data.suspicious_events),
    stat("Watchlist clusters", data.watchlist_candidates),
    stat("Validated incidents", data.correlated_incidents, data.correlated_incidents ? "hot" : ""),
  ].join("");

  const incident = data.incidents?.[0];

  if (!incident) {
    incidentBanner.innerHTML = `
      <div class="banner-safe"><b>NO INCIDENT VALIDATED</b><span>The evidence does not form a complete attack chain, so the engine stays silent.</span></div>`;
    pill.textContent = "BENIGN / SUPPRESSED";
    pill.className = "pill safe";
    timeline.innerHTML = '<div class="empty">No coherent attack chain reconstructed.</div>';
    graph.innerHTML = '<div class="empty">No causal entity graph because no incident was validated.</div>';
    stages.innerHTML = "";
    entities.innerHTML = "";
    renderReconstruction(null);
    renderAttackIntel([]);
    renderResponse([]);
    risk.innerHTML = '<div class="risk-clean">LOW RISK</div><p class="muted">Candidate anomalies remain separate from campaign confidence.</p>';
    confidence.innerHTML = "";
    return;
  }

  incidentBanner.innerHTML = `
    <div class="banner-danger">
      <div><span class="banner-kicker">VALIDATED INCIDENT</span><strong>${esc(incident.title)}</strong></div>
      <div class="banner-reason">${esc(incident.reconstruction?.explanation || "Multiple related events satisfy the evidence-first attack contract.")}</div>
    </div>`;

  pill.textContent = String(incident.severity).toUpperCase();
  pill.className = "pill danger";

  risk.innerHTML = `
    <div class="risk-score">${esc(incident.risk_score)}<span>/100</span></div>
    <div class="meter"><div style="width:${incident.risk_score}%"></div></div>
    <p><strong>${pct(incident.confidence)}</strong> campaign confidence</p>
    <p class="muted">${esc(incident.evidence_count)} supporting events · status: ${esc(incident.status)}</p>
  `;
  renderConfidence(incident);

  timeline.innerHTML = (incident.timeline || []).map((e, i) => `
    <div class="event">
      <div class="dot ${i === 0 ? "first" : ""}"></div>
      <div>
        <div class="time">${new Date(e.timestamp).toLocaleTimeString()}</div>
        <strong>${esc(pretty(e.event_type))}</strong>
        <div class="muted">${esc(e.event_id)} · ${esc(e.source)}</div>
        <div class="event-meta">${[e.user, e.device, e.src_ip, e.application, e.resource].filter(Boolean).map(esc).join(" · ")}</div>
      </div>
    </div>
  `).join("");

  renderGraph(incident.graph_nodes, incident.graph_edges);

  stages.innerHTML = (incident.stages || []).map(s => `
    <div class="stage">
      <div class="stage-top">
        <strong>${esc(s.stage)}</strong>
        <span>${pct(s.confidence)}</span>
      </div>
      <div class="tech">${esc(s.technique || "Behavioral correlation")}</div>
      <p>${esc(s.reason)}</p>
      <div class="evidence-title">PROOF</div>
      ${(s.evidence || []).map(ev => `<div class="evidence"><b>${esc(ev.event_id)}</b> — ${esc(ev.reason)}</div>`).join("")}
    </div>
  `).join("");

  entities.innerHTML = (incident.entities || []).map(x => `<span class="chip">${esc(x)}</span>`).join("");
  renderReconstruction(incident.reconstruction);
  renderAttackIntel(incident.attack_techniques);
  renderResponse(incident.recommended_actions);
}

function renderInvestigator(report) {
  investigatorOutput.innerHTML = `
    <div class="investigator-summary">${esc(report.summary)}</div>
    <div class="evidence-title">GROUNDED CLAIMS</div>
    ${(report.claims || []).map(claim => `
      <div class="investigator-claim">
        <div><b>${esc(claim.claim_type.toUpperCase())}</b> · ${pct(claim.confidence)}</div>
        <p>${esc(claim.claim)}</p>
        <div class="chip-row">${(claim.evidence_event_ids || []).map(esc).map(id => `<span class="evidence-chip">${id}</span>`).join("")}</div>
      </div>
    `).join("")}
    <div class="evidence-title">UNANSWERED QUESTIONS</div>
    ${(report.unanswered_questions || []).map(q => `<div class="muted">• ${esc(q)}</div>`).join("")}
  `;
}

async function runSimulatedInvestigator() {
  if (!currentAnalysis?.incidents?.length) return;
  const incident = currentAnalysis.incidents[0];
  investigatorStatus.textContent = "SIMULATING";
  investigatorStatus.className = "pill";
  investigatorOutput.innerHTML = '<div class="empty">Building a grounded analyst report from validated evidence…</div>';
  simulateInvestigatorBtn.disabled = true;
  await new Promise(resolve => setTimeout(resolve, 900));
  try {
    const res = await fetch("/api/investigate/simulated", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({events: incident.timeline, incident_id: incident.incident_id})
    });
    if (!res.ok) throw new Error(`Request failed: ${res.status}`);
    const report = await res.json();
    renderInvestigator(report);
    investigatorStatus.textContent = "SIMULATION";
    investigatorStatus.className = "pill safe";
  } catch (error) {
    investigatorStatus.textContent = "ERROR";
    investigatorStatus.className = "pill danger";
    investigatorOutput.innerHTML = `<div class="banner-danger"><b>INVESTIGATOR ERROR</b><span>${esc(error.message)}</span></div>`;
  } finally {
    simulateInvestigatorBtn.disabled = !currentAnalysis?.incidents?.length;
  }
}

function setLiveStatus(label, tone = "") {
  liveStatus.textContent = label;
  liveStatus.className = tone ? `pill ${tone}` : "pill";
}

function appendLiveEvent(event, analysis) {
  if (liveStream.querySelector(".empty")) liveStream.innerHTML = "";
  const incident = analysis.incidents?.[0];
  const row = document.createElement("div");
  row.className = "live-event";
  row.innerHTML = `
    <div class="live-dot"></div>
    <div class="live-event-main">
      <div class="live-event-top">
        <strong>${esc(pretty(event.event_type))}</strong>
        <span>${esc(event.event_id)}</span>
      </div>
      <div class="muted">${esc(event.timestamp)} · ${esc(event.source)}</div>
      <div class="event-meta">${[event.user, event.device, event.src_ip, event.resource].filter(Boolean).map(esc).join(" · ")}</div>
    </div>
    <span class="pill ${incident ? "danger" : "safe"}">${incident ? "INCIDENT" : "OBSERVED"}</span>
  `;
  liveStream.appendChild(row);
  liveStream.scrollTop = liveStream.scrollHeight;
}

function stopLiveSimulation() {
  if (liveSocket) {
    liveSocket.close();
    liveSocket = null;
  }
  liveBtn.textContent = "Start Live Simulation";
  liveBtn.disabled = false;
}

function startLiveSimulation() {
  if (liveSocket) return;
  const scenario = scenarioSelect.value || "full_attack";
  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  const socketUrl = `${protocol}//${location.host}/ws/simulate/${encodeURIComponent(scenario)}?delay=0.9`;
  liveStream.innerHTML = "";
  setLiveStatus("CONNECTING");
  liveBtn.textContent = "Stop Simulation";
  liveSocket = new WebSocket(socketUrl);

  liveSocket.onopen = () => setLiveStatus("STREAMING");
  liveSocket.onmessage = (message) => {
    const payload = JSON.parse(message.data);
    if (payload.type === "start") {
      setLiveStatus("STREAMING");
      return;
    }
    if (payload.type === "event") {
      appendLiveEvent(payload.event, payload.analysis);
      render(payload.analysis);
      return;
    }
    if (payload.type === "complete") {
      render(payload.analysis);
      setLiveStatus("COMPLETE", payload.analysis.correlated_incidents ? "danger" : "safe");
      stopLiveSimulation();
      return;
    }
    if (payload.type === "error") {
      setLiveStatus("ERROR", "danger");
      liveStream.innerHTML = `<div class="banner-danger"><b>STREAM ERROR</b><span>${esc(payload.message)}</span></div>`;
      stopLiveSimulation();
    }
  };
  liveSocket.onerror = () => {
    setLiveStatus("ERROR", "danger");
    liveStream.innerHTML = '<div class="banner-danger"><b>STREAM ERROR</b><span>Could not connect to the simulation stream.</span></div>';
    stopLiveSimulation();
  };
  liveSocket.onclose = () => {
    liveSocket = null;
    if (liveBtn.textContent === "Stop Simulation") stopLiveSimulation();
  };
}

async function load(path) {
  try {
    const res = await fetch(path);
    if (!res.ok) throw new Error(`Request failed: ${res.status}`);
    render(await res.json());
  } catch (error) {
    incidentBanner.innerHTML = `<div class="banner-danger"><b>DEMO ERROR</b><span>${esc(error.message)}</span></div>`;
  }
}

async function loadPhase2Report() {
  const res = await fetch("/api/phase2/report");
  const data = await res.json();

  const status = data.failed_cases === 0 && data.false_positive_cases === 0 && data.missed_attack_cases === 0;
  phase2Pill.textContent = status ? "PASS" : "FAIL";
  phase2Pill.className = status ? "pill safe" : "pill danger";

  phase2Report.innerHTML = `
    <div class="validation-stat"><span>Cases</span><strong>${data.total_cases}</strong></div>
    <div class="validation-stat"><span>Passed</span><strong>${data.passed_cases}</strong></div>
    <div class="validation-stat"><span>Accuracy</span><strong>${pct(data.accuracy)}</strong></div>
    <div class="validation-stat"><span>False Positives</span><strong>${data.false_positive_cases}</strong></div>
    <div class="validation-stat"><span>Missed Attacks</span><strong>${data.missed_attack_cases}</strong></div>
    <div class="validation-stat"><span>Watchlist</span><strong>${data.watchlist_cases}</strong></div>
  `;

  if (data.failed_cases > 0) {
    phase2Report.innerHTML += `
      <div class="validation-failures">
        <strong>Cases needing fixes</strong>
        ${data.cases.filter(c => !c.passed).map(c => `<div>${esc(pretty(c.scenario))} — expected <b>${esc(c.expected)}</b>, got <b>${esc(c.actual)}</b></div>`).join("")}
      </div>
    `;
  }
}

async function loadScenarios() {
  const res = await fetch("/api/scenarios");
  const data = await res.json();
  scenarioSelect.innerHTML = data.scenarios.map(name => `<option value="${esc(name)}">${esc(pretty(name))}</option>`).join("");
  scenarioSelect.value = "full_attack";
}

document.getElementById("attackBtn").onclick = () => load("/api/demo/full_attack");
liveBtn.onclick = () => liveSocket ? stopLiveSimulation() : startLiveSimulation();
simulateInvestigatorBtn.onclick = runSimulatedInvestigator;
document.getElementById("cleanBtn").onclick = () => load("/api/demo/clean");
document.getElementById("scenarioBtn").onclick = () => load(`/api/demo/${encodeURIComponent(scenarioSelect.value)}`);

loadScenarios();
loadPhase2Report();
render({total_events:0,suspicious_events:0,watchlist_candidates:0,correlated_incidents:0,incidents:[],suppressed:true});

document.getElementById("uploadBtn").onclick = async () => {
  const input = document.getElementById("logFile");
  if (!input.files?.length) {
    incidentBanner.innerHTML = '<div class="banner-danger"><b>UPLOAD ERROR</b><span>Select a log file first.</span></div>';
    return;
  }
  const form = new FormData();
  form.append("file", input.files[0]);
  try {
    const res = await fetch("/api/analyze/upload", { method: "POST", body: form });
    if (!res.ok) throw new Error(`Request failed: ${res.status}`);
    render(await res.json());
  } catch (error) {
    incidentBanner.innerHTML = `<div class="banner-danger"><b>UPLOAD ERROR</b><span>${esc(error.message)}</span></div>`;
  }
};
