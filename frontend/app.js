const stats = document.getElementById("stats");
const timeline = document.getElementById("timeline");
const stages = document.getElementById("stages");
const entities = document.getElementById("entities");
const response = document.getElementById("response");
const risk = document.getElementById("risk");
const graph = document.getElementById("graph");
const pill = document.getElementById("statusPill");
const scenarioSelect = document.getElementById("scenarioSelect");
const phase2Report = document.getElementById("phase2Report");
const phase2Pill = document.getElementById("phase2Pill");

function stat(label, value) {
  return `<div class="stat"><span>${label}</span><strong>${value}</strong></div>`;
}

function esc(value) {
  return String(value).replace(/[&<>"]/g, c => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;" }[c]));
}

function pretty(name) {
  return name.replaceAll("_", " ").replace(/w/g, c => c.toUpperCase());
}

function renderGraph(nodes, edges) {
  if (!nodes?.length) {
    graph.innerHTML = '<div class="empty">No attack graph because no incident was validated.</div>';
    return;
  }

  const width = Math.max(760, nodes.length * 150);
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
        x: 90 + i * (width - 140) / Math.max(1, group.length - 1),
        y: lanes[type] || 165
      };
    });
  }

  const lines = edges.map(e => {
    const a = positions[e.source], b = positions[e.target];
    if (!a || !b) return "";
    return `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="#4b5d7b" stroke-width="2" marker-end="url(#arrow)" />
      <text x="${(a.x+b.x)/2}" y="${(a.y+b.y)/2-7}" class="edge-label">${esc(e.relation)}</text>`;
  }).join("");

  const circles = nodes.map(n => {
    const p = positions[n.id];
    return `<g><circle cx="${p.x}" cy="${p.y}" r="27" class="node-circle node-${n.type.toLowerCase()}" />
      <text x="${p.x}" y="${p.y+4}" text-anchor="middle" class="node-type">${esc(n.type)}</text>
      <text x="${p.x}" y="${p.y+48}" text-anchor="middle" class="node-label">${esc(n.label).slice(0,22)}</text></g>`;
  }).join("");

  graph.innerHTML = `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Attack entity graph">
    <defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto"><path d="M0,0 L0,6 L8,3 z" fill="#4b5d7b"/></marker></defs>
    ${lines}${circles}
  </svg>`;
}

function render(data) {
  stats.innerHTML = [
    stat("Events processed", data.total_events),
    stat("Strong signals", data.suspicious_events),
    stat("Watchlist clusters", data.watchlist_candidates),
    stat("Validated incidents", data.correlated_incidents),
  ].join("");

  const incident = data.incidents[0];

  if (!incident) {
    pill.textContent = "BENIGN / SUPPRESSED";
    pill.className = "pill safe";
    timeline.innerHTML = '<div class="empty">No coherent attack chain. The system stayed quiet.</div>';
    graph.innerHTML = '<div class="empty">No attack graph because no incident was validated.</div>';
    stages.innerHTML = "";
    entities.innerHTML = "";
    response.innerHTML = `<div class="empty">${data.suppressed_events} candidate events were suppressed from becoming an incident.</div>`;
    risk.innerHTML = '<div class="risk-clean">LOW RISK</div>';
    return;
  }

  pill.textContent = incident.severity.toUpperCase();
  pill.className = "pill danger";

  risk.innerHTML = `
    <div class="risk-score">${incident.risk_score}<span>/100</span></div>
    <div class="meter"><div style="width:${incident.risk_score}%"></div></div>
    <p><strong>${Math.round(incident.confidence * 100)}%</strong> campaign confidence</p>
    <p class="muted">Completeness ${Math.round(incident.chain_completeness * 100)}% · entity consistency ${Math.round(incident.entity_consistency_score * 100)}%</p>
    <p class="muted">${incident.evidence_count} supporting events · status: ${incident.status}</p>
  `;

  timeline.innerHTML = incident.timeline.map(e => `
    <div class="event">
      <div class="dot"></div>
      <div>
        <div class="time">${new Date(e.timestamp).toLocaleTimeString()}</div>
        <strong>${e.event_type.replaceAll("_", " ")}</strong>
        <div class="muted">${e.event_id} · ${e.source}</div>
        <div class="event-meta">${[e.user, e.device, e.src_ip, e.application, e.resource].filter(Boolean).join(" · ")}</div>
      </div>
    </div>
  `).join("");

  renderGraph(incident.graph_nodes, incident.graph_edges);

  stages.innerHTML = incident.stages.map(s => `
    <div class="stage">
      <div class="stage-top">
        <strong>${s.stage}</strong>
        <span>${Math.round(s.confidence * 100)}%</span>
      </div>
      <div class="tech">${s.technique || "Behavioral correlation"}</div>
      <p>${s.reason}</p>
      <div class="evidence-title">PROOF</div>
      ${s.evidence.map(ev => `<div class="evidence"><b>${ev.event_id}</b> — ${ev.reason}</div>`).join("")}
    </div>
  `).join("");

  entities.innerHTML = incident.entities.map(x => `<span class="chip">${x}</span>`).join("");
  response.innerHTML = incident.recommended_actions.map(x => `<div class="action">${x}</div>`).join("");
}

async function load(path) {
  const res = await fetch(path);
  const data = await res.json();
  render(data);
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
    <div class="validation-stat"><span>Accuracy</span><strong>${Math.round(data.accuracy * 100)}%</strong></div>
    <div class="validation-stat"><span>False Positives</span><strong>${data.false_positive_cases}</strong></div>
    <div class="validation-stat"><span>Missed Attacks</span><strong>${data.missed_attack_cases}</strong></div>
    <div class="validation-stat"><span>Watchlist</span><strong>${data.watchlist_cases}</strong></div>
  `;

  if (data.failed_cases > 0) {
    phase2Report.innerHTML += `
      <div class="validation-failures">
        <strong>Cases needing fixes</strong>
        ${data.cases.filter(c => !c.passed).map(c => `<div>${pretty(c.scenario)} — expected <b>${c.expected}</b>, got <b>${c.actual}</b></div>`).join("")}
      </div>
    `;
  }
}

async function loadScenarios() {
  const res = await fetch("/api/scenarios");
  const data = await res.json();
  scenarioSelect.innerHTML = data.scenarios.map(name => `<option value="${name}">${pretty(name)}</option>`).join("");
  scenarioSelect.value = "full_attack";
}

document.getElementById("attackBtn").onclick = () => load("/api/demo/full_attack");
document.getElementById("cleanBtn").onclick = () => load("/api/demo/clean");
document.getElementById("scenarioBtn").onclick = () => load(`/api/demo/${scenarioSelect.value}`);

loadScenarios();
loadPhase2Report();
load("/api/demo/full_attack");
