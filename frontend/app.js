const stats = document.getElementById("stats");
const timeline = document.getElementById("timeline");
const stages = document.getElementById("stages");
const entities = document.getElementById("entities");
const response = document.getElementById("response");
const risk = document.getElementById("risk");
const pill = document.getElementById("statusPill");

function stat(label, value) {
  return `<div class="stat"><span>${label}</span><strong>${value}</strong></div>`;
}

function render(data) {
  stats.innerHTML = [
    stat("Events processed", data.total_events),
    stat("Suspicious signals", data.suspicious_events),
    stat("Validated incidents", data.correlated_incidents),
    stat("Suppressed", data.suppressed ? "YES" : "NO"),
  ].join("");

  const incident = data.incidents[0];

  if (!incident) {
    pill.textContent = "BENIGN / SUPPRESSED";
    pill.className = "pill safe";
    timeline.innerHTML = '<div class="empty">No coherent attack chain. The system stayed quiet.</div>';
    stages.innerHTML = "";
    entities.innerHTML = "";
    response.innerHTML = '<div class="empty">No response action recommended.</div>';
    risk.innerHTML = '<div class="risk-clean">LOW RISK</div>';
    return;
  }

  pill.textContent = incident.severity.toUpperCase();
  pill.className = "pill danger";

  risk.innerHTML = `
    <div class="risk-score">${incident.risk_score}<span>/100</span></div>
    <div class="meter"><div style="width:${incident.risk_score}%"></div></div>
    <p><strong>${Math.round(incident.confidence * 100)}%</strong> campaign confidence</p>
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

document.getElementById("attackBtn").onclick = () => load("/api/demo/attack");
document.getElementById("cleanBtn").onclick = () => load("/api/demo/clean");

load("/api/demo/attack");
