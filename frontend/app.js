const stats=document.getElementById("stats");
const hypotheses=document.getElementById("hypotheses");
const hypothesisPill=document.getElementById("hypothesisPill");
const timeline=document.getElementById("timeline");
const timelineCount=document.getElementById("timelineCount");
const stages=document.getElementById("stages");
const entities=document.getElementById("entities");
const response=document.getElementById("response");
const risk=document.getElementById("risk");
const confidence=document.getElementById("confidence");
const graph=document.getElementById("graph");
const reconstruction=document.getElementById("reconstruction");
const reconstructionPill=document.getElementById("reconstructionPill");
const attackIntel=document.getElementById("attackIntel");
const incidentBanner=document.getElementById("incidentBanner");
const statusPill=document.getElementById("statusPill");
const resultTitle=document.getElementById("resultTitle");
const resultSummary=document.getElementById("resultSummary");
const scenarioSelect=document.getElementById("scenarioSelect");
const phase2Report=document.getElementById("phase2Report");
const phase2Pill=document.getElementById("phase2Pill");
const liveBtn=document.getElementById("liveBtn");
const liveStatus=document.getElementById("liveStatus");
const liveStream=document.getElementById("liveStream");
const simulateInvestigatorBtn=document.getElementById("simulateInvestigatorBtn");
const investigatorStatus=document.getElementById("investigatorStatus");
const investigatorOutput=document.getElementById("investigatorOutput");
const logFile=document.getElementById("logFile");
let liveSocket=null;
let currentAnalysis=null;

function esc(value){return String(value??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}
function pretty(name){return String(name??"").replaceAll("_"," ").replace(/\b\w/g,c=>c.toUpperCase());}
function stat(label,value,tone=""){return `<div class="stat ${tone}"><span>${esc(label)}</span><strong>${esc(value)}</strong></div>`;}
function pct(value){return `${Math.round((Number(value)||0)*100)}%`;}

function setActiveTab(name){
  const valid=["overview","evidence","reconstruction","intelligence","tools"];
  if(!valid.includes(name))name="overview";
  document.querySelectorAll(".tab").forEach(tab=>{
    const active=tab.dataset.tab===name;
    tab.classList.toggle("active",active);
    tab.setAttribute("aria-selected",String(active));
  });
  document.querySelectorAll(".tab-panel").forEach(panel=>{
    const active=panel.id===`tab-${name}`;
    panel.classList.toggle("active",active);
    panel.hidden=!active;
  });
  if(location.hash!==`#${name}`)history.replaceState(null,"",`#${name}`);
  window.scrollTo({top:0,behavior:"smooth"});
}
function restoreTab(){setActiveTab(location.hash.replace("#","")||"overview");}
function showError(title,message){resultTitle.textContent=title;resultSummary.textContent=message;incidentBanner.innerHTML=`<div class="banner-danger"><strong>${esc(title)}</strong><span>${esc(message)}</span></div>`;}

function renderHypotheses(items){
  if(!items?.length){hypothesisPill.textContent="NONE";hypothesisPill.className="pill safe";hypotheses.innerHTML='<div class="empty">No incomplete or contradictory campaign hypothesis was produced.</div>';return;}
  const contradictory=items.some(item=>!item.temporal_valid);
  hypothesisPill.textContent=contradictory?"REVIEW":`${items.length} FOUND`;
  hypothesisPill.className=contradictory?"pill danger":"pill";
  hypotheses.innerHTML=items.map(item=>`
    <article class="hypothesis-card">
      <div class="hypothesis-top"><div><strong>${esc(item.hypothesis_id)}</strong><span>${pct(item.confidence)}</span></div><span class="pill ${item.temporal_valid?"safe":"danger"}">${item.temporal_valid?"ORDERED":"CONTRADICTORY"}</span></div>
      <div class="hypothesis-stages"><div><span>OBSERVED</span><b>${esc((item.observed_stages||[]).join(" → ")||"None")}</b></div><div><span>MISSING</span><b>${esc((item.missing_stages||[]).join(" · ")||"None")}</b></div></div>
      <div class="chip-row">${(item.evidence_event_ids||[]).map(id=>`<span class="evidence-chip">${esc(id)}</span>`).join("")}</div>
      <p>${esc(item.reason)}</p>
    </article>`).join("");
}

function renderGraph(nodes,edges){
  if(!nodes?.length){graph.innerHTML='<div class="empty">No causal entity graph because no incident was validated.</div>';return;}
  const width=Math.max(820,nodes.length*145),height=290,positions={},lanes={User:55,Device:125,IP:195,Application:195,Resource:255},groups={};
  nodes.forEach(n=>{(groups[n.type]??=[]).push(n);});
  Object.entries(groups).forEach(([type,group])=>group.forEach((n,i)=>{positions[n.id]={x:group.length===1?width/2:85+i*(width-140)/Math.max(1,group.length-1),y:lanes[type]||145};}));
  const lines=(edges||[]).map(e=>{const a=positions[e.source],b=positions[e.target];if(!a||!b)return"";return `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" class="graph-edge" marker-end="url(#arrow)"/><text x="${(a.x+b.x)/2}" y="${(a.y+b.y)/2-7}" class="edge-label">${esc(e.relation)}</text>`;}).join("");
  const circles=nodes.map(n=>{const p=positions[n.id];return `<g><circle cx="${p.x}" cy="${p.y}" r="24" class="node-circle node-${String(n.type).toLowerCase()}"/><text x="${p.x}" y="${p.y+3}" text-anchor="middle" class="node-type">${esc(n.type)}</text><text x="${p.x}" y="${p.y+42}" text-anchor="middle" class="node-label">${esc(n.label).slice(0,28)}</text></g>`;}).join("");
  graph.innerHTML=`<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Attack entity graph"><defs><marker id="arrow" markerWidth="7" markerHeight="7" refX="6" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" class="arrow-head"/></marker></defs>${lines}${circles}</svg>`;
}

function renderConfidence(incident){
  const rows=[["Chain completeness",incident.chain_completeness],["Corroboration",incident.corroboration_score],["Temporal consistency",incident.temporal_score],["Entity consistency",incident.entity_consistency_score]];
  confidence.innerHTML=rows.map(([label,value])=>`<div class="confidence-row"><div><span>${esc(label)}</span><b>${pct(value)}</b></div><div class="mini-meter"><i style="width:${Math.round((Number(value)||0)*100)}%"></i></div></div>`).join("");
}
function renderReconstruction(item){
  if(!item){reconstructionPill.textContent="NOT AVAILABLE";reconstructionPill.className="pill";reconstruction.innerHTML='<div class="empty">No deterministic reconstruction because the system did not validate an incident.</div>';return;}
  reconstructionPill.textContent=item.temporal_valid?"CAUSAL PATH VALID":"PATH INVALID";reconstructionPill.className=item.temporal_valid?"pill safe":"pill danger";
  const selected=(item.selected_event_ids||[]).map(id=>`<span class="evidence-chip">${esc(id)}</span>`).join("");
  const decoys=(item.decoy_event_ids||[]).length?(item.decoy_event_ids||[]).map(id=>`<span class="decoy-chip">${esc(id)}</span>`).join(""):'<span class="muted">None</span>';
  const edges=(item.edges||[]).map(e=>`<div class="recon-edge"><div><b>${esc(e.source_event_id)}</b> → <b>${esc(e.target_event_id)}</b></div><span>${esc(e.relation)}</span><small>${esc((e.reasons||[]).join(" · "))}</small></div>`).join("");
  reconstruction.innerHTML=`<div class="recon-summary"><div><span>Reconstruction score</span><strong>${pct(item.reconstruction_score)}</strong></div><div><span>Entity conflicts</span><strong>${esc(item.entity_conflicts)}</strong></div><div><span>Selected evidence</span><strong>${esc((item.selected_event_ids||[]).length)}</strong></div></div><div class="recon-block"><div class="evidence-title">CAUSAL BACKBONE</div><div class="chip-row">${selected}</div></div><div class="recon-block"><div class="evidence-title">DECOYS REJECTED</div><div class="chip-row">${decoys}</div></div><div class="recon-block"><div class="evidence-title">EDGE REASONS</div>${edges||'<div class="muted">No reconstruction edges recorded.</div>'}</div><p class="recon-explanation">${esc(item.explanation||"No explanation recorded.")}</p>`;
}
function renderAttackIntel(items){
  if(!items?.length){attackIntel.innerHTML='<div class="empty">No ATT&CK enrichment attached to this result.</div>';return;}
  attackIntel.innerHTML=items.map(t=>`<div class="intel-card"><div class="intel-top"><b>${esc(t.technique_id)}</b><span>${pct(t.mapping_confidence)}</span></div><strong>${esc(t.name)}</strong><div class="intel-tactic">${esc(t.tactic)}</div><p>${esc(t.rationale)}</p><div class="intel-evidence">${(t.evidence_event_ids||[]).map(id=>`<span>${esc(id)}</span>`).join("")}</div></div>`).join("");
}
function renderResponse(actions){response.innerHTML=(actions||[]).map((x,i)=>`<div class="response-step"><b>${i+1}</b><span>${esc(x)}</span></div>`).join("")||'<div class="empty">No response recommendations attached.</div>';}

function render(data){
  currentAnalysis=data;
  const incident=data.incidents?.[0];
  stats.innerHTML=[stat("Events processed",data.total_events),stat("Strong signals",data.suspicious_events),stat("Watchlist clusters",data.watchlist_candidates),stat("Validated incidents",data.correlated_incidents,data.correlated_incidents?"hot":"")].join("");
  renderHypotheses(data.campaign_hypotheses||[]);
  simulateInvestigatorBtn.disabled=!incident;

  if(!incident){
    const hasHypothesis=Boolean(data.campaign_hypotheses?.length);
    resultTitle.textContent=hasHypothesis?"Campaign hypothesis":"No incident validated";
    resultSummary.textContent=hasHypothesis?"Related evidence exists, but the required chain is incomplete.":"The evidence does not form a complete attack chain, so the engine stays silent.";
    incidentBanner.innerHTML=hasHypothesis?'<div class="banner-safe"><strong>NO VALIDATED INCIDENT</strong><span>Open Evidence to inspect the observed and missing stages.</span></div>':'<div class="banner-safe"><strong>NO INCIDENT VALIDATED</strong><span>Candidate anomalies remain separate from campaign confidence.</span></div>';
    statusPill.textContent=hasHypothesis?"WATCHLIST":"SUPPRESSED";statusPill.className=hasHypothesis?"pill":"pill safe";
    timeline.innerHTML='<div class="empty">No coherent attack chain reconstructed.</div>';timelineCount.textContent="0 events";
    graph.innerHTML='<div class="empty">No causal entity graph because no incident was validated.</div>';stages.innerHTML="";entities.innerHTML="";
    renderReconstruction(null);renderAttackIntel([]);renderResponse([]);risk.innerHTML='<div class="risk-clean">LOW RISK</div><p class="muted">Anomalies are not promoted to incident status without complete, coherent evidence.</p>';confidence.innerHTML="";return;
  }
  resultTitle.textContent=incident.title;resultSummary.textContent=`${incident.evidence_count} evidence events support the validated chain across ${incident.stages.length} required stages.`;
  incidentBanner.innerHTML=`<div class="banner-danger"><div><strong>VALIDATED INCIDENT</strong><span>${esc(incident.title)}</span></div><span>${esc(incident.reconstruction?.explanation||"Multiple related events satisfy the evidence-first attack contract.")}</span></div>`;
  statusPill.textContent=String(incident.severity).toUpperCase();statusPill.className="pill danger";
  risk.innerHTML=`<div class="risk-score">${esc(incident.risk_score)}<span>/100</span></div><div class="meter"><div style="width:${Math.max(0,Math.min(100,Number(incident.risk_score)||0))}%"></div></div><p><strong>${pct(incident.confidence)}</strong> campaign confidence</p><p class="muted">${esc(incident.evidence_count)} supporting events · status: ${esc(incident.status)}</p>`;
  renderConfidence(incident);timelineCount.textContent=`${incident.timeline?.length||0} events`;
  timeline.innerHTML=(incident.timeline||[]).map((e,i)=>`<div class="event"><div class="dot ${i===0?"first":""}"></div><div><div class="time">${esc(new Date(e.timestamp).toLocaleString())}</div><strong>${esc(pretty(e.event_type))}</strong><div class="muted">${esc(e.event_id)} · ${esc(e.source)}</div><div class="event-meta">${[e.user,e.device,e.src_ip,e.application,e.resource].filter(Boolean).map(esc).join(" · ")}</div></div></div>`).join("")||'<div class="empty">No timeline events.</div>';
  renderGraph(incident.graph_nodes,incident.graph_edges);
  stages.innerHTML=(incident.stages||[]).map(s=>`<div class="stage"><div class="stage-top"><strong>${esc(s.stage)}</strong><span>${pct(s.confidence)}</span></div><div class="tech">${esc(s.technique||"Behavioral correlation")}</div><p>${esc(s.reason)}</p><div class="evidence-title">PROOF</div>${(s.evidence||[]).map(ev=>`<div class="evidence"><b>${esc(ev.event_id)}</b> · ${esc(ev.reason)}</div>`).join("")}</div>`).join("");
  entities.innerHTML=(incident.entities||[]).map(x=>`<span class="chip">${esc(x)}</span>`).join("")||'<div class="empty">No entities attached.</div>';
  renderReconstruction(incident.reconstruction);renderAttackIntel(incident.attack_techniques);renderResponse(incident.recommended_actions);
}

function renderInvestigator(report){
  investigatorOutput.innerHTML=`<div class="investigator-summary">${esc(report.summary)}</div><div class="evidence-title">GROUNDED CLAIMS</div>${(report.claims||[]).map(claim=>`<div class="investigator-claim"><div><b>${esc(claim.claim_type.toUpperCase())}</b> · ${pct(claim.confidence)}</div><p>${esc(claim.claim)}</p><div class="chip-row">${(claim.evidence_event_ids||[]).map(id=>`<span class="evidence-chip">${esc(id)}</span>`).join("")}</div></div>`).join("")}<div class="evidence-title">UNANSWERED QUESTIONS</div>${(report.unanswered_questions||[]).map(q=>`<div class="muted">${esc(q)}</div>`).join("")||'<div class="muted">None recorded.</div>'}`;
}
async function runSimulatedInvestigator(){
  const incident=currentAnalysis?.incidents?.[0];if(!incident)return;
  setActiveTab("tools");investigatorStatus.textContent="GENERATING";investigatorStatus.className="pill";investigatorOutput.innerHTML='<div class="empty">Building the report from validated evidence…</div>';simulateInvestigatorBtn.disabled=true;
  try{const res=await fetch("/api/investigate/simulated",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({events:incident.timeline,incident_id:incident.incident_id})});if(!res.ok)throw new Error(`Request failed: ${res.status}`);renderInvestigator(await res.json());investigatorStatus.textContent="READY";investigatorStatus.className="pill safe";}
  catch(error){investigatorStatus.textContent="ERROR";investigatorStatus.className="pill danger";investigatorOutput.innerHTML=`<div class="banner-danger"><strong>INVESTIGATOR ERROR</strong><span>${esc(error.message)}</span></div>`;}
  finally{simulateInvestigatorBtn.disabled=!currentAnalysis?.incidents?.length;}
}
function setLiveStatus(label,tone=""){liveStatus.textContent=label;liveStatus.className=tone?`pill ${tone}`:"pill";}
function appendLiveEvent(event,analysis){
  if(liveStream.querySelector(".empty"))liveStream.innerHTML="";
  const incident=analysis.incidents?.[0],row=document.createElement("div");row.className="live-event";
  row.innerHTML=`<div class="live-dot"></div><div class="live-event-main"><div class="live-event-top"><strong>${esc(pretty(event.event_type))}</strong><span>${esc(event.event_id)}</span></div><div class="muted">${esc(event.timestamp)} · ${esc(event.source)}</div><div class="event-meta">${[event.user,event.device,event.src_ip,event.resource].filter(Boolean).map(esc).join(" · ")}</div></div><span class="pill ${incident?"danger":"safe"}">${incident?"INCIDENT":"OBSERVED"}</span>`;
  liveStream.appendChild(row);liveStream.scrollTop=liveStream.scrollHeight;
}
function stopLiveSimulation(){if(liveSocket){liveSocket.close();liveSocket=null;}liveBtn.textContent="Start live simulation";liveBtn.disabled=false;}
function startLiveSimulation(){
  if(liveSocket)return;
  const scenario=scenarioSelect.value||"full_attack",protocol=location.protocol==="https:"?"wss:":"ws:";liveStream.innerHTML="";setLiveStatus("CONNECTING");liveBtn.textContent="Stop simulation";liveBtn.disabled=true;
  liveSocket=new WebSocket(`${protocol}//${location.host}/ws/simulate/${encodeURIComponent(scenario)}?delay=0.9`);
  liveSocket.onopen=()=>setLiveStatus("STREAMING");
  liveSocket.onmessage=message=>{
    let payload;try{payload=JSON.parse(message.data);}catch{setLiveStatus("ERROR","danger");liveStream.innerHTML='<div class="banner-danger"><strong>STREAM ERROR</strong><span>Received invalid stream data.</span></div>';stopLiveSimulation();return;}
    if(payload.type==="start"){setLiveStatus("STREAMING");return;}
    if(payload.type==="event"){appendLiveEvent(payload.event,payload.analysis);render(payload.analysis);return;}
    if(payload.type==="complete"){render(payload.analysis);setLiveStatus("COMPLETE",payload.analysis.correlated_incidents?"danger":"safe");stopLiveSimulation();return;}
    if(payload.type==="error"){setLiveStatus("ERROR","danger");liveStream.innerHTML=`<div class="banner-danger"><strong>STREAM ERROR</strong><span>${esc(payload.message)}</span></div>`;stopLiveSimulation();}
  };
  liveSocket.onerror=()=>{setLiveStatus("ERROR","danger");liveStream.innerHTML='<div class="banner-danger"><strong>STREAM ERROR</strong><span>Could not connect to the simulation stream.</span></div>';stopLiveSimulation();};
  liveSocket.onclose=()=>{liveSocket=null;liveBtn.disabled=false;};
}
async function load(path,label="Analysis error"){
  try{const res=await fetch(path);if(!res.ok){let detail="";try{detail=(await res.json()).detail||"";}catch{}throw new Error(detail||`Request failed: ${res.status}`);}render(await res.json());}
  catch(error){showError(label,error.message);}
}
async function uploadFile(){
  if(!logFile.files?.length){showError("No log selected","Choose a supported JSON, JSONL, NDJSON, CSV, or XML log file first.");return;}
  const form=new FormData();form.append("file",logFile.files[0]);
  try{const res=await fetch("/api/analyze/upload",{method:"POST",body:form});if(!res.ok){let detail="";try{detail=(await res.json()).detail||"";}catch{}throw new Error(detail||`Request failed: ${res.status}`);}render(await res.json());}
  catch(error){showError("Upload failed",error.message);}
}
async function loadPhase2Report(){
  try{const res=await fetch("/api/phase2/report");if(!res.ok)throw new Error(`Request failed: ${res.status}`);const data=await res.json(),status=data.failed_cases===0&&data.false_positive_cases===0&&data.missed_attack_cases===0;phase2Pill.textContent=status?"PASS":"FAIL";phase2Pill.className=status?"pill safe":"pill danger";
    phase2Report.innerHTML=`<div class="validation-stat"><span>Cases</span><strong>${esc(data.total_cases)}</strong></div><div class="validation-stat"><span>Passed</span><strong>${esc(data.passed_cases)}</strong></div><div class="validation-stat"><span>Accuracy</span><strong>${pct(data.accuracy)}</strong></div><div class="validation-stat"><span>False positives</span><strong>${esc(data.false_positive_cases)}</strong></div><div class="validation-stat"><span>Missed attacks</span><strong>${esc(data.missed_attack_cases)}</strong></div><div class="validation-stat"><span>Watchlist</span><strong>${esc(data.watchlist_cases)}</strong></div>`;
    if(data.failed_cases>0)phase2Report.innerHTML+=`<div class="validation-failures"><strong>Cases needing review</strong>${data.cases.filter(c=>!c.passed).map(c=>`<div>${esc(pretty(c.scenario))} · expected ${esc(c.expected)}, got ${esc(c.actual)}</div>`).join("")}</div>`;
  }catch(error){phase2Pill.textContent="ERROR";phase2Pill.className="pill danger";phase2Report.innerHTML=`<div class="validation-failures"><strong>Validation unavailable</strong><div>${esc(error.message)}</div></div>`;}
}
async function loadScenarios(){
  try{const res=await fetch("/api/scenarios");if(!res.ok)throw new Error();const data=await res.json();scenarioSelect.innerHTML=data.scenarios.map(name=>`<option value="${esc(name)}">${esc(pretty(name))}</option>`).join("");scenarioSelect.value=data.scenarios.includes("full_attack")?"full_attack":data.scenarios[0];}
  catch{scenarioSelect.innerHTML='<option value="">Scenario list unavailable</option>';}
}
document.querySelectorAll(".tab").forEach(tab=>tab.addEventListener("click",()=>setActiveTab(tab.dataset.tab)));
window.addEventListener("hashchange",restoreTab);
document.getElementById("attackBtn").onclick=()=>{setActiveTab("overview");load("/api/demo/full_attack","Attack demo failed");};
document.getElementById("cleanBtn").onclick=()=>{setActiveTab("overview");load("/api/demo/clean","Clean demo failed");};
document.getElementById("scenarioBtn").onclick=()=>{setActiveTab("overview");load(`/api/demo/${encodeURIComponent(scenarioSelect.value)}`,"Scenario failed");};
document.getElementById("uploadBtn").onclick=()=>{setActiveTab("overview");uploadFile();};
liveBtn.onclick=()=>liveSocket?stopLiveSimulation():startLiveSimulation();
simulateInvestigatorBtn.onclick=runSimulatedInvestigator;
restoreTab();loadScenarios();loadPhase2Report();load("/api/demo/full_attack","Initial analysis failed");