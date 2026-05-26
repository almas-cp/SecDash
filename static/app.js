const state = {
  user: null,
  currentView: "dashboard",
  workspaces: [],
  currentWorkspace: null,
  reports: { items: [], total: 0, page: 1, per_page: 10 },
};

const PAGE_TITLES = {
  dashboard: "Dashboard",
  workspaces: "Workspaces",
  "workspace-detail": "Workspace",
  reports: "Reports",
  admin: "Admin",
};

const OS_VERSIONS = {
  ubuntu: ["24.04 LTS", "23.10", "23.04", "22.04 LTS", "21.10", "21.04", "20.10", "20.04 LTS", "19.10", "18.04 LTS"],
  rhel: ["9.4", "9.3", "9.2", "9.1", "9.0", "8.10", "8.9", "8.8", "8.7", "8.6"],
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

function localDate() {
  const date = new Date();
  date.setMinutes(date.getMinutes() - date.getTimezoneOffset());
  return date.toISOString().slice(0, 10);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    headers: options.body instanceof FormData ? {} : { "Content-Type": "application/json" },
    ...options,
  });

  const text = await response.text();
  const payload = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(payload.detail || payload.error || "Request failed");
  }
  return payload;
}

function toast(message) {
  const root = $("#toast-root");
  const node = document.createElement("div");
  node.className = "toast";
  node.textContent = message;
  root.appendChild(node);
  setTimeout(() => node.remove(), 4000);
}

function showModal(content, size = "") {
  const root = $("#modal-root");
  root.hidden = false;
  root.innerHTML = `<div class="modal ${size}">${content}</div>`;
  root.addEventListener("click", closeOnBackdrop);
}

function closeOnBackdrop(event) {
  if (event.target.id === "modal-root") {
    closeModal();
  }
}

function closeModal() {
  const root = $("#modal-root");
  root.hidden = true;
  root.innerHTML = "";
  root.removeEventListener("click", closeOnBackdrop);
}

function setView(view) {
  state.currentView = view;
  $$(".view").forEach((node) => (node.hidden = true));
  $(`#${view}-view`).hidden = false;
  document.title = `${PAGE_TITLES[view] || "SecDash"} - SecDash`;
  document.body.dataset.page = view;
  $$(".nav-button").forEach((button) => button.classList.toggle("active", button.dataset.view === view));
}

function configureNav() {
  const role = state.user.role;
  $$(".nav-button").forEach((button) => {
    const view = button.dataset.view;
    button.hidden =
      (view === "workspaces" && role !== "researcher") ||
      (view === "reports" && !["researcher", "viewer"].includes(role)) ||
      (view === "admin" && role !== "admin");
  });

  if (role === "admin") {
    setView("admin");
    loadUsers();
  } else if (role === "viewer") {
    setView("reports");
    loadReports(1);
  } else {
    setView("dashboard");
    loadDashboard();
  }
}

function showAuthenticated(user) {
  state.user = user;
  $("#login-view").hidden = true;
  $("#app-shell").hidden = false;
  $("#current-user").textContent = user.username;
  $("#role-badge").textContent = user.role;
  configureNav();
}

function showLogin() {
  state.user = null;
  $("#app-shell").hidden = true;
  $("#login-view").hidden = false;
}

function severityBadge(severity) {
  const normalized = String(severity || "UNKNOWN").toUpperCase();
  return `<span class="severity-badge severity-${normalized.toLowerCase()}">${escapeHtml(normalized)}</span>`;
}

function countPills(row) {
  return `
    <span class="count-pill severity-critical">C ${row.cve_count_critical || 0}</span>
    <span class="count-pill severity-high">H ${row.cve_count_high || 0}</span>
    <span class="count-pill severity-medium">M ${row.cve_count_medium || 0}</span>
    <span class="count-pill severity-low">L ${row.cve_count_low || 0}</span>
  `;
}

async function loadDashboard() {
  if (state.user.role === "researcher") {
    const [workspaces, reports] = await Promise.all([api("/api/workspaces"), api("/api/reports")]);
    $("#dashboard-panels").innerHTML = `
      <div class="metric-card"><p class="muted">Workspaces</p><div class="metric-value">${workspaces.length}</div></div>
      <div class="metric-card"><p class="muted">Saved Reports</p><div class="metric-value">${reports.total}</div></div>
      <div class="metric-card"><p class="muted">Current Role</p><div class="metric-value">${escapeHtml(state.user.role)}</div></div>
    `;
  } else {
    $("#dashboard-panels").innerHTML = `
      <div class="metric-card"><p class="muted">Current Role</p><div class="metric-value">${escapeHtml(state.user.role)}</div></div>
    `;
  }
}

async function loadWorkspaces() {
  const workspaces = await api("/api/workspaces");
  state.workspaces = workspaces;
  const grid = $("#workspace-grid");
  grid.innerHTML = workspaces.length
    ? workspaces
        .map(
          (item) => `
        <article class="workspace-card">
          <div>
            <h3>${escapeHtml(item.name)}</h3>
            <p class="muted mono">${escapeHtml(item.ip)}</p>
          </div>
          <div class="meta-grid">
            <div><p class="muted">OS</p><strong>${escapeHtml(item.os)} ${escapeHtml(item.os_version)}</strong></div>
            <div><p class="muted">Scan</p><strong>${escapeHtml(item.scan_date)}</strong></div>
            <div><p class="muted">Files</p><strong>${item.file_count || 0}</strong></div>
            <div><p class="muted">Reports</p><strong>${item.report_count || 0}</strong></div>
          </div>
          <div class="button-row">
            <button class="secondary-button" data-open-workspace="${item.id}" type="button">Open</button>
            <button class="danger-button" data-delete-workspace="${item.id}" type="button">Delete</button>
          </div>
        </article>
      `
        )
        .join("")
    : `<div class="empty-state">No workspaces yet.</div>`;
}

async function openWorkspace(id) {
  const workspace = await api(`/api/workspaces/${id}`);
  state.currentWorkspace = workspace;
  $("#workspace-title").textContent = workspace.name;
  $("#workspace-meta").innerHTML = `
    <div class="metric-card"><p class="muted">IP</p><strong class="mono">${escapeHtml(workspace.ip)}</strong></div>
    <div class="metric-card"><p class="muted">OS</p><strong>${escapeHtml(workspace.os)} ${escapeHtml(workspace.os_version)}</strong></div>
    <div class="metric-card"><p class="muted">Scan Date</p><strong>${escapeHtml(workspace.scan_date)}</strong></div>
    <div class="metric-card"><p class="muted">Created</p><strong>${escapeHtml(workspace.created_at)}</strong></div>
    <div class="metric-card"><p class="muted">Open Ports</p><strong id="workspace-port-count">-</strong></div>
    <div class="metric-card"><p class="muted">Services</p><strong id="workspace-service-count">-</strong></div>
  `;
  renderFiles(workspace.files || []);
  renderWorkspaceReports(workspace.reports || []);
  $("#live-log").textContent = "";
  $("#parse-status").textContent = "Idle";
  $("#progress-bar").style.width = "0%";
  $("#save-report-button").disabled = true;
  setView("workspace-detail");
  await loadDetectedCves(workspace.id);
}

function renderFiles(files) {
  $("#file-list").innerHTML = files.length
    ? files
        .map(
          (file) => `
        <div class="file-row">
          <span class="mono">${escapeHtml(file.filename)}</span>
          <button class="danger-button" data-delete-file="${file.id}" type="button">Delete</button>
        </div>
      `
        )
        .join("")
    : `<div class="empty-state">No files uploaded.</div>`;
}

async function loadDetectedCves(workspaceId) {
  const list = $("#detected-cve-list");
  const status = $("#cve-list-status");
  const serviceList = $("#service-list");
  const serviceStatus = $("#service-list-status");
  status.textContent = "Extracting from uploaded files";
  serviceStatus.textContent = "Extracting from uploaded files";
  list.innerHTML = `<div class="empty-state">Reading scan files...</div>`;
  serviceList.innerHTML = `<div class="empty-state">Reading scan files...</div>`;
  try {
    const result = await api(`/api/workspaces/${workspaceId}/cves`);
    renderDetectedCves(result.items || []);
    applyRestoredClassifications(result.classifications || {});
    renderServices(result.services || [], result.classifications || {});
    const classifiedText = result.classified_total ? `, ${result.classified_total} classified` : "";
    status.textContent = result.total ? `${result.total} unique CVEs detected${classifiedText}` : "No CVEs detected";
    serviceStatus.textContent = result.service_total ? `${result.service_total} ports/services detected` : "No services detected";
    updateWorkspaceServiceMetrics(result.services || []);
    if (result.classified_total) {
      $("#save-report-button").disabled = false;
      $("#parse-status").textContent = "Classified";
      $("#progress-bar").style.width = "100%";
    }
  } catch (error) {
    status.textContent = "Extraction failed";
    serviceStatus.textContent = "Extraction failed";
    list.innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`;
    serviceList.innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`;
  }
}

function updateWorkspaceServiceMetrics(services) {
  const ports = new Set(services.map((item) => `${item.port}/${item.proto || "tcp"}`));
  const portCount = $("#workspace-port-count");
  const serviceCount = $("#workspace-service-count");
  if (portCount) portCount.textContent = ports.size;
  if (serviceCount) serviceCount.textContent = services.length;
}

function renderDetectedCves(items) {
  $("#detected-cve-list").innerHTML = items.length
    ? items
        .map(
          (item) => `
        <div class="detected-cve-row" id="detected-${escapeHtml(item.cve_id)}">
          <div class="detected-cve-main">
            <div>
              <span class="cve-id">${escapeHtml(item.cve_id)}</span>
              <span class="cve-live-pill status-pending" data-cve-live-pill>Listed</span>
            </div>
            <span class="detected-cve-files">${escapeHtml((item.files || []).join(", "))}</span>
          </div>
          <div class="detected-cve-live" data-cve-live>Waiting for classification</div>
        </div>
      `
        )
        .join("")
    : `<div class="empty-state">No CVEs found in uploaded files.</div>`;
}

function applyRestoredClassifications(classifications) {
  Object.values(classifications || {}).forEach((classification) => updateDetectedCveRow(classification));
}

function serviceName(item) {
  const product = [item.product, item.version].filter(Boolean).join(" ");
  return product || item.service || "unknown";
}

function renderServices(items, classifications = {}) {
  $("#service-list").innerHTML = items.length
    ? items
        .map((item) => {
          const endpoint = `${escapeHtml(item.port)}/${escapeHtml(item.proto || "tcp")}`;
          const state = escapeHtml(item.state || "unknown");
          const service = escapeHtml(serviceName(item));
          const extra = item.extra ? `<span class="service-extra">${escapeHtml(item.extra)}</span>` : "";
          const files = (item.files || []).join(", ");
          const cves = item.cves || [];
          const cveSummary = cves.length ? `${cves.length} CVEs` : "No CVEs linked";
          return `
        <details class="service-row">
          <summary class="service-summary">
            <div class="service-port">
              <span class="service-endpoint">${endpoint}</span>
              <span class="service-state">${state}</span>
            </div>
            <div class="service-details">
              <strong>${service}</strong>
              ${extra}
              <span class="detected-cve-files">${escapeHtml(files)}</span>
            </div>
            <span class="service-cve-count">${escapeHtml(cveSummary)}</span>
          </summary>
          <div class="service-cve-list">
            ${renderServiceCves(cves, classifications)}
          </div>
        </details>
      `;
        })
        .join("")
    : `<div class="empty-state">No ports or services found in uploaded files.</div>`;
}

function renderServiceCves(cves, classifications) {
  return cves.length
    ? cves
        .map((cveId) => {
          const classification = classifications[cveId] || {};
          const label = classification.attention_needed === true ? "Attention" : classification.attention_needed === false ? "Filtered" : "Listed";
          const pillClass = classification.attention_needed === true ? "status-attention" : classification.attention_needed === false ? "status-filtered" : "status-pending";
          const category = classification.status_category ? ` - ${classification.status_category}` : "";
          const verifier = classification.classifier === "groq" ? "Groq verified" : classification.classifier ? "Fallback checked" : "Waiting for classification";
          return `
        <div class="service-cve-row" data-service-cve="${escapeHtml(cveId)}">
          <span class="cve-id">${escapeHtml(cveId)}</span>
          <span class="cve-live-pill ${pillClass}" data-service-cve-pill>${label}</span>
          <span class="service-cve-note" data-service-cve-note>${escapeHtml(`${verifier}${category}`)}</span>
        </div>
      `;
        })
        .join("")
    : `<div class="empty-state">No CVEs linked to this service.</div>`;
}

function resetDetectedCveRows() {
  $$(".detected-cve-row").forEach((row) => {
    row.classList.remove("is-running", "is-attention", "is-filtered", "is-error");
    const pill = row.querySelector("[data-cve-live-pill]");
    const live = row.querySelector("[data-cve-live]");
    if (pill) {
      pill.className = "cve-live-pill status-pending";
      pill.textContent = "Queued";
    }
    if (live) live.textContent = "Waiting for classification";
  });
}

function updateDetectedCveRow(data) {
  if (!data.cve_id) return;
  const row = document.getElementById(`detected-${data.cve_id}`);
  updateServiceCveRows(data);
  if (!row) return;

  const pill = row.querySelector("[data-cve-live-pill]");
  const live = row.querySelector("[data-cve-live]");
  row.classList.remove("is-running", "is-attention", "is-filtered", "is-error");

  if (data.status === "running") {
    row.classList.add("is-running");
    if (pill) {
      pill.className = "cve-live-pill status-running";
      pill.textContent = "Checking";
    }
    if (live) live.textContent = "Calling CVE API, then cross-verifying status with AI";
    row.scrollIntoView({ block: "nearest", behavior: "smooth" });
    return;
  }

  const verifier = data.classifier === "groq" ? "Groq verified" : "Fallback checked";
  const category = data.status_category || "unknown";
  const confidence = data.confidence ? ` (${data.confidence})` : "";
  const decision = data.attention_needed ? "Attention needed" : "Filtered out";
  const statusClass = data.status === "error" ? "status-error" : data.attention_needed ? "status-attention" : "status-filtered";

  row.classList.add(data.status === "error" ? "is-error" : data.attention_needed ? "is-attention" : "is-filtered");
  if (pill) {
    pill.className = `cve-live-pill ${statusClass}`;
    pill.textContent = decision;
  }
  if (live) {
    const reason = data.reason ? ` - ${data.reason}` : "";
    live.textContent = `Status: ${category} | ${verifier}${confidence} | ${decision}${reason}`;
  }
}

function updateServiceCveRows(data) {
  const rows = $$(`[data-service-cve="${CSS.escape(data.cve_id)}"]`);
  rows.forEach((row) => {
    const pill = row.querySelector("[data-service-cve-pill]");
    const note = row.querySelector("[data-service-cve-note]");
    if (data.status === "running") {
      if (pill) {
        pill.className = "cve-live-pill status-running";
        pill.textContent = "Checking";
      }
      if (note) note.textContent = "Checking source data and AI status gate";
      return;
    }
    const verifier = data.classifier === "groq" ? "Groq verified" : data.classifier ? "Fallback checked" : "Waiting for classification";
    const category = data.status_category || "unknown";
    const label = data.status === "error" ? "Error" : data.attention_needed ? "Attention" : "Filtered";
    const pillClass = data.status === "error" ? "status-error" : data.attention_needed ? "status-attention" : "status-filtered";
    if (pill) {
      pill.className = `cve-live-pill ${pillClass}`;
      pill.textContent = label;
    }
    if (note) note.textContent = `${verifier} - ${category}`;
  });
}

function renderWorkspaceReports(reports) {
  $("#workspace-report-list").innerHTML = reports.length
    ? reports
        .map(
          (report) => `
        <button class="compact-row" data-open-report="${report.id}" type="button">
          <span>v${report.version}</span>
          <span class="muted">${escapeHtml(report.saved_at)}</span>
        </button>
      `
        )
        .join("")
    : `<div class="empty-state">No saved report versions.</div>`;
}

function showWorkspaceModal() {
  showModal(`
    <h3>New Workspace</h3>
    <form id="workspace-form" class="view">
      <label>IP Address<input id="workspace-ip" required placeholder="192.168.1.10" /></label>
      <label>OS
        <select id="workspace-os">
          <option value="ubuntu">Ubuntu</option>
          <option value="rhel">RHEL</option>
        </select>
      </label>
      <label>Version<select id="workspace-version"></select></label>
      <label>Scan Date<input id="workspace-date" type="date" required value="${localDate()}" /></label>
      <div class="modal-actions">
        <button class="ghost-button" type="button" data-close-modal>Cancel</button>
        <button class="primary-button" type="submit">Create</button>
      </div>
    </form>
  `);

  const versionSelect = $("#workspace-version");
  const osSelect = $("#workspace-os");
  const fillVersions = () => {
    versionSelect.innerHTML = OS_VERSIONS[osSelect.value].map((version) => `<option>${version}</option>`).join("");
  };
  fillVersions();
  osSelect.addEventListener("change", fillVersions);
  $("#workspace-form").addEventListener("submit", createWorkspace);
}

async function createWorkspace(event) {
  event.preventDefault();
  const payload = {
    ip: $("#workspace-ip").value.trim(),
    os: $("#workspace-os").value,
    os_version: $("#workspace-version").value,
    scan_date: $("#workspace-date").value,
  };
  const created = await api("/api/workspaces", { method: "POST", body: JSON.stringify(payload) });
  closeModal();
  toast("Workspace created");
  await loadWorkspaces();
  await openWorkspace(created.id);
}

async function deleteWorkspace(id) {
  const ok = window.confirm("Delete this workspace? Saved report versions remain available, but uploaded files are removed.");
  if (!ok) return;
  await api(`/api/workspaces/${id}`, { method: "DELETE" });
  toast("Workspace deleted");
  await loadWorkspaces();
}

async function uploadSelectedFiles(files) {
  if (!state.currentWorkspace || !files.length) return;
  const form = new FormData();
  Array.from(files).forEach((file) => form.append("files", file));
  const result = await api(`/api/workspaces/${state.currentWorkspace.id}/files`, { method: "POST", body: form });
  result.files.forEach((file) => {
    if (file.status === "error") toast(`${file.filename}: ${file.message}`);
  });
  await openWorkspace(state.currentWorkspace.id);
}

async function deleteFile(id) {
  await api(`/api/workspaces/${state.currentWorkspace.id}/files/${id}`, { method: "DELETE" });
  toast("File deleted");
  await openWorkspace(state.currentWorkspace.id);
}

function appendLog(line) {
  const log = $("#live-log");
  log.textContent += `${line}\n`;
  log.scrollTop = log.scrollHeight;
}

async function parseWorkspace() {
  if (!state.currentWorkspace) return;
  const classifyButton = $("#parse-button");
  classifyButton.disabled = true;
  classifyButton.textContent = "Classifying...";
  $("#save-report-button").disabled = true;
  $("#live-log").textContent = "";
  $("#parse-status").textContent = "Classifying";
  $("#progress-bar").style.width = "0%";
  resetDetectedCveRows();
  appendLog("[start] CVE API checks and Groq cross-verification started");

  try {
    const response = await fetch(`/api/workspaces/${state.currentWorkspace.id}/parse`, {
      method: "POST",
      credentials: "same-origin",
    });
    if (!response.ok || !response.body) {
      const payload = await response.json();
      throw new Error(payload.detail || payload.error || "Classification failed");
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const events = buffer.split("\n\n");
      buffer = events.pop() || "";
      events.forEach(handleSseEvent);
    }
  } catch (error) {
    toast(error.message);
    $("#parse-status").textContent = "Failed";
  } finally {
    classifyButton.disabled = false;
    classifyButton.textContent = "Classify";
  }
}

function handleSseEvent(raw) {
  const lines = raw.split("\n");
  const event = (lines.find((line) => line.startsWith("event:")) || "").replace("event:", "").trim();
  const dataLine = lines.find((line) => line.startsWith("data:"));
  if (!dataLine) return;
  const data = JSON.parse(dataLine.replace("data:", "").trim());

  if (event === "progress") {
    updateDetectedCveRow(data);
    const completed = data.status === "running" ? data.current - 1 : data.current;
    const percent = data.total ? Math.round((completed / data.total) * 100) : 0;
    $("#progress-bar").style.width = `${percent}%`;
    $("#parse-status").textContent = `${data.current} / ${data.total}`;
    const verifier = data.classifier === "groq" ? "Groq verified" : "fallback checked";
    const category = data.status_category || "unknown";
    const confidence = data.confidence ? `, ${data.confidence}` : "";
    if (data.status === "running") {
      appendLog(`[scan] ${data.cve_id} - checking CVE API and AI status gate`);
    } else if (data.status === "ok") {
      appendLog(`[classify] ${data.cve_id} - ${category} - ${verifier}${confidence} - ${data.attention_needed ? "attention needed" : "filtered"}`);
    } else {
      appendLog(`[error] ${data.cve_id} - ${category} - ${verifier}${confidence} - ${data.message}`);
    }
  }

  if (event === "done") {
    $("#progress-bar").style.width = "100%";
    $("#parse-status").textContent = "Complete";
    $("#cve-list-status").textContent = `Classification complete - ${data.needs_attention} attention needed, ${data.filtered_out || 0} filtered`;
    $("#save-report-button").disabled = false;
    toast(`Classification complete - ${data.needs_attention} attention needed, ${data.filtered_out || 0} filtered`);
  }
}

async function saveReport() {
  const result = await api(`/api/workspaces/${state.currentWorkspace.id}/save`, { method: "POST" });
  toast(`Report v${result.version} saved`);
  await openWorkspace(state.currentWorkspace.id);
}

async function loadReports(page = 1) {
  const params = new URLSearchParams({
    ip: $("#filter-ip").value.trim(),
    os: $("#filter-os").value,
    date: $("#filter-date").value,
    sort: $("#sort-field").value,
    order: $("#sort-order").value,
    page: String(page),
  });
  const reports = await api(`/api/reports?${params.toString()}`);
  state.reports = reports;
  renderReports();
}

function renderReports() {
  const body = $("#report-table-body");
  body.innerHTML = state.reports.items.length
    ? state.reports.items
        .map(
          (report) => `
        <tr class="clickable-row" data-open-report="${report.id}">
          <td>${escapeHtml(report.workspace_name)}</td>
          <td class="mono">${escapeHtml(report.ip)}</td>
          <td>${escapeHtml(report.os)} ${escapeHtml(report.os_version)}</td>
          <td>${escapeHtml(report.scan_date)}</td>
          <td>v${report.version}</td>
          <td>${escapeHtml(report.saved_at)}</td>
          <td><div class="button-row">${countPills(report)}</div></td>
        </tr>
      `
        )
        .join("")
    : `<tr><td colspan="7"><div class="empty-state">No reports found.</div></td></tr>`;

  const maxPage = Math.max(1, Math.ceil(state.reports.total / state.reports.per_page));
  $("#page-status").textContent = `Page ${state.reports.page} of ${maxPage}`;
  $("#prev-page").disabled = state.reports.page <= 1;
  $("#next-page").disabled = state.reports.page >= maxPage;
}

async function openReport(id) {
  const report = await api(`/api/reports/${id}`);
  const summary = report.cve_summary || { all_cves: [], needs_attention: [], parse_errors: [] };
  const reviewedTotal = summary.reviewed_total ?? summary.all_cves?.length ?? 0;
  const fixedCount = summary.filtered_out_count ?? 0;
  const reportCves = summary.needs_attention || summary.all_cves || [];
  const services = summary.services || [];
  showModal(`
    <div class="panel-header">
      <div>
        <p class="eyebrow">Report Detail</p>
        <h3>${escapeHtml(report.workspace_name)}</h3>
      </div>
      <button class="ghost-button" type="button" data-close-modal>Close</button>
    </div>
    <div class="meta-grid">
      <div class="metric-card"><p class="muted">IP</p><strong class="mono">${escapeHtml(report.ip)}</strong></div>
      <div class="metric-card"><p class="muted">OS</p><strong>${escapeHtml(report.os)} ${escapeHtml(report.os_version)}</strong></div>
      <div class="metric-card"><p class="muted">Version</p><strong>v${report.version}</strong></div>
      <div class="metric-card"><p class="muted">Saved By</p><strong>${escapeHtml(report.saved_by_username || "Unknown")}</strong></div>
    </div>
    <div class="meta-grid">
      <div class="metric-card"><p class="muted">Reviewed</p><strong>${reviewedTotal}</strong></div>
      <div class="metric-card"><p class="muted">Fixed</p><strong>${fixedCount}</strong></div>
      <div class="metric-card"><p class="muted">Classifier</p><strong>${escapeHtml(summary.classifier || "unknown")}</strong></div>
      <div class="metric-card"><p class="muted">Policy</p><strong>${escapeHtml(summary.report_policy || "attention only")}</strong></div>
    </div>
    <div class="button-row">${countPills(report)}<span class="count-pill severity-unknown">U ${report.cve_count_unknown || 0}</span></div>
    <div class="report-tabs" role="tablist">
      <button class="report-tab active" type="button" data-report-tab="cves">CVEs</button>
      <button class="report-tab" type="button" data-report-tab="services">Ports / Services</button>
    </div>
    <div class="report-tab-panel active" data-report-panel="cves">
      ${cveTable("Attention Required", reportCves)}
    </div>
    <div class="report-tab-panel" data-report-panel="services">
      ${reportServicesSection(services, reportCves)}
    </div>
  `, "large");
}

function cveLookup(cves) {
  return Object.fromEntries((cves || []).map((item) => [item.cve_id, item]));
}

function reportServicesSection(services, reportCves) {
  const lookup = cveLookup(reportCves);
  return `
    <div class="report-section">
      <h3>Ports / Services</h3>
      <div class="service-list">
        ${services.length ? services.map((service) => reportServiceCard(service, lookup)).join("") : `<div class="empty-state">No ports or services were saved with this report.</div>`}
      </div>
    </div>
  `;
}

function reportServiceCard(item, lookup) {
  const endpoint = `${escapeHtml(item.port)}/${escapeHtml(item.proto || "tcp")}`;
  const state = escapeHtml(item.state || "unknown");
  const service = escapeHtml(serviceName(item));
  const extra = item.extra ? `<span class="service-extra">${escapeHtml(item.extra)}</span>` : "";
  const cves = item.cves || [];
  return `
    <details class="service-row">
      <summary class="service-summary">
        <div class="service-port">
          <span class="service-endpoint">${endpoint}</span>
          <span class="service-state">${state}</span>
        </div>
        <div class="service-details">
          <strong>${service}</strong>
          ${extra}
          <span class="detected-cve-files">${escapeHtml((item.files || []).join(", "))}</span>
        </div>
        <span class="service-cve-count">${cves.length ? `${cves.length} CVEs` : "No CVEs linked"}</span>
      </summary>
      <div class="service-cve-list">
        ${cves.length ? cves.map((cveId) => reportServiceCveRow(cveId, lookup[cveId])).join("") : `<div class="empty-state">No CVEs linked to this service.</div>`}
      </div>
    </details>
  `;
}

function reportServiceCveRow(cveId, cve) {
  const included = Boolean(cve);
  const attention = cve?.attention || {};
  const status = attention.status_category || (included ? "attention_needed" : "fixed");
  const pillClass = included ? "status-attention" : "status-filtered";
  const label = included ? "In report" : "Fixed";
  return `
    <div class="service-cve-row">
      <span class="cve-id">${escapeHtml(cveId)}</span>
      <span class="cve-live-pill ${pillClass}">${label}</span>
      <span class="service-cve-note">${escapeHtml(status)}</span>
    </div>
  `;
}

function switchReportTab(tabName) {
  $$(".report-tab").forEach((button) => button.classList.toggle("active", button.dataset.reportTab === tabName));
  $$("[data-report-panel]").forEach((panel) => panel.classList.toggle("active", panel.dataset.reportPanel === tabName));
}

function previewList(values, limit = 3) {
  const list = Array.isArray(values) ? values.filter(Boolean) : [];
  if (!list.length) return "";
  const head = list.slice(0, limit).map((value) => escapeHtml(value)).join(", ");
  const extra = list.length > limit ? ` +${list.length - limit}` : "";
  return `${head}${extra}`;
}

function affectedPreview(item) {
  if (Array.isArray(item.affected_packages) && item.affected_packages.length) {
    return previewList(item.affected_packages);
  }
  if (Array.isArray(item.packages) && item.packages.length) {
    return previewList(item.packages.map((pkg) => pkg.name || pkg.package));
  }
  return "";
}

function formatStatusCounts(counts) {
  if (!counts || typeof counts !== "object") return "";
  return Object.entries(counts)
    .filter(([, value]) => Number(value) > 0)
    .map(([key, value]) => `${key}: ${value}`)
    .join(" | ");
}

function sourceDetails(item) {
  const parts = [];
  if (item.source_os) parts.push(String(item.source_os).toUpperCase());
  if (item.source_status_code) parts.push(`HTTP ${item.source_status_code}`);
  if (Array.isArray(item.references) && item.references.length) parts.push(`${item.references.length} refs`);
  if (Array.isArray(item.notices_ids) && item.notices_ids.length) parts.push(previewList(item.notices_ids, 2));
  return parts.join(" | ");
}

function cveCard(item) {
  const status = item.status || previewList(item.advisories || []) || item.api_status || "";
  const affected = affectedPreview(item);
  const source = sourceDetails(item);
  const attention = item.attention || {};
  const statusCounts = formatStatusCounts(attention.target_status_summary || attention.status_summary);
  return `
    <article class="cve-card">
      <div class="cve-card-top">
        <div>
          <div class="cve-title-row">
            <span class="cve-id">${escapeHtml(item.cve_id)}</span>
            ${severityBadge(item.severity)}
          </div>
          <div class="cve-meta-line">${escapeHtml(source)}</div>
        </div>
        <div class="cvss-box">
          <span class="muted">CVSS</span>
          <strong>${escapeHtml(item.cvss_score ?? "N/A")}</strong>
        </div>
      </div>

      ${item.cvss_vector ? `<div class="cvss-vector mono">${escapeHtml(item.cvss_vector)}</div>` : ""}

      <div class="cve-card-grid">
        <section>
          <p class="field-label">Description</p>
          <p class="field-text">${escapeHtml(item.description || item.api_error || "No description available.")}</p>
        </section>
        <section>
          <p class="field-label">Status Gate</p>
          <p class="field-text">${escapeHtml(`${attention.status_category || "unknown"}${attention.confidence ? ` (${attention.confidence})` : ""}`)}</p>
          ${statusCounts ? `<p class="field-hint">${escapeHtml(statusCounts)}</p>` : ""}
        </section>
        <section>
          <p class="field-label">Status / Advisory</p>
          <p class="field-text">${escapeHtml(status || "No advisory status available.")}</p>
        </section>
        <section>
          <p class="field-label">Affected</p>
          <p class="field-text">${escapeHtml(affected || "No affected package data available.")}</p>
        </section>
        <section>
          <p class="field-label">Remediation</p>
          <p class="field-text">${escapeHtml(item.remediation || "No remediation guidance available.")}</p>
          ${attention.reason ? `<p class="field-hint">${escapeHtml(attention.reason)}</p>` : ""}
        </section>
      </div>
    </article>
  `;
}

function cveTable(title, cves) {
  return `
    <div class="report-section">
      ${title ? `<h3>${title}</h3>` : ""}
      <div class="cve-card-list">
        ${cves.length ? cves.map(cveCard).join("") : `<div class="empty-state">No CVEs in this section.</div>`}
      </div>
    </div>
  `;
}

async function loadUsers() {
  const users = await api("/api/admin/users");
  $("#user-table-body").innerHTML = users
    .map(
      (user) => `
      <tr>
        <td>${escapeHtml(user.username)}</td>
        <td>${escapeHtml(user.role)}</td>
        <td>${escapeHtml(user.created_at)}</td>
        <td>
          <div class="button-row">
            <button class="secondary-button" data-reset-user="${user.id}" type="button">Reset</button>
            <button class="danger-button" data-delete-user="${user.id}" ${user.role === "admin" ? "disabled" : ""} type="button">Delete</button>
          </div>
        </td>
      </tr>
    `
    )
    .join("");
}

async function createUser(event) {
  event.preventDefault();
  await api("/api/admin/users", {
    method: "POST",
    body: JSON.stringify({
      username: $("#new-username").value.trim(),
      password: $("#new-password").value,
      role: $("#new-role").value,
    }),
  });
  event.target.reset();
  toast("User created");
  await loadUsers();
}

async function deleteUser(id) {
  if (!window.confirm("Delete this user?")) return;
  await api(`/api/admin/users/${id}`, { method: "DELETE" });
  toast("User deleted");
  await loadUsers();
}

function showResetModal(id) {
  showModal(`
    <h3>Reset Password</h3>
    <form id="reset-form" class="view">
      <label>New Password<input id="reset-password" type="password" required /></label>
      <div class="modal-actions">
        <button class="ghost-button" type="button" data-close-modal>Cancel</button>
        <button class="primary-button" type="submit">Reset</button>
      </div>
    </form>
  `);
  $("#reset-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    await api(`/api/admin/users/${id}/reset`, {
      method: "POST",
      body: JSON.stringify({ new_password: $("#reset-password").value }),
    });
    closeModal();
    toast("Password reset");
  });
}

document.addEventListener("click", async (event) => {
  const target = event.target.closest("button, tr");
  if (!target) return;

  if (target.matches("[data-close-modal]")) closeModal();
  if (target.matches("[data-report-tab]")) switchReportTab(target.dataset.reportTab);
  if (target.matches(".nav-button")) {
    const view = target.dataset.view;
    setView(view);
    if (view === "dashboard") loadDashboard();
    if (view === "workspaces") loadWorkspaces();
    if (view === "reports") loadReports(1);
    if (view === "admin") loadUsers();
  }
  if (target.dataset.openWorkspace) openWorkspace(target.dataset.openWorkspace);
  if (target.dataset.deleteWorkspace) deleteWorkspace(target.dataset.deleteWorkspace);
  if (target.dataset.deleteFile) deleteFile(target.dataset.deleteFile);
  if (target.dataset.openReport) openReport(target.dataset.openReport);
  if (target.dataset.deleteUser) deleteUser(target.dataset.deleteUser);
  if (target.dataset.resetUser) showResetModal(target.dataset.resetUser);
});

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("#login-error").hidden = true;
  try {
    const user = await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        username: $("#login-username").value,
        password: $("#login-password").value,
      }),
    });
    showAuthenticated(user);
  } catch (error) {
    $("#login-error").textContent = error.message;
    $("#login-error").hidden = false;
  }
});

$("#logout-button").addEventListener("click", async () => {
  await api("/api/auth/logout", { method: "POST" });
  showLogin();
});

$("#new-workspace-button").addEventListener("click", showWorkspaceModal);
$("#back-to-workspaces").addEventListener("click", async () => {
  setView("workspaces");
  await loadWorkspaces();
});
$("#parse-button").addEventListener("click", parseWorkspace);
$("#save-report-button").addEventListener("click", saveReport);
$("#file-input").addEventListener("change", (event) => uploadSelectedFiles(event.target.files));
$("#create-user-form").addEventListener("submit", createUser);
$("#report-filters").addEventListener("submit", (event) => {
  event.preventDefault();
  loadReports(1);
});
$("#prev-page").addEventListener("click", () => loadReports(state.reports.page - 1));
$("#next-page").addEventListener("click", () => loadReports(state.reports.page + 1));

const dropZone = $("#drop-zone");
["dragenter", "dragover"].forEach((name) => {
  dropZone.addEventListener(name, (event) => {
    event.preventDefault();
    dropZone.classList.add("dragging");
  });
});
["dragleave", "drop"].forEach((name) => {
  dropZone.addEventListener(name, (event) => {
    event.preventDefault();
    dropZone.classList.remove("dragging");
  });
});
dropZone.addEventListener("drop", (event) => uploadSelectedFiles(event.dataTransfer.files));

api("/api/auth/me")
  .then(showAuthenticated)
  .catch(showLogin);
