const $ = (selector) => document.querySelector(selector);

const escapeHtml = (value) => String(value ?? "")
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;").replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");

const formatDate = (value) => value ? new Date(value).toLocaleString() : "-";
const severityRank = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };

async function request(url, options = {}) {
    const response = await fetch(url, options);
    if (response.status === 401 && url !== "/api/login") {
        const dialog = $("#login-dialog");
        if (dialog && !dialog.open) dialog.showModal();
        throw new Error("Login required");
    }
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || data.message || "Request failed");
    return data;
}

function initializeAuthorizationGate() {
    const dialog = $("#authorization-dialog");
    const blocked = $("#blocked-screen");
    if (sessionStorage.getItem("kmn_authorization_ack") === "true") {
        blocked.hidden = true;
        blocked.style.display = "none";
        document.body.classList.remove("gate-locked");
        document.body.classList.add("gate-accepted");
        return true;
    }
    dialog.showModal();
    $("#authorization-ok").addEventListener("click", () => {
        sessionStorage.setItem("kmn_authorization_ack", "true");
        dialog.close();
        blocked.hidden = true;
        blocked.style.display = "none";
        document.body.classList.remove("gate-locked");
        document.body.classList.remove("gate-blocked");
        document.body.classList.add("gate-accepted");
        refreshAll();
    });
    $("#authorization-cancel").addEventListener("click", () => {
        dialog.close();
        document.body.classList.remove("gate-locked");
        document.body.classList.add("gate-blocked");
        blocked.hidden = false;
        blocked.style.display = "flex";
    });
    $("#authorization-retry").addEventListener("click", () => {
        blocked.hidden = true;
        blocked.style.display = "none";
        document.body.classList.remove("gate-blocked");
        document.body.classList.add("gate-locked");
        dialog.showModal();
    });
    return false;
}

async function loadDashboard() {
    const data = await request("/api/dashboard");
    $("#app-version").textContent = data.version;
    $("#metric-scans").textContent = data.scans;
    $("#metric-active").textContent = data.active_scans;
    $("#metric-services").textContent = data.services;
    $("#metric-findings").textContent = Object.values(data.findings || {}).reduce((sum, value) => sum + value, 0);
}

async function loadTools() {
    const tools = await request("/api/tools");
    $("#tool-list").innerHTML = Object.entries(tools).map(([name, available]) =>
        `<span class="tool ${available ? "available" : "unavailable"}">${escapeHtml(name)} ${available ? "ready" : "not installed"}</span>`).join("");
}

async function loadJobs() {
    const data = await request("/api/scans");
    const container = $("#jobs-list");
    if (!data.scans.length) {
        container.innerHTML = '<div class="empty-state">No scans yet. Start with a private lab target.</div>';
        return;
    }
    container.innerHTML = data.scans.map((job) => `
        <article class="job">
            <div><div class="job-target">${escapeHtml(job.target)}</div>
            <div class="job-meta">${escapeHtml(job.profile)} · ${escapeHtml(job.stage)} · ${formatDate(job.created_at)}</div>
            <div class="job-progress"><span style="width:${Math.max(0, Math.min(100, job.progress))}%"></span></div></div>
            <div class="job-side"><span class="job-status ${escapeHtml(job.status)}">${escapeHtml(job.status)}</span>
            <div><button class="ghost-button detail-button" data-id="${escapeHtml(job.id)}" type="button">Details</button></div></div>
        </article>`).join("");
    container.querySelectorAll(".detail-button").forEach((button) => button.addEventListener("click", () => showScan(button.dataset.id)));
}

async function loadFindings() {
    const data = await request("/api/findings");
    const findings = [...data.findings].sort((a, b) => (severityRank[a.severity] || 5) - (severityRank[b.severity] || 5));
    const container = $("#findings-list");
    if (!findings.length) {
        container.innerHTML = '<div class="empty-state">Findings will appear here after a scan.</div>';
        return;
    }
    container.innerHTML = findings.slice(0, 30).map((finding) => `
        <article class="finding ${escapeHtml(finding.severity)}">
            <span class="severity ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
            <div><div class="finding-title">${escapeHtml(finding.title)}</div><div class="finding-evidence">${escapeHtml(finding.evidence || finding.description || "No evidence provided")}</div></div>
            <span class="finding-tool">${escapeHtml(finding.source_tool)}</span>
        </article>`).join("");
}

async function loadSchedules() {
    const data = await request("/api/schedules");
    const container = $("#schedule-list");
    if (!data.schedules.length) {
        container.innerHTML = '<div class="empty-state">No recurring schedules.</div>';
        return;
    }
    container.innerHTML = data.schedules.map((schedule) => `
        <article class="schedule-item"><div><div class="schedule-target">${escapeHtml(schedule.target)}</div>
        <div class="schedule-meta">Every ${schedule.interval_minutes} min · next ${escapeHtml(formatDate(schedule.next_run_at))} · ${schedule.enabled ? "enabled" : "paused"}</div></div>
        <div class="schedule-actions"><button class="ghost-button schedule-toggle" data-id="${escapeHtml(schedule.id)}" data-enabled="${schedule.enabled}" type="button">${schedule.enabled ? "Pause" : "Enable"}</button>
        <button class="ghost-button schedule-delete" data-id="${escapeHtml(schedule.id)}" type="button">Delete</button></div></article>`).join("");
    container.querySelectorAll(".schedule-toggle").forEach((button) => button.addEventListener("click", async () => {
        await request(`/api/schedules/${encodeURIComponent(button.dataset.id)}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled: button.dataset.enabled !== "true" }) });
        await loadSchedules();
    }));
    container.querySelectorAll(".schedule-delete").forEach((button) => button.addEventListener("click", async () => {
        await request(`/api/schedules/${encodeURIComponent(button.dataset.id)}`, { method: "DELETE" });
        await loadSchedules();
    }));
}

$("#cve-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const results = $("#cve-results");
    results.innerHTML = '<div class="empty-state">Searching NVD...</div>';
    try {
        const query = $("#cve-query").value.trim();
        const data = await request(`/api/cves/search?q=${encodeURIComponent(query)}`);
        results.innerHTML = data.results.length ? data.results.map((cve) => `
            <article class="cve-result"><a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.id)}" target="_blank" rel="noreferrer">${escapeHtml(cve.id)}</a>
            <p>${escapeHtml(cve.description)}</p><div class="cve-meta">CVSS: ${escapeHtml(cve.cvss_score ?? "N/A")} · Published: ${escapeHtml(formatDate(cve.published))}</div></article>`).join("") : '<div class="empty-state">No matching CVEs found.</div>';
    } catch (error) { results.innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`; }
});

async function refreshAll() {
    if (sessionStorage.getItem("kmn_authorization_ack") !== "true") return;
    try { await Promise.all([loadDashboard(), loadTools(), loadJobs(), loadFindings(), loadSchedules()]); }
    catch (error) { $("#form-message").textContent = error.message; $("#form-message").className = "form-message error"; }
}

async function showScan(id) {
    try {
        const scan = await request(`/api/scans/${encodeURIComponent(id)}`);
        $("#dialog-title").textContent = scan.target;
        $("#dialog-content").innerHTML = `
            <div class="detail-block"><table class="detail-table"><tr><td>Status</td><td>${escapeHtml(scan.status)}</td></tr><tr><td>Profile</td><td>${escapeHtml(scan.profile)}</td></tr><tr><td>Message</td><td>${escapeHtml(scan.message || scan.error || "-")}</td></tr><tr><td>Created</td><td>${escapeHtml(formatDate(scan.created_at))}</td></tr></table></div>
            <div class="detail-block"><h4>Services (${scan.services.length})</h4><table class="detail-table">${scan.services.map((service) => `<tr><td>${escapeHtml(service.port)}/${escapeHtml(service.protocol)}</td><td>${escapeHtml(service.service || "unknown")} ${escapeHtml(service.product || "")} ${escapeHtml(service.version || "")}</td></tr>`).join("") || '<tr><td colspan="2">No open services</td></tr>'}</table></div>
            <div class="detail-block"><h4>Findings (${scan.findings.length})</h4>${scan.findings.map((finding) => `<div class="detail-finding"><strong>${escapeHtml(finding.severity.toUpperCase())} · ${escapeHtml(finding.title)}</strong><div class="finding-tool">${escapeHtml(finding.source_tool)} · confidence ${escapeHtml(finding.confidence)}</div><pre>${escapeHtml(finding.evidence || finding.description || "No evidence")}</pre></div>`).join("") || '<div class="empty-state">No findings reported.</div>'}</div>
            <div class="detail-block dialog-actions">
                <a class="ghost-button" href="/api/scans/${encodeURIComponent(id)}/export.csv">Export CSV</a>
                <a class="ghost-button" href="/api/scans/${encodeURIComponent(id)}/report" target="_blank" rel="noreferrer">HTML report</a>
                <button class="ghost-button" id="diff-button" type="button">Compare with previous</button>
            </div>
            <div id="diff-results"></div>`;
        $("#diff-button").addEventListener("click", () => loadDiff(id));
        $("#scan-dialog").showModal();
    } catch (error) { $("#form-message").textContent = error.message; $("#form-message").className = "form-message error"; }
}

async function loadDiff(id) {
    const container = $("#diff-results");
    container.innerHTML = '<div class="empty-state">Comparing with previous scan...</div>';
    try {
        const diff = await request(`/api/scans/${encodeURIComponent(id)}/diff`);
        if (!diff.previous) {
            container.innerHTML = '<div class="empty-state">No previous completed scan exists for this target yet.</div>';
            return;
        }
        if (!diff.comparable) {
            container.innerHTML = `<div class="empty-state">Scans cannot be compared safely: ${escapeHtml(diff.reason || "tool coverage differs")}</div>`;
            return;
        }
        container.innerHTML = `
            <div class="detail-block"><h4>Comparison with ${escapeHtml(formatDate(diff.previous.created_at))}</h4>
            <table class="detail-table"><tr><td>New findings</td><td>${diff.new.length}</td></tr><tr><td>Fixed findings</td><td>${diff.fixed.length}</td></tr><tr><td>Still present</td><td>${diff.persistent_count}</td></tr></table>
            ${diff.new.map((finding) => `<div class="detail-finding"><strong>NEW · ${escapeHtml(finding.severity.toUpperCase())} · ${escapeHtml(finding.title)}</strong></div>`).join("")}
            ${diff.fixed.map((finding) => `<div class="detail-finding"><strong>FIXED · ${escapeHtml(finding.severity.toUpperCase())} · ${escapeHtml(finding.title)}</strong></div>`).join("")}
            </div>`;
    } catch (error) { container.innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`; }
}

$("#scan-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = $("#start-button");
    const message = $("#form-message");
    button.disabled = true; message.className = "form-message"; message.textContent = "Queueing scan...";
    try {
        const data = await request("/api/scans", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
            target: $("#target").value, profile: $("#profile").value, include_nse: $("#include-nse").checked, include_cve_match: $("#include-cve-match").checked, include_nuclei: $("#include-nuclei").checked, include_tls: $("#include-tls").checked, include_zap: $("#include-zap").checked, include_udp: $("#include-udp").checked, include_ssh_audit: $("#include-ssh-audit").checked, authorization_confirmed: sessionStorage.getItem("kmn_authorization_ack") === "true",
        }) });
        message.className = "form-message success"; message.textContent = `Scan ${data.id.slice(0, 8)} queued.`; event.target.reset(); $("#include-nuclei").checked = true; $("#include-tls").checked = true; await refreshAll();
    } catch (error) { message.className = "form-message error"; message.textContent = error.message; }
    finally { button.disabled = false; }
});

$("#artifact-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const message = $("#artifact-message");
    message.textContent = "Queueing Trivy scan...";
    try {
        const data = await request("/api/artifacts/scans", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
            target: $("#artifact-target").value, mode: $("#artifact-mode").value, authorization_confirmed: sessionStorage.getItem("kmn_authorization_ack") === "true",
        }) });
        message.className = "form-message success"; message.textContent = `Artifact scan ${data.id.slice(0, 8)} queued.`; await loadJobs();
    } catch (error) { message.className = "form-message error"; message.textContent = error.message; }
});

$("#schedule-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const message = $("#schedule-message");
    message.textContent = "Creating schedule...";
    try {
        await request("/api/schedules", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
            target: $("#schedule-target").value, profile: $("#schedule-profile").value, interval_minutes: Number($("#schedule-interval").value), authorization_confirmed: sessionStorage.getItem("kmn_authorization_ack") === "true",
        }) });
        message.className = "form-message success"; message.textContent = "Recurring scan scheduled."; await loadSchedules();
    } catch (error) { message.className = "form-message error"; message.textContent = error.message; }
});

$("#windows-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const message = $("#windows-message");
    message.textContent = "Queueing Windows audit...";
    try {
        const data = await request("/api/windows/scans", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
            host: $("#windows-host").value, port: Number($("#windows-port").value), authorization_confirmed: sessionStorage.getItem("kmn_authorization_ack") === "true",
        }) });
        message.className = "form-message success"; message.textContent = `Windows audit ${data.id.slice(0, 8)} queued.`; await loadJobs();
    } catch (error) { message.className = "form-message error"; message.textContent = error.message; }
});

$("#cloud-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const message = $("#cloud-message");
    message.textContent = "Queueing cloud audit...";
    try {
        const data = await request("/api/cloud/scans", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
            provider: $("#cloud-provider").value, authorization_confirmed: sessionStorage.getItem("kmn_authorization_ack") === "true",
        }) });
        message.className = "form-message success"; message.textContent = `Cloud audit ${data.id.slice(0, 8)} queued.`; await loadJobs();
    } catch (error) { message.className = "form-message error"; message.textContent = error.message; }
});

$("#login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const errorBox = $("#login-error");
    errorBox.textContent = "";
    try {
        await request("/api/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password: $("#login-password").value }) });
        $("#login-dialog").close();
        await refreshAll();
    } catch (error) { errorBox.textContent = error.message; }
});

$("#refresh-button").addEventListener("click", refreshAll);
$("#close-dialog").addEventListener("click", () => $("#scan-dialog").close());
$("#scan-dialog").addEventListener("click", (event) => { if (event.target === $("#scan-dialog")) $("#scan-dialog").close(); });
initializeAuthorizationGate();
if (sessionStorage.getItem("kmn_authorization_ack") === "true") refreshAll();
setInterval(refreshAll, 5000);
