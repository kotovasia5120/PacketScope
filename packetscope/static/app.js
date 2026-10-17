/* PacketScope's browser client.  It renders untrusted values with textContent
 * and keeps large byte arrays bounded to a small virtual window of rows. */
const state = {
  result: null, annotations: [], selectedHypothesis: null, controller: null, jobId: null,
  compare: { ids: [], diffs: [], cursor: 0, mode: "offset" }, scrollTop: 0,
  undo: [], redo: [], schemaUndo: [], schemaRedo: [], editingAnnotation: null, editingSchemaField: null, schemaEditorSelection: null, hexSelection: null, hexDrag: null, hexClickSuppressed: false, demoProfile: null, flowId: "", direction: "both", requestVersion: 0,
  sourceFile: null, sourceFormat: "auto", sourceRaw: false, scopePending: false, displayOnlyScope: false, packetQuery: "", schema: null, authoredSchema: null, schemaValues: [], packetWindowStart: 0, deploymentMode: document.body.dataset.deploymentMode === "public-demo" ? "public-demo" : "local",
  experiment: { baseline: null, changed: null, metadata: null, report: null, annotations: [], selectedRange: null, controller: null, jobId: null, requestVersion: 0 }
};
const $ = (selector) => document.querySelector(selector);
const node = (tag, text, cls) => { const value = document.createElement(tag); if (text !== undefined) value.textContent = String(text); if (cls) value.className = cls; return value; };
const schemaEditorType = document.querySelector("#schema-editor-type"); if (schemaEditorType && !Array.from(schemaEditorType.options).some((option) => option.value === "custom")) schemaEditorType.append(Object.assign(node("option", "Custom bytes"), { value: "custom" }));
const allPackets = () => state.result?.packets || [];
const packets = () => {
  const selected = state.result?.flows?.find((flow) => flow.flow_id === state.flowId);
  const flows = state.result?.flows || [];
  if (!selected && (!flows.length || state.direction === "both")) return allPackets();
  const flowPackets = selected ? selected.packets || [] : flows.flatMap((flow) => flow.packets || []);
  const ids = new Set(flowPackets.filter((item) => state.direction === "both" || item.direction === state.direction).map((item) => Number(item.packet_id)));
  return allPackets().filter((packet) => ids.has(Number(packet.index)));
};
const selectedPacket = () => packets().find((packet) => packet.index === Number($("#packet-select").value));
const packetOptions = (prior) => { const available = packets(); const query = state.packetQuery.trim().toLowerCase(); const filtered = query ? available.filter((packet) => `${packet.index} ${packet.source_name || ""}`.toLowerCase().includes(query)) : available; const bounded = filtered.slice(0, 200); if (!query && prior >= 0 && available.some((packet) => packet.index === prior) && !bounded.some((packet) => packet.index === prior) && bounded.length) bounded[bounded.length - 1] = available.find((packet) => packet.index === prior); return bounded; };
const hexBytes = (value) => (String(value || "").match(/[0-9a-f]{2}/gi) || []).map((part) => part.toLowerCase());
const bytesOf = (packet) => {
  if ($("#payload-mode")?.value === "raw") return hexBytes(packet.raw_payload ?? packet.payload);
  if (packet.application_payload_available === false) return [];
  return hexBytes(packet.application_payload ?? packet.payload);
};
const setStatus = (text, error = false) => { $("#status").textContent = text; $("#status").classList.toggle("error", error); };
const isPublicDemo = () => state.deploymentMode === "public-demo";
const formatUploadLimit = (bytes) => bytes >= 1024 * 1024 && bytes % (1024 * 1024) === 0 ? `${bytes / (1024 * 1024)} MiB` : `${bytes.toLocaleString()} bytes`;
async function configureDeployment() {
  try {
    const response = await fetch("/api/health");
    if (!response.ok) return;
    const health = await response.json();
    state.deploymentMode = health.deployment_mode === "public-demo" ? "public-demo" : "local";
    if (health.privacy_notice) $("#privacy-notice").textContent = health.privacy_notice;
    if (Number.isInteger(health.upload_limit_bytes)) $(".limit-note").textContent = `${formatUploadLimit(health.upload_limit_bytes)} upload limit`;
    if (isPublicDemo()) {
      $("#analyze-button").textContent = "Upload to demo server";
      $("#privacy-badge").textContent = "Hosted public demo · uploads are transmitted to this server";
    }
  } catch {
    // The server-rendered copy remains truthful if the health request fails.
  }
}
configureDeployment();
const sourceKey = () => `packetscope:annotations:${contentHash(state.result?.packets || [])}`;
function contentHash(value) { let hash = 2166136261; const text = JSON.stringify(value); for (let i = 0; i < text.length; i += 1) { hash ^= text.charCodeAt(i); hash = Math.imul(hash, 16777619); } return (hash >>> 0).toString(16).padStart(8, "0"); }

$("#packet-file").addEventListener("change", (event) => { const file = event.target.files[0]; $("#file-name").textContent = file ? `${file.name} · ${file.size.toLocaleString()} bytes` : "Nothing loaded yet"; });
$("#upload-form").addEventListener("submit", (event) => { event.preventDefault(); analyzeFile($("#packet-file").files[0]); });
$("#demo-button").addEventListener("click", async () => { setStatus("Loading deterministic demo capture…"); try { const profile = $("#demo-profile").value; const response = await fetch(`/api/demo?profile=${encodeURIComponent(profile)}`); if (!response.ok) throw new Error("demo endpoint unavailable"); state.sourceFile = null; state.flowId = ""; state.direction = "both"; state.displayOnlyScope = false; loadResult(await response.json()); setStatus("Demo capture loaded. Inspect the evidence, then evaluate the reference."); } catch (error) { setStatus(error.message, true); } });
$("#download-demo-pcap").addEventListener("click", () => downloadDemo("pcap")); $("#download-demo-pcapng").addEventListener("click", () => downloadDemo("pcapng"));
$("#cancel-button").addEventListener("click", cancelCurrentJob);
$("#project-file").addEventListener("change", async (event) => { const file = event.target.files[0]; if (!file || file.size > 8 * 1024 * 1024) { setStatus("Saved project is too large.", true); return; } try { const value = JSON.parse(await file.text()); validateProject(value); loadResult(value, { restoreLocal: false }); setStatus("Restored saved project without applying stale browser annotations."); } catch (error) { setStatus(`Saved project is not valid: ${error.message}`, true); } });
$("#schema-file").addEventListener("change", async (event) => { const file = event.target.files[0]; if (!file || file.size > 2 * 1024 * 1024) { setStatus("Protocol schema is too large.", true); return; } try { const authored = JSON.parse(await file.text()); const schema = validateSchema(authored); if (!state.result) throw new Error("load a capture before applying a schema"); state.authoredSchema = cloneJson(authored); state.schema = schema; state.schemaValues = applySchema(schema); state.schemaUndo = []; state.schemaRedo = []; state.editingSchemaField = null; state.schemaEditorSelection = null; renderFields(); renderSchemaEditor(); updateSchemaHistoryButtons(); setStatus(`Applied protocol schema to ${state.schemaValues.length} packet(s).`); } catch (error) { setStatus(`Protocol schema is not valid: ${error.message}`, true); } });
$("#export-button").addEventListener("click", exportProject);
$("#export-schema-button").addEventListener("click", exportProtocolSchema);
$("#save-annotations").addEventListener("click", () => { if (!state.result) return; localStorage.setItem(sourceKey(), JSON.stringify(state.annotations)); setStatus("Annotations saved locally for this content hash."); });
$("#demo-evaluate").addEventListener("click", evaluateDemo);
$("#packet-select").addEventListener("change", () => { state.packetWindowStart = 0; state.hexSelection = null; updateHexSelectionControls(); renderPacket(); });
$("#packet-search").addEventListener("input", () => { state.packetQuery = $("#packet-search").value; render(); });
$("#payload-mode").addEventListener("change", () => { state.hexSelection = null; updateHexSelectionControls(); renderPacket(); renderComparison(); });
$("#offset-search").addEventListener("keydown", (event) => { if (event.key === "Enter") goOffset(); });
$("#go-offset").addEventListener("click", goOffset);
$("#hex-select-range").addEventListener("click", selectHexRangeFromControls);
$("#hex-selection-offset").addEventListener("keydown", (event) => { if (event.key === "Enter") selectHexRangeFromControls(); });
$("#hex-selection-width").addEventListener("keydown", (event) => { if (event.key === "Enter") selectHexRangeFromControls(); });
$("#hex-create-field").addEventListener("click", createSchemaFieldFromHexSelection);
$("#prev-diff").addEventListener("click", () => moveDiff(-1)); $("#next-diff").addEventListener("click", () => moveDiff(1));
$("#sync-scroll").addEventListener("change", renderComparison);
$("#compare-mode").addEventListener("change", () => { state.compare.mode = $("#compare-mode").value; renderComparison(); });
$("#compare-select").addEventListener("change", () => { state.compare.ids = Array.from($("#compare-select").selectedOptions).map((option) => Number(option.value)); state.compare.cursor = 0; renderComparison(); });
$("#hypothesis-type").addEventListener("change", renderHypotheses); $("#hypothesis-confidence").addEventListener("input", renderHypotheses); $("#evidence-only").addEventListener("change", renderHypotheses);
$("#annotation-form").addEventListener("submit", (event) => { event.preventDefault(); const start = Number($("#annotation-start").value); const width = Number($("#annotation-width").value); const label = $("#annotation-label").value.trim(); if (!label || !Number.isInteger(start) || start < 0 || !Number.isInteger(width) || width < 1) { setStatus("Annotation label, offsets, and width must be valid.", true); return; } const annotation = { label, field_type: $("#annotation-type").value, endian: $("#annotation-endian").value, start, end: start + width, coordinate_system: $("#payload-mode").value === "raw" ? "raw_packet" : "application_payload", source: "manual", status: "confirmed" }; pushUndo(); if (state.editingAnnotation === null) state.annotations.push(annotation); else state.annotations[state.editingAnnotation] = annotation; state.editingAnnotation = null; $("#annotation-submit").textContent = "Add annotation"; renderAnnotations(); setStatus("Manual annotation updated; export to persist it."); });
document.querySelectorAll(".tab").forEach((button) => button.addEventListener("click", () => { document.querySelectorAll(".tab").forEach((item) => item.classList.toggle("active", item === button)); document.querySelectorAll(".tab-panel").forEach((panel) => panel.classList.toggle("active", panel.dataset.panel === button.dataset.tab)); }));
$("#flow-select").addEventListener("change", () => { state.flowId = $("#flow-select").value; requestScopedAnalysis(); });
$("#direction-select").addEventListener("change", () => { state.direction = $("#direction-select").value; requestScopedAnalysis(); });
document.addEventListener("keydown", (event) => {
  if (!(event.ctrlKey || event.metaKey) || !["z", "y"].includes(event.key.toLowerCase())) return;
  const editingText = event.target?.matches?.("input, textarea, select, [contenteditable='true']");
  const schemaContext = !$("#schema-editor")?.hidden && !editingText;
  if (schemaContext) {
    event.preventDefault();
    const redo = event.key.toLowerCase() === "y" || (event.key.toLowerCase() === "z" && event.shiftKey);
    restoreSchemaHistory(redo);
    return;
  }
  if (editingText) return;
  event.preventDefault();
  const undoing = event.key.toLowerCase() === "z" && !event.shiftKey;
  const source = undoing ? state.undo : state.redo; const target = undoing ? state.redo : state.undo;
  if (!source.length) return;
  target.push(JSON.stringify(state.annotations)); state.annotations = JSON.parse(source.pop()); renderAnnotations(); setStatus(undoing ? "Annotation change undone." : "Annotation change redone.");
});
document.addEventListener("mouseup", () => { if (state.hexDrag) { state.hexClickSuppressed = state.hexDrag.moved; state.hexDrag = null; updateHexSelectionControls(); } });

async function analyzeFile(file) {
  if (!file) { setStatus("Choose a capture before analyzing.", true); return; }
  state.sourceFile = file; state.sourceFormat = $("#format").value; state.sourceRaw = $("#raw-analysis").checked;
  state.flowId = ""; state.direction = "both"; state.displayOnlyScope = false;
  const body = new FormData(); body.append("file", file, file.name); body.append("format", state.sourceFormat); if (state.sourceRaw) body.append("raw", "true");
  await runAnalysis(body, isPublicDemo() ? "Uploading evidence to the hosted demo and analyzing…" : "Reading evidence and analyzing locally…", false);
}

async function runAnalysis(body, message, preserveAnnotations) {
  const version = ++state.requestVersion; const controller = new AbortController(); state.controller = controller; let jobId = null;
  $("#cancel-button").hidden = false; $("#analyze-button").disabled = true; $("#analysis-progress").hidden = false; setStatus(message);
  try { const response = await fetch("/api/jobs", { method: "POST", body, signal: controller.signal }); const queued = await response.json(); if (!response.ok) throw new Error(queued.error || "Could not queue analysis"); jobId = queued.job_id; if (version !== state.requestVersion) return; state.jobId = jobId; let value; while (jobId) { await new Promise((resolve) => setTimeout(resolve, 60)); const statusResponse = await fetch(`/api/jobs/${jobId}`, { signal: controller.signal }); const status = await statusResponse.json(); if (version !== state.requestVersion) return; $("#analysis-progress").value = Number(status.progress || 0) / 100; $("#progress-label").textContent = `${status.status} · ${status.progress || 0}%`; if (status.status === "COMPLETE") { value = status.result; break; } if (status.status === "FAILED") throw new Error(status.error || "Analysis failed"); if (status.status === "CANCELLED") throw new DOMException("Analysis cancelled", "AbortError"); } if (!value) throw new Error("Analysis did not return a result"); if (version !== state.requestVersion) return; state.scopePending = false; loadResult(value, { preserveAnnotations }); setStatus(preserveAnnotations ? "Analysis scope updated for the selected flow and direction." : isPublicDemo() ? `Uploaded and analyzed ${value.source.packet_count} packet(s) on the hosted demo server.` : `Analyzed ${value.source.packet_count} packet(s) locally from ${value.source.name}.`); }
  catch (error) { if (version === state.requestVersion) { state.scopePending = false; setStatus(error.name === "AbortError" ? "Analysis cancelled." : error.message, true); render(); } }
  finally { if (version !== state.requestVersion) return; state.controller = null; state.jobId = null; state.scopePending = false; $("#cancel-button").hidden = true; $("#analyze-button").disabled = false; $("#analysis-progress").hidden = true; $("#progress-label").textContent = "Idle"; }
}

function requestScopedAnalysis() {
  if (!state.result) return;
  state.scopePending = true; state.displayOnlyScope = false; render();
  if (!state.sourceFile) { state.scopePending = false; state.displayOnlyScope = true; render(); setStatus("Scope changed for display only; the saved result has no source capture to reanalyze."); return; }
  state.controller?.abort();
  if (state.jobId) fetch(`/api/jobs/${state.jobId}`, { method: "DELETE" }).catch(() => {});
  const body = new FormData(); body.append("file", state.sourceFile, state.sourceFile.name); body.append("format", state.sourceFormat); body.append("direction", state.direction); if (state.sourceRaw) body.append("raw", "true"); if (state.flowId) body.append("flow_id", state.flowId);
  runAnalysis(body, isPublicDemo() ? "Uploading evidence to the hosted demo for the selected scope…" : "Reanalyzing the selected flow and direction…", true);
}
async function cancelCurrentJob() { const id = state.jobId; state.controller?.abort(); if (id) { try { await fetch(`/api/jobs/${id}`, { method: "DELETE" }); } catch { /* the server may already have completed cleanup */ } } }
function downloadDemo(format) { const profile = $("#demo-profile").value; const link = document.createElement("a"); link.href = `/api/demo/download?profile=${encodeURIComponent(profile)}&format=${format}`; link.download = `packetscope-${profile}.${format}`; link.click(); setStatus(isPublicDemo() ? `${format.toUpperCase()} demo downloaded from the hosted server.` : `${format.toUpperCase()} demo generated locally.`); }

function validateProject(value) { if (!value || typeof value !== "object" || !Array.isArray(value.packets) || value.packets.length > 100000) throw new Error("packet list is missing or too large"); if (value.schema_version !== undefined && value.schema_version !== 2) throw new Error("unsupported schema version"); if (Array.isArray(value.annotations) && value.annotations.length > 1000) throw new Error("too many annotations"); if (value.project?.schema_version !== undefined && value.project.schema_version !== 1) throw new Error("unsupported project schema version"); }
function validateSchema(value) { return PacketScopeSchema.validate(value); }
function applySchema(schema) { return PacketScopeSchema.apply(schema, packets()); }
function cloneJson(value) { return value === undefined ? undefined : JSON.parse(JSON.stringify(value)); }
function authoredSchemaForValidation() { return cloneJson(state.authoredSchema || state.schema); }
function validAnnotation(item) { return item && typeof item === "object" && typeof item.label === "string" && item.label.trim() && Number.isInteger(item.start) && item.start >= 0 && Number.isInteger(item.end) && item.end > item.start && item.end - item.start <= 16 * 1024 * 1024; }
function loadResult(result, options = {}) { validateProject(result); const priorAnnotations = state.annotations; state.result = result; state.selectedHypothesis = null; $("#stream-view").hidden = true; if (!options.preserveAnnotations) { state.schema = null; state.authoredSchema = null; state.schemaValues = []; state.hexSelection = null; } const imported = Array.isArray(result.annotations) ? result.annotations.filter(validAnnotation).slice(0, 1000) : []; let saved = []; if (!options.preserveAnnotations && options.restoreLocal !== false) { try { const candidate = JSON.parse(localStorage.getItem(sourceKey()) || "[]"); saved = Array.isArray(candidate) ? candidate.filter(validAnnotation).slice(0, 1000) : []; } catch { saved = []; } } state.annotations = options.preserveAnnotations ? priorAnnotations.slice(0, 1000) : (imported.length ? imported : saved); state.undo = []; state.redo = []; state.schemaUndo = []; state.schemaRedo = []; state.editingAnnotation = null; state.editingSchemaField = null; state.schemaEditorSelection = null; $("#annotation-submit").textContent = "Add annotation"; state.packetQuery = options.preserveAnnotations ? state.packetQuery : ""; $("#packet-search").value = state.packetQuery; state.demoProfile = result.demo?.profile || null; $("#results").hidden = false; $("#demo-evaluate").hidden = !state.demoProfile; render(); updateHexSelectionControls(); }
function render() {
  const result = state.result; const summary = $("#summary-grid"); summary.replaceChildren();
  const flowSelect = $("#flow-select"); const priorFlow = state.flowId; flowSelect.replaceChildren(node("option", "All flows")); flowSelect.firstChild.value = ""; (result.flows || []).forEach((flow) => flowSelect.append(Object.assign(node("option", `${flow.protocol.toUpperCase()} ${flow.endpoint_a.address}:${flow.endpoint_a.port} ↔ ${flow.endpoint_b.address}:${flow.endpoint_b.port}`), { value: flow.flow_id }))); if ((result.flows || []).some((flow) => flow.flow_id === priorFlow)) flowSelect.value = priorFlow; else { state.flowId = ""; flowSelect.value = ""; }
  $("#direction-select").value = state.direction; const selectedFlow = result.flows?.find((flow) => flow.flow_id === state.flowId); const selection = result.flow_selection || { flow_id: null, direction: "both", applied: false }; const matchesAnalysis = (selection.flow_id || "") === state.flowId && (selection.direction || "both") === state.direction; const heterogeneous = (result.flows || []).length > 1 && new Set((result.flows || []).map((flow) => flow.transport || flow.protocol)).size > 0; const heterogeneityWarning = !state.flowId && state.direction === "both" && heterogeneous ? " All flows / both directions may combine heterogeneous conversations; scope a flow before treating a pattern as shared." : ""; $("#flow-selection-status").textContent = selectedFlow ? `${packets().length} packet(s) in selected flow · ${state.direction} direction.` : `Showing ${packets().length} packet(s) across all flows.`; $("#flow-analysis-mode").textContent = state.scopePending ? "Analysis pending: hypotheses will be replaced when the selected scope finishes." : state.displayOnlyScope || !matchesAnalysis ? "Display-only filtering: hypotheses and evidence are from a different analysis scope." : selection.applied ? `Analysis scope: hypotheses and evidence were recomputed for this selection.${heterogeneityWarning}` : `Analysis scope: all captured packets and both directions.${heterogeneityWarning}`;
  [[result.source?.packet_count || result.packets.length, "packets"], [(result.source?.byte_count || 0).toLocaleString(), "source bytes"], [result.hypotheses?.length || 0, "candidate hypotheses"], [result.analysis?.status || "unknown", "analysis status"]].forEach(([value, label]) => { const metric = node("div", undefined, "metric"); metric.append(node("strong", value), node("span", label)); summary.append(metric); });
  const selector = $("#packet-select"); const prior = Number(selector.value); selector.replaceChildren(); packetOptions(prior).forEach((packet) => selector.append(Object.assign(node("option", `Packet ${packet.index} · ${bytesOf(packet).length} bytes`), { value: packet.index }))); if (packetOptions(prior).some((packet) => packet.index === prior)) selector.value = prior;
  const compare = $("#compare-select"); const oldIds = state.compare.ids.length ? state.compare.ids : packets().slice(0, 2).map((packet) => packet.index); compare.replaceChildren(); packets().slice(0, 64).forEach((packet) => { const option = Object.assign(node("option", `Packet ${packet.index} · ${bytesOf(packet).length} bytes`), { value: packet.index }); option.selected = oldIds.includes(packet.index); compare.append(option); }); state.compare.ids = oldIds.filter((id) => packets().some((packet) => packet.index === id));
  renderPacket(); renderComparison(); renderHypotheses(); renderFields(); renderCrc(); renderAnnotations();
}
function offsetForView(item, coordinateSystem) { if (!item) return -1; const source = item.coordinate_system || (item.payload_relative_offset !== undefined && item.payload_relative_offset !== null ? "application_payload" : "raw_packet"); if (source === coordinateSystem) return Number(source === "raw_packet" ? (item.absolute_offset ?? item.offset ?? -1) : (item.payload_relative_offset ?? item.offset ?? -1)); if (coordinateSystem === "raw_packet" && Number.isInteger(Number(item.absolute_offset))) return Number(item.absolute_offset); if (coordinateSystem === "application_payload" && Number.isInteger(Number(item.payload_relative_offset))) return Number(item.payload_relative_offset); return -1; }
const MAX_HEX_SELECTION_WIDTH = 16 * 1024 * 1024;
function currentCoordinateSystem() { return $("#payload-mode")?.value === "raw" ? "raw_packet" : "application_payload"; }
function hexSelectionStatus(text, error = false) { const view = $("#hex-selection-status"); if (!view) return; view.textContent = text; view.classList.toggle("error", error); }
function selectionMatchesView(selection = state.hexSelection) { return Boolean(selection && selection.packetIndex === Number($("#packet-select")?.value) && selection.coordinateSystem === currentCoordinateSystem()); }
function updateHexSelectionVisuals() {
  const selection = selectionMatchesView() ? state.hexSelection : null;
  document.querySelectorAll("#hex-view .hex-byte").forEach((byte) => {
    const offset = Number(byte.dataset.offset);
    byte.classList.toggle("hex-selection", Boolean(selection && offset >= selection.offset && offset < selection.offset + selection.width));
  });
}
function updateHexSelectionControls() {
  const selection = state.hexSelection;
  const button = $("#hex-create-field");
  if (selection) {
    $("#hex-selection-offset").value = `0x${selection.offset.toString(16)}`;
    $("#hex-selection-width").value = selection.width;
    hexSelectionStatus(`Packet ${selection.packetIndex} · ${selection.coordinateSystem} · offset 0x${selection.offset.toString(16)} · ${selection.width} byte(s)`);
  } else {
    hexSelectionStatus("No bytes selected.");
  }
  if (button) button.disabled = !selection;
  updateHexSelectionVisuals();
}
function setHexSelection(offset, width, packet = selectedPacket(), coordinateSystem = currentCoordinateSystem()) {
  if (!packet || !Number.isInteger(offset) || offset < 0 || !Number.isInteger(width) || width < 1 || width > MAX_HEX_SELECTION_WIDTH) return false;
  const bytes = coordinateSystem === currentCoordinateSystem() ? bytesOf(packet) : [];
  if (bytes.length && offset + width > bytes.length) return false;
  state.hexSelection = { packetIndex: Number(packet.index), coordinateSystem, offset, width };
  updateHexSelectionControls();
  return true;
}
function parseOffsetValue(raw) { const value = String(raw || "").trim(); if (/^0x[0-9a-f]+$/i.test(value)) return parseInt(value, 16); if (/^\d+$/.test(value)) return Number(value); return -1; }
function selectHexRangeFromControls() {
  const packet = selectedPacket(); const offset = parseOffsetValue($("#hex-selection-offset").value); const width = Number($("#hex-selection-width").value); const bytes = bytesOf(packet || {});
  if (!packet || !Number.isSafeInteger(offset) || offset < 0 || !Number.isInteger(width) || width < 1 || width > MAX_HEX_SELECTION_WIDTH || offset + width > bytes.length) { hexSelectionStatus("Enter a byte range inside the selected packet.", true); return; }
  state.packetWindowStart = Math.max(0, Math.floor(offset / 16 - 128) * 16);
  setHexSelection(offset, width, packet);
  renderPacket();
  hexSelectionStatus(`Packet ${packet.index} · ${currentCoordinateSystem()} · offset 0x${offset.toString(16)} · ${width} byte(s)`);
}
function selectHexByte(offset, event) {
  const packet = selectedPacket(); if (!packet) return;
  let start = offset; let end = offset;
  if (event?.shiftKey && selectionMatchesView()) { start = Math.min(state.hexSelection.offset, offset); end = Math.max(state.hexSelection.offset + state.hexSelection.width - 1, offset); }
  setHexSelection(start, end - start + 1, packet);
}
function beginHexDrag(offset) { const packet = selectedPacket(); if (!packet) return; state.hexClickSuppressed = false; state.hexDrag = { packetIndex: Number(packet.index), coordinateSystem: currentCoordinateSystem(), start: offset, current: offset, moved: false }; setHexSelection(offset, 1, packet); }
function updateHexDrag(offset) { if (!state.hexDrag) return; if (state.hexDrag.packetIndex !== Number($("#packet-select").value) || state.hexDrag.coordinateSystem !== currentCoordinateSystem()) return; state.hexDrag.current = offset; state.hexDrag.moved ||= offset !== state.hexDrag.start; const start = Math.min(state.hexDrag.start, offset); const end = Math.max(state.hexDrag.start, offset); setHexSelection(start, end - start + 1); }
function createHexByte(value, offset, selectedStart, selectedWidth, transform, parent) {
  const byte = node("span", transform(value), "hex-byte"); byte.dataset.offset = String(offset); byte.tabIndex = 0; byte.setAttribute("role", "button"); byte.setAttribute("aria-label", `Byte at offset 0x${offset.toString(16)}`);
  if (offset >= selectedStart && offset < selectedStart + selectedWidth) byte.classList.add("byte-hit");
  byte.addEventListener("mousedown", (event) => { if (event.button !== 0) return; event.preventDefault(); beginHexDrag(offset); });
  byte.addEventListener("mouseenter", () => updateHexDrag(offset));
  byte.addEventListener("click", (event) => { if (state.hexClickSuppressed) { state.hexClickSuppressed = false; return; } selectHexByte(offset, event); });
  byte.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); selectHexByte(offset, event); } });
  parent.append(byte);
}
function renderPacket() { const packet = selectedPacket(); const view = $("#hex-view"); if (!packet) return; const previous = view.scrollTop; const bytes = bytesOf(packet); const selected = state.selectedHypothesis; const coordinateSystem = $("#payload-mode")?.value === "raw" ? "raw_packet" : "application_payload"; const start = offsetForView(selected, coordinateSystem); const width = selected?.width || (selected?.width_bits ? selected.width_bits / 8 : 0); const windowStart = Math.min(Math.max(0, state.packetWindowStart || 0), Math.max(0, Math.floor((bytes.length - 1) / 16) * 16)); const windowBytes = bytes.slice(windowStart, windowStart + 512 * 16); view.replaceChildren(); const maxRows = Math.min(Math.ceil(windowBytes.length / 16), 512); for (let row = 0; row < maxRows; row += 1) { const rowStart = windowStart + row * 16; const chunk = windowBytes.slice(row * 16, row * 16 + 16); const line = node("div", undefined, "hex-line"); line.append(node("span", rowStart.toString(16).padStart(8, "0"), "offset")); const hex = node("span"); const ascii = node("span", undefined, "ascii"); appendRuns(hex, chunk, rowStart, start, width, (value) => value); appendRuns(ascii, chunk, rowStart, start, width, (value) => { const number = parseInt(value, 16); return number >= 32 && number <= 126 ? String.fromCharCode(number) : "."; }); line.append(hex, ascii); view.append(line); } if (!bytes.length) view.append(node("p", "Empty packet.", "muted")); view.scrollTop = previous; updateHexSelectionControls(); }
function appendRuns(parent, chunk, rowStart, selectedStart, selectedWidth, transform) {
  chunk.forEach((value, index) => {
    const offset = rowStart + index;
    createHexByte(value, offset, selectedStart, selectedWidth, transform, parent);
    if (!parent.classList.contains("ascii") && index < chunk.length - 1) parent.append(document.createTextNode(" "));
  });
}
function goOffset() { const raw = $("#offset-search").value.trim(); const query = raw.replace(/\s+/g, "").toLowerCase(); const bytes = bytesOf(selectedPacket() || {}); let offset = /^0x[0-9a-f]+$/i.test(raw) ? parseInt(raw, 16) : /^\d+$/.test(raw) ? Number(raw) : -1; if (offset < 0 && /^[0-9a-f]+$/.test(query) && query.length % 2 === 0) offset = findSequence(bytes, hexBytes(query)); if (Number.isInteger(offset) && offset >= 0 && offset < bytes.length) { state.packetWindowStart = Math.max(0, Math.floor(offset / 16 - 128) * 16); renderPacket(); $("#hex-view").scrollTop = Math.max(0, Math.floor((offset - state.packetWindowStart) / 16) * 32); setStatus(`Viewing offset 0x${offset.toString(16)}.`); } else setStatus("Enter a decimal/hexadecimal offset or a HEX sequence.", true); }
function findSequence(haystack, needle) { if (!needle.length) return -1; for (let i = 0; i <= haystack.length - needle.length; i += 1) if (needle.every((value, index) => haystack[i + index] === value)) return i; return -1; }

function comparePackets() { return state.compare.ids.map((id) => packets().find((packet) => packet.index === id)).filter(Boolean); }
function diffMap(a, b, mode) { if (mode === "offset") { const result = []; for (let i = 0; i < Math.max(a.length, b.length); i += 1) result.push({ a: a[i], b: b[i], status: a[i] === undefined ? "inserted" : b[i] === undefined ? "deleted" : a[i] === b[i] ? "identical" : "modified", index: i }); return result; } const matcher = new SequenceMatcher(a.slice(0, 4096), b.slice(0, 4096)); return matcher.align(); }
function renderComparison() { const container = $("#comparison-view"); container.replaceChildren(); const selected = comparePackets(); if (selected.length < 2) { $("#compare-status").textContent = "Select at least two packets."; return; } const base = bytesOf(selected[0]); const maps = selected.slice(1).map((packet) => diffMap(base, bytesOf(packet), state.compare.mode)); state.compare.diffs = maps[0].filter((item) => item.status !== "identical").map((item) => item.index); const active = state.compare.diffs[state.compare.cursor]; $("#compare-status").textContent = `${selected.length} packets · ${state.compare.diffs.length} differences · ${state.compare.mode} mode`;
  const grid = node("div", undefined, "dual-hex"); selected.forEach((packet, packetIndex) => { const pane = node("section", undefined, "compare-pane"); pane.append(node("h3", `Packet ${packet.index} · ${bytesOf(packet).length} bytes`)); const view = node("div", undefined, "hex-view"); view.dataset.compareIndex = String(packetIndex); const bytes = bytesOf(packet); const map = packetIndex === 0 ? null : maps[packetIndex - 1]; for (let row = 0; row < Math.min(512, Math.ceil(bytes.length / 16)); row += 1) { const start = row * 16; const line = node("div", undefined, "hex-line"); const status = map ? map.slice(start, start + 16).map((item) => item.status) : []; const selectedStart = state.selectedHypothesis ? Number(state.selectedHypothesis.payload_relative_offset ?? state.selectedHypothesis.offset ?? -1) : -1; const selectedWidth = state.selectedHypothesis?.width || (state.selectedHypothesis?.width_bits || 0) / 8; const rowStatus = active >= start && active < start + 16 ? "active-diff" : selectedStart >= start && selectedStart < start + 16 ? "field-hit" : status.includes("modified") ? "modified" : status.includes("inserted") ? "inserted" : status.includes("deleted") ? "deleted" : "identical"; line.classList.add(rowStatus); line.append(node("span", start.toString(16).padStart(8, "0"), "offset"), node("span", bytes.slice(start, start + 16).join(" ")), node("span", bytes.slice(start, start + 16).map((value) => { const number = parseInt(value, 16); return number >= 32 && number <= 126 ? String.fromCharCode(number) : "."; }).join(""), "ascii")); view.append(line); } pane.append(view); grid.append(pane); }); container.append(grid); if ($("#sync-scroll").checked) { const views = Array.from(container.querySelectorAll(".compare-pane .hex-view")); views.forEach((view) => view.addEventListener("scroll", () => views.forEach((other) => { if (other !== view) other.scrollTop = view.scrollTop; }))); } }
function moveDiff(step) { if (!state.compare.diffs.length) return; state.compare.cursor = (state.compare.cursor + step + state.compare.diffs.length) % state.compare.diffs.length; renderComparison(); }

function renderHypotheses() { const container = $("#hypotheses-view"); container.replaceChildren(); if (state.scopePending) { container.append(node("p", "Waiting for scoped analysis; the previous hypotheses are hidden.", "muted")); return; } const all = state.result?.hypotheses || []; const type = $("#hypothesis-type"); const known = new Set(all.map((item) => item.field_type || item.kind || "field")); const selectedType = type.value; type.replaceChildren(node("option", "All types")); type.firstChild.value = ""; Array.from(known).sort().forEach((value) => type.append(Object.assign(node("option", value.replaceAll("_", " ")), { value }))); type.value = selectedType; const minimum = Number($("#hypothesis-confidence").value); all.filter((item) => (!type.value || (item.field_type || item.kind) === type.value) && Number(item.confidence || 0) >= minimum && (!$("#evidence-only").checked || (item.evidence || []).length)).forEach((hypothesis) => { const card = node("article", undefined, "hypothesis-card"); if (state.selectedHypothesis === hypothesis) card.classList.add("selected"); card.tabIndex = 0; const group = hypothesis.interpretation_group; const groupText = group ? ` · alternative group ${group.id} (${group.widths_bytes.join("/\u00a0")} byte widths)` : ""; card.append(node("strong", (hypothesis.field_type || hypothesis.kind || "field").replaceAll("_", " ")), node("p", `Packet ${hypothesis.packet_id}; offset 0x${Number(hypothesis.absolute_offset ?? hypothesis.offset ?? 0).toString(16)}; width ${hypothesis.width || (hypothesis.width_bits || 8) / 8} byte(s); heuristic ranking ${Math.round(Number(hypothesis.ranking?.score ?? hypothesis.confidence ?? 0) * 100)}%.${groupText}`)); card.addEventListener("click", () => { state.selectedHypothesis = hypothesis; renderPacket(); renderComparison(); renderHypotheses(); renderEvidence(); }); card.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); card.click(); } }); container.append(card); }); if (!container.childNodes.length) container.append(node("p", "No candidate matches the current filters.", "muted")); }
function renderEvidence() { const view = $("#evidence-view"); view.replaceChildren(); const item = state.selectedHypothesis; if (!item) { view.append(node("p", "Select a hypothesis to inspect its evidence.", "muted")); return; } view.append(node("strong", item.field_type || item.kind || "field"), node("p", item.caveats?.[0] || "This interpretation is not confirmed.")); if (item.interpretation_group) view.append(node("p", `Ambiguous interpretation group: ${item.interpretation_group.id}. Other compatible widths: ${item.interpretation_group.widths_bytes.join(", ")} byte(s); endianness observed: ${item.interpretation_group.endianness.join(", ")}.`)); if (item.evidence_quality) view.append(node("p", `Evidence basis: ${item.evidence_quality.basis}; ${item.evidence_quality.independent_samples} observed samples; independently verified: ${item.evidence_quality.independently_verified ? "yes" : "no"}.`)); (item.evidence || []).slice(0, 4).forEach((evidence) => view.append(node("p", evidence.rationale || JSON.stringify(evidence)))); if (item.what_would_help?.length) { view.append(node("h3", "What would help confirm this?")); item.what_would_help.forEach((hint) => view.append(node("p", hint, "muted"))); } }
function renderFields() {
  const view = $("#fields-view"); view.replaceChildren();
  if (state.scopePending) { view.append(node("p", "Waiting for scoped analysis.", "muted")); return; }
  if (state.schema) {
    view.append(node("h3", `Applied schema: ${state.schema.name || "PacketScope protocol"} · V${state.schema.schema_version}`), node("p", "Schema fields are declarative descriptions. Values are read from bounded capture bytes; status and diagnostics remain explicit."));
    function findSchemaOutput(fields, target) { for (const candidate of fields || []) { if (candidate.id === target.id || candidate.name === target.name) return candidate; const nested = findSchemaOutput(candidate.fields, target); if (nested) return nested; const item = (candidate.items || []).map((entry) => findSchemaOutput([entry], target)).find(Boolean); if (item) return item; } return null; }
    const renderSchemaField = (field, depth = 0, parentId = "") => {
      if (depth > 16) return;
      const samples = state.schemaValues.slice(0, 8).map((packet) => {
        const item = findSchemaOutput(packet.fields, field);
        const value = item?.present === false ? "absent" : item?.available ? item.value : item?.status || "unavailable";
        return `P${packet.packetId}: ${value}`;
      });
      const sample = findSchemaOutput(state.schemaValues[0]?.fields, field);
      const diagnostics = (sample?.diagnostics || []).slice(0, 2).map((item) => `${item.code}: ${item.message}`).join(" · ");
      const row = node("div", undefined, `field-row schema-value-row depth-${Math.min(depth, 4)}`); row.dataset.fieldId = field.id;
      const location = sample?.offset === null || sample?.offset === undefined ? "dynamic/unresolved" : `offset 0x${Number(sample.offset).toString(16)}`;
      const length = sample?.length === null || sample?.length === undefined ? "dynamic length" : `${sample.length} byte(s)`;
      row.append(node("strong", `${field.name} · ${field.id}`), node("span", `${field.type || "bytes"} · ${location} · ${length} · ${sample?.status || "UNKNOWN"}`), node("span", `${field.description || "No description."}${diagnostics ? ` · ${diagnostics}` : ""} · ${samples.join(" · ")}`));
      view.append(row);
      if (sample?.fields && Array.isArray(field.fields)) field.fields.slice(0, 64).forEach((child) => renderSchemaField(child, depth + 1, field.id));
      if (sample?.items && field.array?.element) sample.items.slice(0, 16).forEach((item, index) => { const itemRow = node("div", undefined, `field-row schema-array-item depth-${Math.min(depth + 1, 4)}`); itemRow.append(node("strong", `${field.name}[${index}]`), node("span", `${item.status || "UNKNOWN"} · offset ${item.offset === null ? "?" : `0x${Number(item.offset).toString(16)}`}`), node("span", item.present === false ? "absent" : item.available ? item.value : (item.diagnostics || []).map((entry) => entry.message).join("; ") || "unavailable")); view.append(itemRow); });
    };
       state.schema.fields.slice(0, 1000).forEach((field) => renderSchemaField(field));
    const relationships = state.schemaValues.flatMap((packet) => (packet.relationships || []).map((relationship) => ({ packetId: packet.packetId, relationship })));
    if (relationships.length) {
      view.append(node("h3", "Checksum relationships"));
      relationships.slice(0, 32).forEach(({ packetId, relationship }) => {
        const row = node("div", undefined, "field-row schema-value-row");
        const status = String(relationship.status || "unknown").toUpperCase();
        const ranges = (relationship.covered_ranges || []).map((range) => `[0x${Number(range[0]).toString(16)}, 0x${Number(range[1]).toString(16)})`).join(", ") || "unresolved range";
        row.append(node("strong", `${relationship.algorithm || "checksum"} · ${status}`), node("span", `P${packetId} · ${relationship.checksum_field_id || relationship.id || "relationship"} · ${ranges}`), node("span", relationship.diagnostics?.[0]?.message || `${relationship.expected ?? "?"} → ${relationship.actual ?? "?"}`));
        view.append(row);
      });
    }
  }
  const fields = (state.result?.hypotheses || []).filter((item) => item.field_type && item.field_type !== "crc"); if (!fields.length && !state.schema) view.append(node("p", "No field hypotheses.", "muted"));
  fields.forEach((field) => { const row = node("div", undefined, "field-row"); row.append(node("strong", field.field_type.replaceAll("_", " ")), node("span", `offset 0x${Number(field.absolute_offset ?? field.offset ?? 0).toString(16)} · ${field.width || (field.width_bits || 8) / 8} byte(s)`), node("span", `${(field.locations || []).length || field.sample_count || 1} packet location(s)`)); row.addEventListener("click", () => { state.selectedHypothesis = field; renderPacket(); renderComparison(); }); view.append(row); });
}
function renderCrc() { const view = $("#crc-view"); view.replaceChildren(); const contradictions = $("#contradictions-view"); contradictions.replaceChildren(); if (state.scopePending) { view.append(node("p", "Waiting for scoped analysis.", "muted")); return; } const fields = (state.result?.hypotheses || []).filter((item) => item.algorithm || item.field_type === "crc" || item.field_type === "checksum"); fields.forEach((field) => { const row = node("div", undefined, "field-row"); row.append(node("strong", field.algorithm || field.field_type), node("span", `${field.checksum?.location_mode || "absolute"} · ${field.checksum?.matches || 0}/${field.checksum?.samples || 0} samples`), node("span", `locations: ${(field.checksum?.locations || []).join(", ") || field.absolute_offset}`)); row.addEventListener("click", () => { state.selectedHypothesis = field; renderPacket(); }); view.append(row); (field.caveats || []).forEach((caveat) => contradictions.append(node("p", caveat, "muted"))); }); if (!fields.length) view.append(node("p", "No checksum hypothesis found.", "muted")); }
function renderAnnotations() { const view = $("#annotations-view"); view.replaceChildren(); state.annotations.forEach((annotation, index) => { const item = node("li"); item.append(node("span", `${annotation.label} · 0x${annotation.start.toString(16)}–0x${annotation.end.toString(16)}`)); const actions = node("span", undefined, "annotation-actions"); const edit = node("button", "Edit", "secondary"); edit.type = "button"; edit.addEventListener("click", () => { state.editingAnnotation = index; $("#annotation-label").value = annotation.label; $("#annotation-type").value = annotation.field_type || "custom"; $("#annotation-endian").value = annotation.endian || "unknown"; $("#annotation-start").value = annotation.start; $("#annotation-width").value = Math.max(1, annotation.end - annotation.start); $("#annotation-submit").textContent = "Update annotation"; $("#annotation-label").focus(); }); const remove = node("button", "Remove"); remove.type = "button"; remove.addEventListener("click", () => { pushUndo(); state.annotations.splice(index, 1); if (state.editingAnnotation === index) { state.editingAnnotation = null; $("#annotation-submit").textContent = "Add annotation"; } renderAnnotations(); }); actions.append(edit, remove); item.append(actions); view.append(item); }); }
function pushUndo() { state.undo.push(JSON.stringify(state.annotations)); if (state.undo.length > 30) state.undo.shift(); state.redo = []; }
function exportProject() { if (!state.result) return; const copy = JSON.parse(JSON.stringify(state.result)); copy.annotations = state.annotations; copy.project = { schema_version: 1, content_hash: contentHash(copy.packets) }; const blob = new Blob([JSON.stringify(copy, null, 2)], { type: "application/json" }); const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = `${state.result.source?.name || "packetscope-project"}.json`; link.click(); URL.revokeObjectURL(link.href); setStatus("Project exported with annotations."); }
function exportProtocolSchema() {
  if (!state.result) return;
  const coordinateSystem = $("#payload-mode").value === "raw" ? "raw_packet" : "application_payload";
  const fields = [];
  (state.result.hypotheses || []).forEach((item) => {
    const fieldCoordinateSystem = item.coordinate_system || coordinateSystem;
    const offset = fieldCoordinateSystem === "application_payload" ? Number(item.payload_relative_offset ?? item.absolute_offset ?? item.offset ?? 0) : Number(item.absolute_offset ?? item.offset ?? 0);
    const name = item.field_type || item.kind || "field";
    fields.push({
      id: `${name.replace(/[^a-zA-Z0-9]+/g, "_").toLowerCase()}_${stableClientHash(`${name}:${offset}:${item.width || item.width_bits || 8}:${fieldCoordinateSystem}`)}`,
      name, description: "Inferred field; review before treating it as a protocol fact.", type: browserSchemaType(item, Number(item.width || (item.width_bits || 8) / 8)), offset,
      length: Number(item.width || (item.width_bits || 8) / 8), endian: item.endian || "unknown", coordinate_system: fieldCoordinateSystem,
      observed_values: item.candidate_value ?? [], constraints: item.interpretation_group || {}, metadata: { origin: "inferred", review_status: "hypothesis" },
      evidence_refs: (item.evidence || []).map((evidence) => evidence.packet_ids || []), known_limitations: [...(item.caveats || []), ...(item.what_would_help || [])],
    });
  });
  state.annotations.forEach((item) => fields.push({
    id: `${item.label.replace(/[^a-zA-Z0-9]+/g, "_").toLowerCase()}_${stableClientHash(`${item.label}:${item.start}:${item.end}:${item.coordinate_system || coordinateSystem}`)}`,
    name: item.label, description: "Manually reviewed field annotation.", type: browserSchemaType(item, item.end - item.start), offset: item.start, length: item.end - item.start,
    endian: item.endian || "unknown", coordinate_system: item.coordinate_system || coordinateSystem, metadata: { origin: "manual", review_status: item.status || "confirmed" },
  }));
  fields.sort((left, right) => Number(left.offset) - Number(right.offset) || Number(left.length) - Number(right.length) || left.name.localeCompare(right.name));
  const schema = validateSchema({
    schema_version: 2, name: "PacketScope protocol", coordinate_system: coordinateSystem, fields,
    source: { packet_count: allPackets().length, analysis_scope: state.result.analysis?.scope || "unknown" },
    limitations: ["Descriptions only; no executable parser is generated.", "Inferred fields remain hypotheses until manually reviewed.", "Offsets are relative to the declared coordinate system."],
  });
  const blob = new Blob([JSON.stringify(schema, null, 2)], { type: "application/json" }); const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = `${state.result.source?.name || "packetscope-protocol"}.schema.json`; link.click(); URL.revokeObjectURL(link.href);
  setStatus("Versioned protocol schema exported; inferred fields remain hypotheses.");
}
function browserSchemaType(item, width) { const type = String(item.field_type || item.kind || "bytes").toLowerCase(); if (["bytes", "raw", "opaque", "custom", "hex", "checksum", "crc", "text", "string", "utf8", "ascii", "bool", "boolean", "uint8", "uint16", "uint32", "uint64", "int8", "int16", "int32", "int64"].includes(type)) return type; if (type === "length_field" && [1, 2, 4, 8].includes(width)) return `uint${width * 8}`; return "bytes"; }
function stableClientHash(value) { let hash = 2166136261; const text = String(value); for (let index = 0; index < text.length; index += 1) { hash ^= text.charCodeAt(index); hash = Math.imul(hash, 16777619); } return (hash >>> 0).toString(16).padStart(8, "0"); }
async function evaluateDemo() { if (!state.demoProfile || !state.result) return; $("#demo-evaluate").disabled = true; try { const payload = { profile: state.demoProfile, evaluation_id: state.result.demo?.evaluation_id }; if (!payload.evaluation_id) payload.result = state.result; const response = await fetch("/api/demo/evaluate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }); const evaluation = await response.json(); if (!response.ok) throw new Error(evaluation.error || "evaluation failed"); const view = $("#evaluation-view"); view.hidden = false; view.replaceChildren(node("strong", `${evaluation.trusted ? "Trusted server reference" : "Untrusted client comparison"} · precision ${formatMetric(evaluation.precision)} · recall ${formatMetric(evaluation.recall)} · F1 ${formatMetric(evaluation.f1)}`), node("p", `${evaluation.matched} matched · ${evaluation.unmatched} unmatched hypotheses · ${evaluation.missed} missed ground-truth fields. ${evaluation.trusted ? "The server re-evaluated its stored analysis identity; client edits were not used." : "Client-submitted metrics are comparative only."}`)); setStatus("Reference evaluation is now visible after investigation."); } catch (error) { setStatus(error.message, true); } finally { $("#demo-evaluate").disabled = false; } }
function formatMetric(value) { return value === null || value === undefined ? "N/A" : `${Math.round(value * 100)}%`; }

/* Small bounded LCS alignment.  It emits one status per logical byte, but the
 * renderer groups those statuses into 16-byte rows rather than creating a DOM
 * element for every byte of a capture. */
class SequenceMatcher { constructor(a, b) { this.a = a; this.b = b; } align() { const a = this.a; const b = this.b; const width = b.length + 1; const table = Array.from({ length: a.length + 1 }, () => new Uint16Array(width)); for (let i = a.length - 1; i >= 0; i -= 1) for (let j = b.length - 1; j >= 0; j -= 1) table[i][j] = a[i] === b[j] ? table[i + 1][j + 1] + 1 : Math.max(table[i + 1][j], table[i][j + 1]); const out = []; let i = 0; let j = 0; while (i < a.length || j < b.length) { if (i < a.length && j < b.length && a[i] === b[j]) { out.push({ a: a[i], b: b[j], status: "identical", index: i }); i += 1; j += 1; } else if (j < b.length && (i === a.length || table[i][j + 1] >= table[i + 1][j])) { out.push({ a: undefined, b: b[j], status: "inserted", index: i }); j += 1; } else { out.push({ a: a[i], b: undefined, status: "deleted", index: i }); i += 1; } } return out; } }

/* Controlled experiments deliberately use the Python report as their only
 * inference source.  The browser renders bounded evidence, stores review
 * annotations separately, and never recomputes a field meaning. */
function experimentStatus(text, error = false) { const view = $("#experiment-status"); view.textContent = text; view.classList.toggle("error", error); }
function experimentFilesReady() { return Boolean(state.experiment.baseline && state.experiment.changed); }
function experimentFormData(includeScope = true) {
  const exp = state.experiment; const body = new FormData();
  body.append("baseline", exp.baseline, exp.baseline.name); body.append("changed", exp.changed, exp.changed.name);
  body.append("baseline_format", $("#experiment-baseline-format").value); body.append("changed_format", $("#experiment-changed-format").value);
  body.append("baseline_direction", $("#experiment-baseline-direction").value); body.append("changed_direction", $("#experiment-changed-direction").value);
  if (includeScope) { if ($("#experiment-baseline-flow").value) body.append("baseline_flow_id", $("#experiment-baseline-flow").value); if ($("#experiment-changed-flow").value) body.append("changed_flow_id", $("#experiment-changed-flow").value); }
  if ($("#experiment-raw").checked) body.append("raw", "true"); body.append("change_label", $("#experiment-change-label").value.trim() || "controlled change"); return body;
}
function updateExperimentFileLabel(side, file) { $(`#experiment-${side}-name`).textContent = file ? `${file.name} · ${file.size.toLocaleString()} bytes` : "Nothing loaded"; }
function populateExperimentFlows(side, flows) {
  const select = $(`#experiment-${side}-flow`); const prior = select.value; select.replaceChildren(node("option", "All flows")); select.firstChild.value = "";
  (flows || []).forEach((flow) => { const label = `${String(flow.protocol || "flow").toUpperCase()} ${flow.endpoint_a.address}:${flow.endpoint_a.port} ↔ ${flow.endpoint_b.address}:${flow.endpoint_b.port} · ${flow.packet_count} packets`; select.append(Object.assign(node("option", label), { value: flow.flow_id })); });
  if ((flows || []).some((flow) => flow.flow_id === prior)) select.value = prior;
}
async function prepareExperimentCaptures() {
  if (!experimentFilesReady()) { experimentStatus("Choose both a baseline and changed capture first.", true); return false; }
  try {
    experimentStatus("Importing both captures and discovering bounded flow options…"); $("#experiment-load-button").disabled = true;
    const response = await fetch("/api/experiments/prepare", { method: "POST", body: experimentFormData(false) }); const value = await response.json();
    if (!response.ok) throw new Error(value.error || "Could not load experiment captures"); state.experiment.metadata = value; state.experiment.report = null; state.experiment.annotations = []; state.experiment.selectedRange = null;
    populateExperimentFlows("baseline", value.baseline.flows); populateExperimentFlows("changed", value.changed.flows); $("#experiment-results").hidden = true;
    experimentStatus(`Loaded ${value.baseline.packet_count} baseline packet(s) and ${value.changed.packet_count} changed packet(s). Select independent scopes, then run.`); return true;
  } catch (error) { experimentStatus(error.message, true); return false; }
  finally { $("#experiment-load-button").disabled = false; }
}
async function runExperiment() {
  if (!experimentFilesReady()) { experimentStatus("Choose both a baseline and changed capture first.", true); return; }
  if (!state.experiment.metadata && !(await prepareExperimentCaptures())) return;
  const version = ++state.experiment.requestVersion; const controller = new AbortController(); state.experiment.controller = controller; $("#experiment-run-button").disabled = true; $("#experiment-load-button").disabled = true; $("#experiment-cancel-button").hidden = false; $("#experiment-progress").hidden = false; experimentStatus("Queueing controlled comparison…");
  try {
    const response = await fetch("/api/experiments", { method: "POST", body: experimentFormData(true), signal: controller.signal }); const queued = await response.json(); if (!response.ok) throw new Error(queued.error || "Could not queue experiment"); state.experiment.jobId = queued.job_id;
    let status; while (state.experiment.jobId && version === state.experiment.requestVersion) { await new Promise((resolve) => setTimeout(resolve, 60)); const statusResponse = await fetch(`/api/jobs/${state.experiment.jobId}`, { signal: controller.signal }); status = await statusResponse.json(); $("#experiment-progress").value = Number(status.progress || 0); $("#experiment-progress-label").textContent = `${status.status} · ${status.progress || 0}%`; if (["COMPLETE", "FAILED", "CANCELLED"].includes(status.status)) break; }
    if (!status || status.status !== "COMPLETE") throw new Error(status?.error || (status?.status === "CANCELLED" ? "Experiment cancelled." : "Experiment did not complete."));
    state.experiment.report = status.result; state.experiment.annotations = []; state.experiment.selectedRange = null; renderExperimentReport(); $("#experiment-results").hidden = false; experimentStatus(`Experiment complete: ${status.result.correlated_ranges.length} changed region(s), ${status.result.pairing.paired_messages} paired message(s).`);
  } catch (error) { if (version === state.experiment.requestVersion) experimentStatus(error.name === "AbortError" ? "Experiment cancelled." : error.message, true); }
  finally { if (version === state.experiment.requestVersion) { state.experiment.controller = null; state.experiment.jobId = null; $("#experiment-run-button").disabled = false; $("#experiment-load-button").disabled = false; $("#experiment-cancel-button").hidden = true; $("#experiment-progress-label").textContent = "Idle"; } }
}
async function cancelExperiment() { const id = state.experiment.jobId; state.experiment.requestVersion += 1; state.experiment.controller?.abort(); if (id) { try { await fetch(`/api/jobs/${id}`, { method: "DELETE" }); } catch { /* polling will stop; the server owns cancellation */ } } state.experiment.jobId = null; $("#experiment-cancel-button").hidden = true; $("#experiment-run-button").disabled = false; $("#experiment-load-button").disabled = false; experimentStatus("Experiment cancellation requested."); }
function experimentMetric(value, label) { const metric = node("div", undefined, "metric"); metric.append(node("strong", value), node("span", label)); return metric; }
function renderExperimentReport() {
  const report = state.experiment.report; if (!report) return; const baseline = report.baseline || {}; const changed = report.changed || {}; const pairing = report.pairing || {};
  const summary = $("#experiment-summary"); summary.replaceChildren(experimentMetric(baseline.packet_count || 0, "baseline packets"), experimentMetric(changed.packet_count || 0, "changed packets"), experimentMetric(pairing.paired_messages || 0, "paired messages"), experimentMetric((pairing.unpaired_baseline_messages || 0) + (pairing.unpaired_changed_messages || 0), "unpaired messages"), experimentMetric(report.correlated_ranges?.length || 0, "changed regions"));
  $("#experiment-provenance").textContent = `${baseline.name || "baseline"} (${baseline.format || "unknown"}) · SHA-256 ${baseline.raw_sha256 || "unavailable"}  ↔  ${changed.name || "changed"} (${changed.format || "unknown"}) · SHA-256 ${changed.raw_sha256 || "unavailable"} · ${report.coordinate_system || "unknown"} coordinates`;
  renderExperimentDistributions(report.message_distributions || {}); renderExperimentRegions(report.correlated_ranges || []); renderExperimentSuggestions(report); renderExperimentAnnotations();
  if (report.correlated_ranges?.length) selectExperimentRange(0); else { $("#experiment-evidence").replaceChildren(node("p", "No consistently changing range was observed.", "muted")); $("#experiment-promote-button").disabled = true; renderExperimentHex(null); }
}
function renderExperimentDistributions(distributions) { const view = $("#experiment-distributions"); view.replaceChildren(); const row = node("div", undefined, "experiment-distribution"); ["baseline", "changed"].forEach((side) => { (distributions[side] || []).slice(0, 32).forEach((item) => row.append(node("span", `${side}: ${item.count} × ${item.length} byte message${item.length === 1 ? "" : "s"}${item.first_byte ? ` · first 0x${item.first_byte}` : ""}`))); }); if (row.childNodes.length) view.append(row); }
function renderExperimentRegions(ranges) { const view = $("#experiment-regions"); view.replaceChildren(); ranges.forEach((range, index) => { const button = node("button", undefined, "experiment-region"); button.type = "button"; button.dataset.rangeIndex = String(index); button.append(node("strong", `0x${Number(range.offset).toString(16)}–0x${(Number(range.offset) + Number(range.width)).toString(16)} · ${range.width} byte(s)`), node("span", `${range.changed_bytes}/${range.compared_bytes} compared bytes changed · ${Math.round(Number(range.change_rate || 0) * 100)}% change rate`), node("small", "Hypothesis only · select to inspect evidence")); button.addEventListener("click", () => selectExperimentRange(index)); view.append(button); }); if (!ranges.length) view.append(node("p", "No changed regions matched the bounded comparison.", "muted")); }
function selectedExperimentHypothesis() { const report = state.experiment.report; const range = state.experiment.selectedRange; return (report?.hypotheses || []).find((item) => Number(item.offset) === Number(range?.offset) && Number(item.width) === Number(range?.width)); }
function selectExperimentRange(index) {
  const ranges = state.experiment.report?.correlated_ranges || []; const range = ranges[index]; if (!range) return; state.experiment.selectedRange = range; document.querySelectorAll(".experiment-region").forEach((item) => item.classList.toggle("selected", item.dataset.rangeIndex === String(index)));
  const view = $("#experiment-evidence"); view.replaceChildren(); const hypothesis = selectedExperimentHypothesis(); view.append(node("strong", `Hypothesis: experimental correlation at offset 0x${Number(range.offset).toString(16)}`), node("p", `${range.changed_bytes} changed byte(s) across ${range.compared_bytes} comparable positions. This does not establish causation or a field meaning.`));
  (range.evidence || []).slice(0, 32).forEach((item) => { const row = node("div", undefined, "experiment-evidence-row"); const changed = node("span", `P${item.changed_packet_id}: ${item.changed_byte}`, "changed-byte"); row.append(node("span", `0x${Number(item.offset).toString(16)}`), node("span", `P${item.baseline_packet_id}: ${item.baseline_byte}`), changed); view.append(row); });
  if (hypothesis) { (hypothesis.evidence || []).forEach((item) => view.append(node("p", item.rationale || JSON.stringify(item), "muted"))); (hypothesis.contradictions || []).forEach((item) => view.append(node("p", `Contradiction: ${item.reason || JSON.stringify(item)}`, "muted"))); (hypothesis.caveats || []).forEach((item) => view.append(node("p", `Caveat: ${item}`, "muted"))); if (hypothesis.what_would_help?.length) { view.append(node("h3", "Supporting next observations")); hypothesis.what_would_help.forEach((item) => view.append(node("p", item, "muted"))); } }
  $("#experiment-promote-button").disabled = false; $("#experiment-annotation-start").value = range.offset; $("#experiment-annotation-width").value = range.width; renderExperimentHex(range);
}
function renderExperimentHex(range) {
  const baselineView = $("#experiment-hex-baseline"); const changedView = $("#experiment-hex-changed"); baselineView.replaceChildren(node("h3", "Baseline evidence")); changedView.replaceChildren(node("h3", "Changed evidence")); if (!range) return;
  (range.evidence || []).slice(0, 32).forEach((item) => { const left = node("div", undefined, "hex-line"); left.append(node("span", Number(item.offset).toString(16).padStart(8, "0"), "offset"), node("span", item.baseline_byte, "byte-hit")); baselineView.append(left); const right = node("div", undefined, "hex-line"); right.append(node("span", Number(item.offset).toString(16).padStart(8, "0"), "offset"), node("span", item.changed_byte, "byte-hit")); changedView.append(right); });
  if (!range.evidence?.length) { baselineView.append(node("p", "No bounded sample evidence.", "muted")); changedView.append(node("p", "No bounded sample evidence.", "muted")); }
}
function renderExperimentSuggestions(report) { const view = $("#experiment-suggestions"); view.replaceChildren(); (report.suggested_experiments || []).forEach((item) => view.append(node("p", item, "muted"))); const limitations = $("#experiment-limitations"); limitations.replaceChildren(node("h3", "Limitations")); (report.limitations || []).forEach((item) => limitations.append(node("p", item, "muted"))); }
function validExperimentAnnotation(item) { return item && typeof item.label === "string" && item.label.trim() && Number.isInteger(item.start) && item.start >= 0 && Number.isInteger(item.end) && item.end > item.start && item.end - item.start <= 16 * 1024 * 1024; }
function renderExperimentAnnotations() { const view = $("#experiment-annotations"); view.replaceChildren(); state.experiment.annotations.forEach((annotation, index) => { const item = node("li"); item.append(node("span", `${annotation.label} · 0x${annotation.start.toString(16)}–0x${annotation.end.toString(16)} · manual/confirmed`)); const remove = node("button", "Remove"); remove.type = "button"; remove.addEventListener("click", () => { state.experiment.annotations.splice(index, 1); renderExperimentAnnotations(); }); item.append(remove); view.append(item); }); }
function exportExperimentReport() {
  const report = state.experiment.report; if (!report) return; const project = { schema_version: 1, project_type: "packetscope-experiment", baseline: report.baseline, changed: report.changed, selection: report.selection || {}, report, annotations: state.experiment.annotations };
  const blob = new Blob([JSON.stringify(project, null, 2)], { type: "application/json" }); const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = "packetscope-experiment.json"; link.click(); URL.revokeObjectURL(link.href); experimentStatus("Experiment report exported without embedding raw captures.");
}
function validateExperimentProject(value) { if (!value || typeof value !== "object" || value.project_type !== "packetscope-experiment" || value.schema_version !== 1 || !value.report || typeof value.report !== "object") throw new Error("unsupported experiment project"); if (!Array.isArray(value.report.correlated_ranges) || value.report.correlated_ranges.length > 1000) throw new Error("experiment ranges are missing or too large"); if (!Array.isArray(value.annotations) || value.annotations.length > 1000 || value.annotations.some((item) => !validExperimentAnnotation(item))) throw new Error("experiment annotations are invalid"); }
function restoreExperimentProject(value) { validateExperimentProject(value); state.experiment.report = value.report; state.experiment.annotations = value.annotations.slice(); state.experiment.metadata = null; renderExperimentReport(); $("#experiment-results").hidden = false; experimentStatus("Restored experiment report for inspection. Select both source captures again before rerunning."); }
async function reconstructStreams() {
  if (!state.sourceFile) { setStatus("Load a capture before reconstructing TCP streams.", true); return; }
  const body = new FormData(); body.append("file", state.sourceFile, state.sourceFile.name); body.append("format", state.sourceFormat); $("#reconstruct-button").disabled = true; setStatus("Reconstructing bounded TCP streams…");
  try { const response = await fetch("/api/reconstruct", { method: "POST", body }); const report = await response.json(); if (!response.ok) throw new Error(report.error || "stream reconstruction failed"); renderStreamReport(report); setStatus(`Reconstructed ${report.stream_count} TCP stream direction(s); gaps and overlaps remain explicit.`); } catch (error) { setStatus(error.message, true); } finally { $("#reconstruct-button").disabled = false; }
}
function renderStreamReport(report) {
  const view = $("#stream-view"); view.hidden = false; view.replaceChildren(node("h3", `${report.stream_count} bounded TCP stream direction(s)`)); (report.limitations || []).forEach((item) => view.append(node("p", item, "muted"))); (report.streams || []).forEach((stream) => { const card = node("article", undefined, "stream-card"); card.append(node("strong", `${stream.flow_id} · ${stream.direction} · ${stream.complete ? "complete" : "incomplete"}`), node("p", `${stream.segments.length} segment(s) · ${stream.packet_to_stream.length} packet mapping(s) · ${stream.gaps.length} gap(s) · ${stream.overlaps.length} overlap(s)`, "muted")); if (stream.data) card.append(node("p", `Reconstructed data: ${stream.data.slice(0, 256)}${stream.data.length > 256 ? "…" : ""}`, "muted")); (stream.limitations || []).forEach((item) => card.append(node("p", item, "muted"))); view.append(card); }); }
const SCHEMA_HISTORY_LIMIT = 40;
function ensureEditorSchema() { if (!state.schema) { state.schema = { schema_version: 2, name: "Reviewed PacketScope protocol", coordinate_system: $("#payload-mode").value === "raw" ? "raw_packet" : "application_payload", fields: [] }; state.authoredSchema = cloneJson(state.schema); } return state.schema; }
function schemaSnapshot() { return { schema: cloneJson(state.schema), authoredSchema: cloneJson(state.authoredSchema) }; }
function updateSchemaHistoryButtons() { $("#schema-editor-undo").disabled = !state.schemaUndo.length; $("#schema-editor-redo").disabled = !state.schemaRedo.length; }
function recordSchemaUndo(snapshot = schemaSnapshot()) { state.schemaUndo.push(cloneJson(snapshot)); if (state.schemaUndo.length > SCHEMA_HISTORY_LIMIT) state.schemaUndo.shift(); state.schemaRedo = []; updateSchemaHistoryButtons(); }
function refreshSchemaAfterHistory() { state.schemaValues = state.result && state.schema ? applySchema(state.schema) : []; state.editingSchemaField = null; state.schemaEditorSelection = null; clearSchemaEditor(); renderSchemaEditor(); renderFields(); updateSchemaHistoryButtons(); }
function restoreSchemaHistory(redo) {
  const source = redo ? state.schemaRedo : state.schemaUndo; const target = redo ? state.schemaUndo : state.schemaRedo;
  if (!source.length) { updateSchemaHistoryButtons(); return; }
  target.push(schemaSnapshot());
  const snapshot = source.pop(); state.schema = cloneJson(snapshot.schema); state.authoredSchema = cloneJson(snapshot.authoredSchema);
  refreshSchemaAfterHistory(); setStatus(redo ? "Schema change redone." : "Schema change undone.");
}
function commitSchemaChange(authored, before = schemaSnapshot()) {
  const candidate = validateSchema(authored);
  recordSchemaUndo(before); state.schema = candidate; state.authoredSchema = cloneJson(authored);
  state.schemaValues = state.result ? applySchema(candidate) : []; renderSchemaEditor(); renderFields(); updateSchemaHistoryButtons();
}
function openSchemaEditor() {
  const editor = $("#schema-editor"); editor.hidden = false; $("#schema-editor-toggle").textContent = "Close schema editor";
  document.querySelectorAll(".tab").forEach((item) => item.classList.toggle("active", item.dataset.tab === "fields"));
  document.querySelectorAll(".tab-panel").forEach((panel) => panel.classList.toggle("active", panel.dataset.panel === "fields"));
  renderSchemaEditor();
}
function renderSchemaSelectionSource() {
  const view = $("#schema-editor-selection-source"); const selection = state.schemaEditorSelection;
  if (!view) return;
  view.textContent = selection ? `HEX selection source: Packet ${selection.packetIndex} · ${selection.coordinateSystem} · offset 0x${selection.offset.toString(16)} · ${selection.width} byte(s).` : "No HEX selection is attached to this field.";
}
function createSchemaFieldFromHexSelection() {
  const selection = state.hexSelection; const packet = packets().find((item) => Number(item.index) === Number(selection?.packetIndex));
  if (!selection || !packet) { hexSelectionStatus("Select bytes in a packet before creating a field.", true); return; }
  const coordinateMode = selection.coordinateSystem === "raw_packet" ? "raw" : "application";
  if ($("#payload-mode").value !== coordinateMode) $("#payload-mode").value = coordinateMode;
  $("#packet-select").value = String(selection.packetIndex); state.packetWindowStart = Math.max(0, Math.floor(selection.offset / 16 - 128) * 16);
  state.schemaEditorSelection = cloneJson(selection); state.editingSchemaField = null; openSchemaEditor(); clearSchemaEditor(); state.schemaEditorSelection = cloneJson(selection);
  const identity = `selected_bytes_${stableClientHash(`${selection.packetIndex}:${selection.coordinateSystem}:${selection.offset}:${selection.width}`)}`;
  $("#schema-editor-id").value = identity; $("#schema-editor-name").value = "Selected bytes"; $("#schema-editor-description").value = `Bytes selected from Packet ${selection.packetIndex} for review.`; $("#schema-editor-type").value = "bytes"; $("#schema-editor-offset").value = selection.offset; $("#schema-editor-width").value = selection.width; $("#schema-editor-offset-expression").value = ""; $("#schema-editor-length-expression").value = ""; renderSchemaSelectionSource(); $("#schema-editor-name").focus(); setStatus(`HEX range copied into the schema editor from packet ${selection.packetIndex}.`);
}
function expressionText(value) { return value === undefined || value === null || typeof value === "boolean" || typeof value === "number" ? String(value ?? "") : JSON.stringify(value); }
function renderSchemaEditor() { const view = $("#schema-editor-fields"); view.replaceChildren(); const schema = ensureEditorSchema(); schema.fields.slice(0, 1000).forEach((field, index) => { const row = node("div", undefined, "field-row schema-editor-row"); const arrayText = field.array ? ` · array count ${expressionText(field.array.count)}` : ""; const nestedText = field.fields ? ` · ${field.fields.length} nested` : ""; const edit = node("button", "Edit", "secondary"); edit.type = "button"; edit.addEventListener("click", () => { state.editingSchemaField = index; state.schemaEditorSelection = null; populateSchemaEditor(field); renderSchemaSelectionSource(); $("#schema-editor-name").focus(); }); const remove = node("button", "Remove", "secondary"); remove.type = "button"; remove.addEventListener("click", () => { const before = schemaSnapshot(); const authoredBase = state.authoredSchema?.schema_version === 2 ? cloneJson(state.authoredSchema) : cloneJson(schema); authoredBase.fields = Array.isArray(authoredBase.fields) ? authoredBase.fields.filter((item) => item.id !== field.id) : []; try { commitSchemaChange(authoredBase, before); state.editingSchemaField = null; clearSchemaEditor(); setStatus(`Schema field ${field.id} removed.`); } catch (error) { setStatus(`Schema field could not be removed: ${error.message}`, true); } }); const actions = node("span", undefined, "annotation-actions"); actions.append(edit, remove); row.append(node("strong", `${field.name} · ${field.id}`), node("span", `${field.type || "bytes"} · offset ${expressionText(field.offset)} · length ${expressionText(field.length)} · ${field.endian || "unknown"}${arrayText}${nestedText}`), node("span", `${field.description || "No description."}${Object.keys(field.constraints || {}).length ? ` · ${Object.keys(field.constraints).length} constraint(s)` : ""}`), actions); view.append(row); }); if (!schema.fields.length) view.append(node("p", "No reviewed fields yet.", "muted")); updateSchemaHistoryButtons(); renderSchemaSelectionSource(); }
function parseEditorExpression(value, label, fallback) { const text = String(value || "").trim(); if (!text) return fallback; try { return JSON.parse(text); } catch (error) { throw new Error(`${label} must be valid JSON`); } }
function parseConstraintJson(id, label) { const text = $(id).value.trim(); if (!text) return undefined; try { return JSON.parse(text); } catch (error) { throw new Error(`${label} must be valid JSON`); } }
function parseConstraintScalar(id, label, integer = false) { const text = $(id).value.trim(); if (!text) return undefined; if (integer && /^-?\d+$/.test(text)) return text; try { const value = JSON.parse(text); if (integer && !isIntegerLike(value)) throw new Error(`${label} must be an integer`); return value; } catch (error) { if (error.message === `${label} must be an integer`) throw error; throw new Error(`${label} must be valid JSON (or an integer)`); } }
function isIntegerLike(value) { return (typeof value === "number" && Number.isSafeInteger(value)) || (typeof value === "string" && /^-?\d+$/.test(value.trim())); }
function parseBitValue(id, label) { const value = parseConstraintJson(id, label); if (value === undefined) return undefined; const valid = isIntegerLike(value) ? BigInt(value) >= 0n : Array.isArray(value) && value.every((item) => isIntegerLike(item) && BigInt(item) >= 0n && BigInt(item) < 128n); if (!valid) throw new Error(`${label} must be a non-negative integer or a JSON list of bit numbers`); return value; }
function parseFlagSet(id, label) { const value = parseConstraintJson(id, label); if (value === undefined) return undefined; if (!Array.isArray(value)) throw new Error(`${label} must be a JSON array`); if (value.length > 10000) throw new Error(`${label} has too many values`); if (!value.every((item) => typeof item === "string" || isIntegerLike(item))) throw new Error(`${label} must contain flag names or integer masks`); return value; }
function parseStructuredConstraints(type) {
  const constraints = {};
  const advancedText = $("#schema-editor-constraints-json").value.trim();
  if (advancedText) { const advanced = parseConstraintJson("#schema-editor-constraints-json", "Advanced constraints"); if (!advanced || typeof advanced !== "object" || Array.isArray(advanced)) throw new Error("Advanced constraints must be a JSON object"); Object.assign(constraints, advanced); }
  const minimum = parseConstraintScalar("#schema-editor-minimum", "Minimum", true); const maximum = parseConstraintScalar("#schema-editor-maximum", "Maximum", true); const exact = parseConstraintScalar("#schema-editor-exact", "Exact");
  if (minimum !== undefined) constraints.minimum = minimum; if (maximum !== undefined) constraints.maximum = maximum; if (exact !== undefined) constraints.exact = exact;
  const minimumNumber = minimum === undefined ? null : BigInt(minimum); const maximumNumber = maximum === undefined ? null : BigInt(maximum); if (minimumNumber !== null && maximumNumber !== null && minimumNumber > maximumNumber) throw new Error("Minimum cannot be greater than maximum");
  const enumValue = parseConstraintJson("#schema-editor-enum", "Enum values"); if (enumValue !== undefined) { if (!Array.isArray(enumValue) && (!enumValue || typeof enumValue !== "object")) throw new Error("Enum values must be a JSON array or object"); constraints.enum = { ...(Array.isArray(enumValue) ? { values: enumValue } : enumValue), policy: $("#schema-editor-enum-policy").value }; }
  const allowed = parseConstraintJson("#schema-editor-allowed", "Allowed values"); const forbidden = parseConstraintJson("#schema-editor-forbidden", "Forbidden values"); if (allowed !== undefined) { if (!Array.isArray(allowed)) throw new Error("Allowed values must be a JSON array"); constraints.allowed = allowed; } if (forbidden !== undefined) { if (!Array.isArray(forbidden)) throw new Error("Forbidden values must be a JSON array"); constraints.forbidden = forbidden; }
  const mask = parseBitValue("#schema-editor-mask", "Mask"); const reserved = parseBitValue("#schema-editor-reserved", "Reserved bits"); if (mask !== undefined) constraints.mask = mask; if (reserved !== undefined) constraints.reserved = reserved;
  const requiredFlags = parseFlagSet("#schema-editor-required-flags", "Required flags"); const forbiddenFlags = parseFlagSet("#schema-editor-forbidden-flags", "Forbidden flags"); if (requiredFlags !== undefined) constraints.required_flags = requiredFlags; if (forbiddenFlags !== undefined) constraints.forbidden_flags = forbiddenFlags;
  const target = $("#schema-editor-length-target").value.trim(); if (target) constraints.length_relationship = { target, mode: $("#schema-editor-length-mode").value }; else if ($("#schema-editor-length-mode").value !== "length" && $("#schema-editor-length-mode").value) throw new Error("Length relationship target is required when a non-default mode is selected");
  const integerType = new Set(["u8", "uint8", "byte", "u16", "uint16", "u32", "uint32", "u64", "uint64", "u128", "uint128", "i8", "int8", "i16", "int16", "i32", "int32", "i64", "int64", "i128", "int128", "uint", "unsigned", "unsigned_integer", "int", "signed", "signed_integer", "integer"]); if ((mask !== undefined || reserved !== undefined || requiredFlags !== undefined || forbiddenFlags !== undefined) && !integerType.has(String(type).toLowerCase())) throw new Error("Mask, reserved bits, and flag constraints require an integer field");
  return constraints;
}
function valueForEditor(value) { return value === undefined || value === null ? "" : typeof value === "string" ? value : JSON.stringify(value); }
function populateSchemaEditorOriginal(field) { const constraints = field.constraints || {}; $("#schema-editor-id").value = field.id || ""; $("#schema-editor-name").value = field.name || "field"; $("#schema-editor-description").value = field.description || ""; $("#schema-editor-type").value = field.type || "bytes"; $("#schema-editor-offset").value = Number.isInteger(field.offset) ? field.offset : 0; $("#schema-editor-offset-expression").value = field.offset && typeof field.offset === "object" ? JSON.stringify(field.offset) : ""; $("#schema-editor-width").value = Number.isInteger(field.length) ? field.length : 1; $("#schema-editor-length-expression").value = field.length && typeof field.length === "object" ? JSON.stringify(field.length) : ""; $("#schema-editor-condition").value = field.presence === true || field.presence === undefined ? "" : JSON.stringify(field.presence); $("#schema-editor-endian").value = field.endian || "unknown"; $("#schema-editor-array").checked = Boolean(field.array); $("#schema-editor-array-count").value = field.array ? valueForEditor(field.array.count) : ""; $("#schema-editor-array-type").value = field.array?.element?.type || "uint8"; $("#schema-editor-array-length").value = field.array?.element?.length || 1; $("#schema-editor-nested-json").value = field.fields ? JSON.stringify(field.fields) : ""; $("#schema-editor-minimum").value = valueForEditor(constraints.minimum); $("#schema-editor-maximum").value = valueForEditor(constraints.maximum); $("#schema-editor-exact").value = valueForEditor(constraints.exact); const enumValue = constraints.enum; $("#schema-editor-enum").value = valueForEditor(Array.isArray(enumValue) ? enumValue : enumValue?.values ?? enumValue?.allowed); $("#schema-editor-enum-policy").value = enumValue?.policy || constraints.enum_policy || "strict"; $("#schema-editor-allowed").value = valueForEditor(constraints.allowed); $("#schema-editor-forbidden").value = valueForEditor(constraints.forbidden); $("#schema-editor-mask").value = valueForEditor(constraints.mask); $("#schema-editor-reserved").value = valueForEditor(constraints.reserved); $("#schema-editor-required-flags").value = valueForEditor(constraints.required_flags); $("#schema-editor-forbidden-flags").value = valueForEditor(constraints.forbidden_flags); const relationship = constraints.length_relationship || constraints.length_relation; $("#schema-editor-length-target").value = relationship?.target || ""; $("#schema-editor-length-mode").value = relationship?.mode || "length"; const advanced = { ...constraints }; ["minimum", "maximum", "exact", "enum", "enum_policy", "allowed", "forbidden", "mask", "reserved", "required_flags", "forbidden_flags", "length_relationship", "length_relation"].forEach((key) => delete advanced[key]); $("#schema-editor-constraints-json").value = Object.keys(advanced).length ? JSON.stringify(advanced) : ""; }
function clearSchemaEditorOriginal() { ["#schema-editor-id", "#schema-editor-description", "#schema-editor-offset-expression", "#schema-editor-length-expression", "#schema-editor-condition", "#schema-editor-array-count", "#schema-editor-nested-json", "#schema-editor-minimum", "#schema-editor-maximum", "#schema-editor-exact", "#schema-editor-enum", "#schema-editor-allowed", "#schema-editor-forbidden", "#schema-editor-mask", "#schema-editor-reserved", "#schema-editor-required-flags", "#schema-editor-forbidden-flags", "#schema-editor-length-target", "#schema-editor-constraints-json"].forEach((id) => { $(id).value = ""; }); $("#schema-editor-name").value = "field"; $("#schema-editor-offset").value = "0"; $("#schema-editor-width").value = "1"; $("#schema-editor-condition").value = ""; $("#schema-editor-array").checked = false; $("#schema-editor-array-count").value = ""; $("#schema-editor-array-length").value = "1"; $("#schema-editor-endian").value = "unknown"; $("#schema-editor-enum-policy").value = "strict"; $("#schema-editor-length-mode").value = "length"; $("#schema-editor-array-type").value = "uint8"; state.schemaEditorSelection = null; renderSchemaSelectionSource(); }
function schemaFieldFromEditorOriginal() { const name = $("#schema-editor-name").value.trim(); const type = $("#schema-editor-type").value; if (!name) throw new Error("Field name is required"); const offset = parseEditorExpression($("#schema-editor-offset-expression").value, "Offset", Number($("#schema-editor-offset").value)); const length = parseEditorExpression($("#schema-editor-length-expression").value, "Length", Number($("#schema-editor-width").value)); const selection = state.schemaEditorSelection; const coordinate = selection?.coordinateSystem || currentCoordinateSystem(); const integerTypes = new Set(["u8", "uint8", "byte", "u16", "uint16", "u32", "uint32", "u64", "uint64", "u128", "uint128", "i8", "int8", "i16", "int16", "i32", "int32", "i64", "int64", "i128", "int128", "uint", "unsigned", "unsigned_integer", "int", "signed", "signed_integer", "integer"]); const endian = $("#schema-editor-endian").value === "unknown" && integerTypes.has(String(type).toLowerCase()) ? "big" : $("#schema-editor-endian").value; const metadata = { origin: "manual", review_status: "confirmed" }; if (selection) Object.assign(metadata, { source_packet_index: selection.packetIndex, source_coordinate_system: selection.coordinateSystem, source_offset: selection.offset, source_width: selection.width }); const field = { id: $("#schema-editor-id").value.trim() || `${name.replace(/[^a-zA-Z0-9]+/g, "_").toLowerCase() || "field"}_${stableClientHash(`${name}:${type}:${JSON.stringify(offset)}:${JSON.stringify(length)}:${coordinate}`)}`, name, description: $("#schema-editor-description").value.trim(), type, offset, length, endian, coordinate_system: coordinate, presence: parseEditorExpression($("#schema-editor-condition").value, "Condition", true), constraints: parseStructuredConstraints(type), metadata }; const nestedText = $("#schema-editor-nested-json").value.trim(); if (nestedText) { const nested = JSON.parse(nestedText); if (!Array.isArray(nested)) throw new Error("Nested fields JSON must be an array"); field.fields = nested; } if ($("#schema-editor-array").checked) { const elementLength = Number($("#schema-editor-array-length").value); if (!Number.isInteger(elementLength) || elementLength < 1) throw new Error("Array element length must be a positive integer"); field.array = { count: parseEditorExpression($("#schema-editor-array-count").value, "Array count", 0), element: { type: $("#schema-editor-array-type").value, offset: 0, length: elementLength, endian } }; } return field; }
function saveEditorField() { const schema = ensureEditorSchema(); const index = state.editingSchemaField; const previous = index === null || index === undefined ? null : schema.fields[index]; const before = schemaSnapshot(); const field = schemaFieldFromEditor(); if (previous) field.id = previous.id; const authoredBase = state.authoredSchema?.schema_version === 2 ? cloneJson(state.authoredSchema) : cloneJson(schema); authoredBase.fields = Array.isArray(authoredBase.fields) ? authoredBase.fields.slice() : []; if (index === null || index === undefined) authoredBase.fields.push(cloneJson(field)); else authoredBase.fields[index] = cloneJson(field); commitSchemaChange(authoredBase, before); state.editingSchemaField = null; clearSchemaEditor(); }
function applyReviewedSchema() { try { const schema = validateSchema(ensureEditorSchema()); state.schema = schema; state.authoredSchema = authoredSchemaForValidation() || cloneJson(schema); state.schemaValues = applySchema(schema); renderSchemaEditor(); renderFields(); const needsServer = (Array.isArray(schema.relationships) && schema.relationships.length) || (schema.definitions && Object.keys(schema.definitions).length); setStatus(needsServer ? `Applied reviewed schema to ${state.schemaValues.length} packet(s). Browser preview is bounded; run Schema Validation for authoritative reusable-definition and relationship diagnostics.` : `Applied reviewed schema to ${state.schemaValues.length} packet(s).`); } catch (error) { setStatus(`Schema is not valid: ${error.message}`, true); } }
function diagnosticText(item) { if (!item || typeof item !== "object") return String(item ?? "unknown diagnostic"); const code = item.code ? `${item.code}: ` : ""; return `${code}${item.message || item.reason || "diagnostic"}`; }
function validationSummary(report) { const summary = report?.summary || {}; return { packetCount: Number(summary.packet_count || report?.packets?.length || 0), decoded: Number(summary.decoded_packets || 0), incomplete: Number(summary.incomplete_packets ?? summary.missing_fields ?? 0), violated: Number(summary.invalid_packets ?? summary.constraint_violations ?? 0), unsupported: Number(summary.unsupported_packets ?? summary.unsupported_fields ?? 0), schemaDiagnostics: Number(summary.schema_diagnostics || report?.schema_diagnostics?.length || 0), applicationStatus: summary.application_status || report?.status || "RESOLVED" }; }
function renderValidationDiagnostics(report, view) { const summary = validationSummary(report); view.hidden = false; view.replaceChildren(); const summaryBox = node("div", undefined, "schema-validation-summary"); summaryBox.id = view.id === "schema-validation" ? "schema-validation-summary-loaded" : "schema-validation-summary"; summaryBox.append(node("strong", `${summary.decoded}/${summary.packetCount} packet(s) satisfy the reviewed schema`), node("span", `${summary.incomplete} incomplete · ${summary.violated} violated · ${summary.unsupported} unsupported · ${summary.schemaDiagnostics} schema diagnostic(s) · scope: whole capture`)); view.append(summaryBox); const schemaDiagnostics = (report?.schema_diagnostics || []).slice(0, 32); const schemaBox = node("div", undefined, "schema-validation-list"); schemaBox.id = view.id === "schema-validation" ? "schema-validation-schema-diagnostics-loaded" : "schema-validation-schema-diagnostics"; schemaBox.append(node("h4", `Schema diagnostics (${schemaDiagnostics.length}${(report?.schema_diagnostics || []).length > schemaDiagnostics.length ? "+" : ""})`)); if (schemaDiagnostics.length) schemaDiagnostics.forEach((item) => schemaBox.append(node("div", diagnosticText(item), "schema-validation-diagnostic"))); else schemaBox.append(node("p", "No schema diagnostics.", "muted")); view.append(schemaBox); const packetList = node("div", undefined, "schema-validation-list"); packetList.id = view.id === "schema-validation" ? "schema-validation-packet-diagnostics-loaded" : "schema-validation-packet-diagnostics"; packetList.append(node("h4", `Packet diagnostics (${Math.min((report?.packets || []).length, 32)} shown)`)); (report?.packets || []).slice(0, 32).forEach((packet) => { const packetBox = node("article", undefined, "schema-validation-packet"); packetBox.append(node("strong", `Packet ${packet.packet_id ?? packet.packetId ?? "?"} · ${String(packet.status || "unknown").toUpperCase()}`)); (packet.diagnostics || []).slice(0, 8).forEach((item) => packetBox.append(node("div", diagnosticText(item), "schema-validation-diagnostic"))); const missing = (packet.missing_fields || []).slice(0, 8); missing.forEach((field) => packetBox.append(node("div", `missing field: ${field}`, "schema-validation-diagnostic"))); const violations = (packet.constraint_violations || []).slice(0, 8); violations.forEach((item) => packetBox.append(node("div", `${item.field || "field"}: ${item.reason || diagnosticText(item)}`, "schema-validation-diagnostic"))); (packet.unsupported_fields || []).slice(0, 8).forEach((field) => packetBox.append(node("div", `unsupported field: ${field}`, "schema-validation-diagnostic"))); (packet.fields || []).slice(0, 32).forEach((field) => { const fieldDiagnostics = (field.diagnostics || []).slice(0, 8); if (!fieldDiagnostics.length && ["RESOLVED", "ok"].includes(field.status)) return; const fieldBox = node("div", undefined, "schema-validation-field"); fieldBox.append(node("strong", `${field.name || field.id || field.path || "field"} · ${String(field.status || "unknown").toUpperCase()}`)); fieldDiagnostics.forEach((item) => fieldBox.append(node("div", diagnosticText(item), "schema-validation-diagnostic"))); if (!fieldDiagnostics.length) fieldBox.append(node("div", "No field diagnostic details returned.", "muted")); packetBox.append(fieldBox); }); if ((packet.relationships || packet.checksum_diagnostics || []).length) (packet.relationships || packet.checksum_diagnostics || []).slice(0, 8).forEach((item) => packetBox.append(node("div", `relationship ${item.id || item.algorithm || "checksum"}: ${item.status || "unknown"} · ${diagnosticText(item.diagnostics?.[0])}`, "schema-validation-diagnostic"))); packetList.append(packetBox); }); if (!(report?.packets || []).length) packetList.append(node("p", "No packet diagnostics returned.", "muted")); view.append(packetList); }
async function validateCurrentSchema() { if (!state.sourceFile) { setStatus("Load a capture before validating a schema.", true); return; } try { const schema = validateSchema(ensureEditorSchema()); const authored = authoredSchemaForValidation() || schema; const body = new FormData(); body.append("file", state.sourceFile, state.sourceFile.name); body.append("format", state.sourceFormat); body.append("schema", JSON.stringify(authored)); $("#schema-editor-validate").disabled = true; const response = await fetch("/api/schema/validate", { method: "POST", body }); const report = await response.json(); if (!response.ok) throw new Error(report.error || "schema validation failed"); renderValidationDiagnostics(report, $("#schema-validation")); setStatus("Schema validation complete."); } catch (error) { setStatus(error.message, true); } finally { $("#schema-editor-validate").disabled = false; } }
async function validateIndependentCapture() { const file = $("#schema-validation-file").files[0]; if (!file) { $("#schema-validation-status").textContent = "Choose an independent capture first."; $("#schema-validation-status").classList.add("error"); return; } try { const schema = validateSchema(ensureEditorSchema()); const authored = authoredSchemaForValidation() || schema; const body = new FormData(); body.append("file", file, file.name); body.append("format", $("#schema-validation-format").value); body.append("schema", JSON.stringify(authored)); $("#schema-validation-run").disabled = true; $("#schema-validation-status").textContent = "Validating the whole independent capture…"; $("#schema-validation-status").classList.remove("error"); const response = await fetch("/api/schema/validate", { method: "POST", body }); const report = await response.json(); if (!response.ok) throw new Error(report.error || "schema validation failed"); renderValidationDiagnostics(report, $("#independent-schema-validation-report")); $("#schema-validation-status").textContent = `Validation complete for ${file.name}.`; } catch (error) { $("#schema-validation-status").textContent = error.message; $("#schema-validation-status").classList.add("error"); } finally { $("#schema-validation-run").disabled = false; } }
async function exportReviewedSchema(format) { try { const schema = validateSchema(ensureEditorSchema()); const response = await fetch(`/api/schema/export/${format}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ schema: schemaForInterop(schema) }) }); const result = await response.json(); if (!response.ok) throw new Error(result.error || "schema export failed"); const extension = format === "kaitai" ? "ksy" : "lua"; const blob = new Blob([result.content], { type: "text/plain" }); const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = `packetscope-protocol.${extension}`; link.click(); URL.revokeObjectURL(link.href); setStatus(`${format === "kaitai" ? "Kaitai" : "Wireshark Lua"} schema exported${result.warnings?.length ? ` with ${result.warnings.length} warning(s)` : ""}.`); } catch (error) { setStatus(error.message, true); } }
function schemaForInterop(schema) { return { schema_version: 1, name: schema.name, coordinate_system: schema.coordinate_system, fields: (schema.fields || []).filter((field) => Number.isInteger(field.offset) && Number.isInteger(field.length) && field.length > 0).map((field) => ({ name: field.name, type: String(field.type || "custom").toUpperCase(), offset: field.offset, width: field.length, endian: field.endian || "unknown", coordinate_system: field.coordinate_system || schema.coordinate_system, constraints: field.constraints || {}, origin: field.metadata?.origin || "manual", review_status: field.metadata?.review_status || "confirmed" })) }; }
function initializeExperiments() {
  $("#experiments-toggle").addEventListener("click", () => { const workspace = $("#experiments-workspace"); const open = workspace.hidden; workspace.hidden = !open; $("#experiments-toggle").setAttribute("aria-expanded", String(open)); $("#experiments-toggle").textContent = open ? "Close Experiments" : "Open Experiments"; });
  ["baseline", "changed"].forEach((side) => $(`#experiment-${side}-file`).addEventListener("change", (event) => { state.experiment[side] = event.target.files[0] || null; updateExperimentFileLabel(side, state.experiment[side]); state.experiment.metadata = null; state.experiment.report = null; $("#experiment-results").hidden = true; }));
  $("#experiment-load-button").addEventListener("click", prepareExperimentCaptures); $("#experiment-form").addEventListener("submit", (event) => { event.preventDefault(); runExperiment(); }); $("#experiment-cancel-button").addEventListener("click", cancelExperiment); $("#experiment-export-button").addEventListener("click", exportExperimentReport);
  $("#experiment-restore-file").addEventListener("change", async (event) => { const file = event.target.files[0]; if (!file || file.size > 8 * 1024 * 1024) { experimentStatus("Saved experiment report is too large.", true); return; } try { restoreExperimentProject(JSON.parse(await file.text())); } catch (error) { experimentStatus(`Saved experiment report is not valid: ${error.message}`, true); } });
  $("#experiment-promote-button").addEventListener("click", () => { const range = state.experiment.selectedRange; if (!range) return; $("#experiment-annotation-label").value = "candidate controlled-change range"; $("#experiment-annotation-start").value = range.offset; $("#experiment-annotation-width").value = range.width; $("#experiment-annotation-label").focus(); });
  $("#experiment-annotation-form").addEventListener("submit", (event) => { event.preventDefault(); const start = Number($("#experiment-annotation-start").value); const width = Number($("#experiment-annotation-width").value); const label = $("#experiment-annotation-label").value.trim(); if (!label || !Number.isInteger(start) || start < 0 || !Number.isInteger(width) || width < 1) { experimentStatus("Annotation label, offset, and width must be valid.", true); return; } state.experiment.annotations.push({ label, start, end: start + width, coordinate_system: state.experiment.report?.coordinate_system || "application_payload", source: "manual", status: "confirmed" }); renderExperimentAnnotations(); experimentStatus("Manual experiment annotation saved; export the report to persist it."); });
  $("#reconstruct-button").addEventListener("click", reconstructStreams);
  $("#schema-editor-toggle").addEventListener("click", () => { const editor = $("#schema-editor"); if (editor.hidden) openSchemaEditor(); else { editor.hidden = true; $("#schema-editor-toggle").textContent = "Open schema editor"; } });
  $("#schema-editor-undo").addEventListener("click", () => restoreSchemaHistory(false)); $("#schema-editor-redo").addEventListener("click", () => restoreSchemaHistory(true));
  const schemaType = $("#schema-editor-type"); if (![...schemaType.options].some((option) => option.value === "custom")) schemaType.append(node("option", "Custom bytes")); schemaType.value = schemaType.value || "bytes";
  $("#schema-editor-form").addEventListener("submit", (event) => { event.preventDefault(); try { const editing = state.editingSchemaField !== null && state.editingSchemaField !== undefined; saveEditorField(); setStatus(editing ? "Schema field updated." : "Schema field saved."); } catch (error) { setStatus(`Schema field is not valid: ${error.message}`, true); } });
  $("#schema-validation-file").addEventListener("change", (event) => { const file = event.target.files[0]; $("#schema-validation-file-name").textContent = file ? `${file.name} · ${file.size.toLocaleString()} bytes` : "Nothing loaded"; $("#schema-validation-status").textContent = file ? "Ready to validate the whole capture." : "Choose a capture to validate against the reviewed schema."; $("#schema-validation-status").classList.remove("error"); });
  $("#schema-validation-form").addEventListener("submit", (event) => { event.preventDefault(); validateIndependentCapture(); });
  $("#schema-editor-apply").addEventListener("click", applyReviewedSchema); $("#schema-editor-validate").addEventListener("click", validateCurrentSchema);
  const schemaExportRow = $("#schema-editor-apply").parentElement; [["kaitai", "Export Kaitai .ksy"], ["wireshark", "Export Wireshark Lua"]].forEach(([format, label]) => { const button = node("button", label, "secondary"); button.type = "button"; button.addEventListener("click", () => exportReviewedSchema(format)); schemaExportRow.append(button); });
}
initializeExperiments();
initializeSchemaWorkbench();

/* Schema Workbench -------------------------------------------------------
 *
 * The original editor deliberately kept nested fields behind a JSON escape
 * hatch.  The workbench below is a small, dependency-free tree editor over
 * the same declarative Schema V2 document.  It never evaluates expressions
 * or packet bytes: edits are validated by PacketScopeSchema before they are
 * committed, and the server remains authoritative for reusable definitions,
 * relationships, and other unsupported browser previews.
 */
function schemaEditorLocator(kind = "root", definition = "", segments = []) {
  return { kind, definition: definition || "", segments: (segments || []).map((segment) => ({ index: Number(segment.index), array: Boolean(segment.array) })) };
}
function schemaEditorBaseFields(schema, locator) {
  if (locator?.kind === "definition") return schema.definitions?.[locator.definition]?.fields || [];
  return schema.fields || [];
}
function schemaEditorFieldAt(schema, locator) {
  if (!locator) return null;
  let fields = schemaEditorBaseFields(schema, locator);
  let field = null;
  for (const segment of locator.segments || []) {
    field = fields?.[segment.index];
    if (!field) return null;
    if (segment.array) field = field.array?.element || null;
    if (!field) return null;
    fields = field.fields || [];
  }
  return field;
}
function schemaEditorParentFields(schema, locator) {
  const segments = locator?.segments || [];
  if (!segments.length) return schemaEditorBaseFields(schema, locator);
  if (segments.length === 1) return schemaEditorBaseFields(schema, locator);
  const parent = schemaEditorFieldAt(schema, schemaEditorLocator(locator.kind, locator.definition, segments.slice(0, -1)));
  const last = segments[segments.length - 1];
  if (last.array) return parent?.array ? [parent.array.element] : [];
  return parent?.fields || [];
}
function schemaEditorFieldPath(locator) { return (locator?.segments || []).map((segment) => segment.array ? `[${segment.index}]` : String(segment.index)).join("."); }
function schemaEditorLocatorLabel(locator) {
  if (!locator) return "root";
  const scope = locator.kind === "definition" ? `definition ${locator.definition}` : "root";
  return locator.segments?.length ? `${scope} / ${schemaEditorFieldPath(locator)}` : scope;
}
function schemaEditorSameLocator(left, right) { return JSON.stringify(left || null) === JSON.stringify(right || null); }
function schemaEditorScopeLocator() {
  const scope = state.schemaEditorScope || schemaEditorLocator();
  return schemaEditorLocator(scope.kind, scope.definition, scope.segments);
}
function schemaEditorFieldsInDocument(schema) {
  const result = [];
  const visit = (fields, scope, prefix = []) => (fields || []).forEach((field, index) => {
    const locator = schemaEditorLocator(scope.kind, scope.definition, [...prefix, { index }]);
    result.push({ field, locator });
    visit(field.fields, scope, [...prefix, { index }]);
    if (field.array?.element) {
      const arrayLocator = schemaEditorLocator(scope.kind, scope.definition, [...prefix, { index, array: true }]);
      result.push({ field: field.array.element, locator: arrayLocator, arrayElement: true });
      visit(field.array.element.fields, scope, [...prefix, { index, array: true }]);
    }
  });
  visit(schema.fields, schemaEditorLocator("root"), []);
  Object.entries(schema.definitions || {}).forEach(([name, definition]) => visit(definition.fields, schemaEditorLocator("definition", name), []));
  return result;
}
function schemaEditorReferenceValues(value, refs = []) {
  if (Array.isArray(value)) value.forEach((item) => schemaEditorReferenceValues(item, refs));
  else if (value && typeof value === "object") Object.entries(value).forEach(([key, item]) => {
    if (["field", "ref", "field_ref", "field_id", "target", "target_field", "target_field_id", "source", "source_field_id"].includes(key) && typeof item === "string") refs.push(item);
    else schemaEditorReferenceValues(item, refs);
  });
  return refs;
}
function schemaEditorReferenceDiagnostics(schema) {
  const entries = schemaEditorFieldsInDocument(schema);
  const known = new Set(entries.flatMap(({ field }) => [field.id, field.name]).filter(Boolean));
  const diagnostics = [];
  entries.forEach(({ field, locator }) => schemaEditorReferenceValues(field).forEach((reference) => {
    if (!known.has(reference) && !Object.keys(schema.definitions || {}).includes(reference)) diagnostics.push({ kind: "missing", locator, reference, field });
  }));
  const graph = new Map();
  entries.forEach(({ field }) => graph.set(field.id, schemaEditorReferenceValues(field).filter((ref) => known.has(ref))));
  const visiting = new Set(); const visited = new Set();
  function visit(id, stack = []) {
    if (visiting.has(id)) { diagnostics.push({ kind: "cycle", fieldId: id, path: [...stack, id] }); return; }
    if (visited.has(id)) return;
    visiting.add(id); (graph.get(id) || []).forEach((ref) => visit(ref, [...stack, id])); visiting.delete(id); visited.add(id);
  }
  graph.forEach((_, id) => visit(id));
  return diagnostics;
}
function schemaEditorTextField(label, id, value = "", type = "text") {
  const wrapper = node("label", undefined, "schema-workbench-control"); wrapper.append(node("span", label)); const input = node("input"); input.id = id; input.type = type; input.value = value; wrapper.append(input); return wrapper;
}
function schemaEditorSelect(label, id, options = []) {
  const wrapper = node("label", undefined, "schema-workbench-control"); wrapper.append(node("span", label)); const select = node("select"); select.id = id; options.forEach(([value, text]) => select.append(Object.assign(node("option", text), { value }))); wrapper.append(select); return wrapper;
}
function schemaEditorButton(text, className = "secondary") { const button = node("button", text, className); button.type = "button"; return button; }
function schemaEditorDefinitionNames(schema) { return Object.keys(schema.definitions || {}).sort((a, b) => a.localeCompare(b)); }
function schemaEditorFieldOptions(schema, includeBlank = true) {
  const entries = schemaEditorFieldsInDocument(schema); const options = includeBlank ? [["", "No field reference"]] : [];
  entries.forEach(({ field, locator }) => options.push([field.id, `${field.name || field.id} · ${schemaEditorLocatorLabel(locator)}`]));
  return options;
}
function schemaEditorMakeUi() {
  if (state.schemaWorkbenchUi) return;
  state.schemaEditorScope = schemaEditorLocator(); state.schemaEditorTarget = null; state.schemaEditorInsert = { kind: "scope", scope: schemaEditorLocator() };
  const host = $("#schema-editor-fields"); if (!host) return;
  const workbench = node("section", undefined, "schema-workbench"); workbench.id = "schema-editor-workbench";
  const heading = node("div", undefined, "section-heading"); heading.append(node("div", undefined, "schema-workbench-title")); heading.firstChild.append(node("h4", "Structure tree"), node("p", "Select a structure or field to edit it with the existing inspector. IDs stay stable while fields move."));
  const saveRow = node("div", undefined, "button-row");
  const save = schemaEditorButton("Save reviewed V2 schema"); save.id = "schema-editor-save";
  const restoreLabel = node("label", "Restore reviewed V2 schema", "button secondary"); restoreLabel.setAttribute("for", "schema-editor-restore"); const restore = node("input"); restore.id = "schema-editor-restore"; restore.type = "file"; restore.accept = "application/json,.json"; restore.hidden = true; restoreLabel.append(restore);
  const exportJson = schemaEditorButton("Export exact V2 JSON"); exportJson.id = "schema-editor-export-json";
  saveRow.append(save, restoreLabel, exportJson); heading.append(saveRow); workbench.append(heading);
  const definitions = node("div", undefined, "schema-workbench-definitions"); definitions.id = "schema-editor-definitions"; workbench.append(definitions);
  const tree = node("div", undefined, "schema-workbench-tree"); tree.id = "schema-editor-tree"; workbench.append(tree);
  const dependencies = node("div", undefined, "schema-workbench-dependencies"); dependencies.id = "schema-editor-dependencies"; workbench.append(dependencies);
  const relationships = node("div", undefined, "schema-workbench-relationships"); relationships.id = "schema-editor-relationships"; workbench.append(relationships);
  host.before(workbench); state.schemaWorkbenchUi = workbench;
  save.addEventListener("click", exportReviewedSchemaJson);
  exportJson.addEventListener("click", exportReviewedSchemaJson);
  restore.addEventListener("change", restoreSchemaWorkbenchFile);
}
function initializeSchemaWorkbench() { schemaEditorMakeUi(); renderSchemaWorkbench(); }

function schemaEditorRenderDefinitions(schema) {
  const view = $("#schema-editor-definitions"); if (!view) return; view.replaceChildren();
  const title = node("h4", "Reusable definitions"); view.append(title);
  const rootButton = schemaEditorButton("Open root protocol"); rootButton.addEventListener("click", () => { state.schemaEditorScope = schemaEditorLocator(); state.schemaEditorInsert = { kind: "scope", scope: schemaEditorScopeLocator() }; state.schemaEditorTarget = null; clearSchemaEditor(); renderSchemaWorkbench(); }); view.append(rootButton);
  const controls = node("div", undefined, "button-row");
  const name = node("input"); name.id = "schema-editor-definition-name"; name.maxLength = 80; name.placeholder = "definition name"; name.setAttribute("aria-label", "New definition name");
  const add = schemaEditorButton("Add definition"); add.addEventListener("click", () => {
    const definitionName = name.value.trim();
    if (!definitionName || !/^[A-Za-z][A-Za-z0-9_.-]{0,79}$/.test(definitionName)) { setStatus("Definition names must start with a letter and contain only letters, numbers, dots, dashes, or underscores.", true); return; }
    const next = cloneJson(state.authoredSchema || ensureEditorSchema()); next.definitions ||= {};
    if (next.definitions[definitionName]) { setStatus(`Definition ${definitionName} already exists.`, true); return; }
    next.definitions[definitionName] = { fields: [], source: { origin: "manual", review_status: "confirmed" } };
    try { commitSchemaChange(next); state.schemaEditorScope = schemaEditorLocator("definition", definitionName); state.schemaEditorInsert = { kind: "scope", scope: schemaEditorScopeLocator() }; name.value = ""; renderSchemaWorkbench(); setStatus(`Definition ${definitionName} created.`); } catch (error) { setStatus(`Definition could not be created: ${error.message}`, true); }
  });
  controls.append(name, add); view.append(controls);
  const list = node("div", undefined, "schema-definition-list"); const definitions = schemaEditorDefinitionNames(schema);
  if (!definitions.length) list.append(node("p", "No reusable definitions yet. Add one, then reference it from a structure field.", "muted"));
  definitions.forEach((definitionName) => {
    const row = node("div", undefined, "field-row schema-definition-row"); const selected = state.schemaEditorScope?.kind === "definition" && state.schemaEditorScope.definition === definitionName;
    if (selected) row.classList.add("selected"); row.append(node("strong", definitionName), node("span", `${schema.definitions[definitionName]?.fields?.length || 0} field(s)`));
    const actions = node("span", undefined, "annotation-actions"); const select = schemaEditorButton(selected ? "Selected" : "Open"); select.disabled = selected; select.addEventListener("click", () => { state.schemaEditorScope = schemaEditorLocator("definition", definitionName); state.schemaEditorInsert = { kind: "scope", scope: schemaEditorScopeLocator() }; state.schemaEditorTarget = null; state.editingSchemaField = null; clearSchemaEditor(); renderSchemaWorkbench(); });
    const rename = schemaEditorButton("Rename"); rename.addEventListener("click", () => schemaEditorRenameDefinition(definitionName));
    const duplicate = schemaEditorButton("Duplicate"); duplicate.addEventListener("click", () => schemaEditorDuplicateDefinition(definitionName));
    const remove = schemaEditorButton("Delete"); remove.addEventListener("click", () => schemaEditorDeleteDefinition(definitionName)); actions.append(select, rename, duplicate, remove); row.append(actions); list.append(row);
  });
  view.append(list);
}
function schemaEditorRenameDefinition(oldName) {
  const nextName = window.prompt(`Rename reusable definition ${oldName}`, oldName);
  if (nextName === null) return;
  const clean = nextName.trim(); const schema = cloneJson(state.authoredSchema || ensureEditorSchema());
  if (!clean || !/^[A-Za-z][A-Za-z0-9_.-]{0,79}$/.test(clean) || schema.definitions?.[clean]) { setStatus("Definition name is invalid or already in use.", true); return; }
  schema.definitions[clean] = schema.definitions[oldName]; delete schema.definitions[oldName];
  const rewrite = (value) => { if (Array.isArray(value)) return value.forEach(rewrite); if (!value || typeof value !== "object") return; Object.entries(value).forEach(([key, item]) => { if ((key === "definition" || key === "use") && item === oldName) value[key] = clean; else rewrite(item); }); };
  rewrite(schema.fields); rewrite(schema.relationships); rewrite(schema.definitions);
  try { commitSchemaChange(schema); if (state.schemaEditorScope?.definition === oldName) state.schemaEditorScope.definition = clean; renderSchemaWorkbench(); setStatus(`Definition renamed to ${clean}; references were updated.`); } catch (error) { setStatus(`Definition could not be renamed: ${error.message}`, true); }
}
function schemaEditorDuplicateDefinition(name) {
  const schema = cloneJson(state.authoredSchema || ensureEditorSchema()); const base = `${name}_copy`; let candidate = base; let index = 2; while (schema.definitions?.[candidate]) candidate = `${base}_${index++}`;
  schema.definitions ||= {}; schema.definitions[candidate] = cloneJson(schema.definitions[name]);
  try { commitSchemaChange(schema); state.schemaEditorScope = schemaEditorLocator("definition", candidate); renderSchemaWorkbench(); setStatus(`Definition ${candidate} duplicated. References remain pointed at ${name}.`); } catch (error) { setStatus(`Definition could not be duplicated: ${error.message}`, true); }
}
function schemaEditorDeleteDefinition(name) {
  const schema = cloneJson(state.authoredSchema || ensureEditorSchema()); const references = [];
  schemaEditorReferenceValues(schema.fields).forEach((reference) => { if (reference === name) references.push(reference); });
  Object.values(schema.definitions || {}).forEach((definition) => schemaEditorReferenceValues(definition).forEach((reference) => { if (reference === name) references.push(reference); }));
  if (references.length) { setStatus(`Definition ${name} is still referenced. Remove or retarget ${references.length} reference(s) first.`, true); return; }
  delete schema.definitions?.[name]; try { commitSchemaChange(schema); state.schemaEditorScope = schemaEditorLocator(); renderSchemaWorkbench(); setStatus(`Definition ${name} deleted.`); } catch (error) { setStatus(`Definition could not be deleted: ${error.message}`, true); }
}
function schemaEditorRenderFieldTree(schema) {
  const view = $("#schema-editor-tree"); if (!view) return; view.replaceChildren();
  const scope = schemaEditorScopeLocator(); const fields = schemaEditorBaseFields(schema, scope); const title = node("div", undefined, "section-heading"); title.append(node("div", undefined, "schema-workbench-title")); title.firstChild.append(node("h4", `${scope.kind === "definition" ? `Definition: ${scope.definition}` : "Root protocol"}`), node("p", "Add and reorder fields in this scope. A structure's children and an array's element are edited from the tree.")); const add = schemaEditorButton("Add field to scope"); add.addEventListener("click", () => { state.schemaEditorTarget = null; state.schemaEditorInsert = { kind: "scope", scope }; state.editingSchemaField = null; clearSchemaEditor(); renderSchemaWorkbench(); $("#schema-editor-name")?.focus(); }); title.append(add); view.append(title);
  const render = (field, locator, depth, parent) => {
    if (depth > 16) return;
    const row = node("div", undefined, `field-row schema-tree-row depth-${Math.min(depth, 4)}`); row.dataset.fieldId = field.id || ""; row.dataset.schemaPath = schemaEditorLocatorLabel(locator); if (schemaEditorSameLocator(state.schemaEditorTarget, locator)) row.classList.add("selected");
    const marker = field.definition ? ` · uses ${field.definition}` : field.array ? ` · array ${expressionText(field.array.count)}` : field.fields ? ` · ${field.fields.length} child field(s)` : "";
    row.append(node("strong", `${field.name || field.id} · ${field.id}`), node("span", `${field.type || "bytes"}${marker} · offset ${expressionText(field.offset)} · length ${expressionText(field.length)}`));
    const actions = node("span", undefined, "annotation-actions"); const edit = schemaEditorButton("Inspect"); edit.addEventListener("click", () => { state.schemaEditorTarget = locator; state.schemaEditorInsert = { kind: "scope", scope }; state.editingSchemaField = 0; populateSchemaEditor(field, locator); renderSchemaWorkbench(); $("#schema-editor-name")?.focus(); });
    const up = schemaEditorButton("↑"); up.title = "Move field earlier"; up.disabled = !parent || parent.index === 0; up.addEventListener("click", () => schemaEditorMoveField(locator, -1));
    const down = schemaEditorButton("↓"); down.title = "Move field later"; down.disabled = !parent || parent.index >= fields.length - 1; down.addEventListener("click", () => schemaEditorMoveField(locator, 1));
    const duplicate = schemaEditorButton("Duplicate"); duplicate.addEventListener("click", () => schemaEditorDuplicateField(locator));
    const remove = schemaEditorButton("Delete"); remove.addEventListener("click", () => schemaEditorDeleteField(locator)); actions.append(edit, up, down, duplicate, remove); row.append(actions); view.append(row);
    if (field.fields || field.type === "struct") { const childAdd = schemaEditorButton("Add child"); childAdd.addEventListener("click", () => { state.schemaEditorTarget = null; state.schemaEditorInsert = { kind: "children", parent: locator }; state.editingSchemaField = null; clearSchemaEditor(); renderSchemaWorkbench(); }); row.append(childAdd); (field.fields || []).slice(0, 1000).forEach((child, index) => render(child, schemaEditorLocator(scope.kind, scope.definition, [...locator.segments, { index }]), depth + 1, { index })); }
    if (field.array?.element) { const elementSegments = locator.segments.slice(0, -1).concat([{ index: locator.segments.at(-1)?.index ?? 0, array: true }]); const elementLocator = schemaEditorLocator(scope.kind, scope.definition, elementSegments); const elementRow = node("div", undefined, "field-row schema-array-editor-row"); elementRow.append(node("span", `↳ element · ${field.array.element.type || "bytes"} · ${field.array.element.id || "element"}`)); const inspect = schemaEditorButton("Inspect element"); inspect.addEventListener("click", () => { state.schemaEditorTarget = elementLocator; state.schemaEditorInsert = { kind: "scope", scope }; state.editingSchemaField = 0; populateSchemaEditor(field.array.element, elementLocator); renderSchemaWorkbench(); }); elementRow.append(inspect); view.append(elementRow); if (field.array.element.fields) field.array.element.fields.forEach((child, index) => render(child, schemaEditorLocator(scope.kind, scope.definition, [...elementLocator.segments, { index }]), depth + 2, { index })); }
  };
  if (!fields.length) view.append(node("p", "No fields in this scope. Add a field to begin building the protocol.", "muted")); fields.slice(0, 1000).forEach((field, index) => render(field, schemaEditorLocator(scope.kind, scope.definition, [{ index }]), 0, { index }));
}
function schemaEditorRenderDependencies(schema) {
  const view = $("#schema-editor-dependencies"); if (!view) return; view.replaceChildren(node("h4", "Dependency inspector"));
  const diagnostics = schemaEditorReferenceDiagnostics(schema); const entries = schemaEditorFieldsInDocument(schema);
  if (!entries.length) { view.append(node("p", "Add fields to inspect dependencies.", "muted")); return; }
  entries.slice(0, 1000).forEach(({ field, locator }) => {
    const refs = schemaEditorReferenceValues(field); const row = node("div", undefined, "dependency-row"); row.append(node("strong", field.name || field.id), node("span", refs.length ? refs.map((reference) => `→ ${reference}`).join(" ") : "No field references"));
    const issues = diagnostics.filter((item) => item.locator && schemaEditorSameLocator(item.locator, locator) || item.fieldId === field.id); issues.forEach((issue) => row.append(node("span", issue.kind === "cycle" ? `cycle: ${(issue.path || []).join(" → ")}` : `missing: ${issue.reference}`, "schema-dependency-error"))); view.append(row);
  });
  if (!diagnostics.length) view.append(node("p", "All visible field references resolve; server validation still remains authoritative for reusable scopes and relationships.", "muted"));
}
function schemaEditorRenderRelationships(schema) {
  const view = $("#schema-editor-relationships"); if (!view) return; view.replaceChildren(node("h4", "Length and checksum relationships"), node("p", "Relationships are validated by the Python evaluator. Add only reviewed relationships; unsupported or incomplete states remain visible in validation.", "muted"));
  const form = node("div", undefined, "schema-relationship-form"); form.append(schemaEditorTextField("Relationship ID", "schema-rel-id", "relationship")); form.append(schemaEditorSelect("Kind", "schema-rel-kind", [["length", "Length"], ["checksum", "Checksum"]])); form.append(schemaEditorSelect("Source field", "schema-rel-field", schemaEditorFieldOptions(schema, false))); form.append(schemaEditorSelect("Target field", "schema-rel-target", schemaEditorFieldOptions(schema, true))); form.append(schemaEditorSelect("Algorithm", "schema-rel-algorithm", [["CRC-8", "CRC-8"], ["CRC-16/CCITT-FALSE", "CRC-16/CCITT-FALSE"], ["CRC-32", "CRC-32"], ["XOR-8", "XOR-8"], ["ADDITIVE-8", "ADDITIVE-8"], ["ADDITIVE-16", "ADDITIVE-16"]])); form.append(schemaEditorTextField("Include ranges (JSON)", "schema-rel-include", "[[0, 1]]")); form.append(schemaEditorTextField("Exclude ranges (JSON)", "schema-rel-exclude", "[]")); const add = schemaEditorButton("Add relationship"); add.addEventListener("click", () => schemaEditorAddRelationship(schema)); form.append(add); view.append(form);
  const list = node("div", undefined, "schema-relationship-list"); (schema.relationships || []).forEach((relationship, index) => { const row = node("div", undefined, "field-row"); row.append(node("strong", relationship.id || `relationship-${index}`), node("span", `${relationship.kind || "checksum"} · ${relationship.field_id || relationship.checksum_field_id || "?"} → ${relationship.target_field_id || "coverage"}`)); const remove = schemaEditorButton("Delete"); remove.addEventListener("click", () => { const next = cloneJson(state.authoredSchema || schema); next.relationships.splice(index, 1); try { commitSchemaChange(next); renderSchemaWorkbench(); } catch (error) { setStatus(`Relationship could not be removed: ${error.message}`, true); } }); row.append(remove); list.append(row); }); if (!(schema.relationships || []).length) list.append(node("p", "No relationships have been declared.", "muted")); view.append(list);
}
function renderSchemaWorkbench() { schemaEditorMakeUi(); const schema = ensureEditorSchema(); schemaEditorRenderDefinitions(schema); schemaEditorRenderFieldTree(schema); schemaEditorRenderDependencies(schema); schemaEditorRenderRelationships(schema); renderSchemaSelectionSource(); updateSchemaHistoryButtons(); }

function schemaEditorCloneForChange() { return cloneJson(state.authoredSchema?.schema_version === 2 ? state.authoredSchema : ensureEditorSchema()); }
function schemaEditorListForInsert(schema, insert) {
  if (!insert || insert.kind === "scope") return schemaEditorBaseFields(schema, insert?.scope || schemaEditorScopeLocator());
  const parent = schemaEditorFieldAt(schema, insert.parent); if (!parent) throw new Error("parent structure no longer exists");
  if (insert.kind === "children") { parent.fields ||= []; return parent.fields; }
  throw new Error("unsupported schema insertion target");
}
function schemaEditorSetAtLocator(schema, locator, field) {
  const segments = locator?.segments || []; if (!segments.length) throw new Error("field locator is empty");
  const parentFields = schemaEditorParentFields(schema, locator); const last = segments[segments.length - 1];
  if (last.array) { const parent = schemaEditorFieldAt(schema, schemaEditorLocator(locator.kind, locator.definition, segments.slice(0, -1).concat([{ index: last.index }]))); if (!parent?.array) throw new Error("array element no longer exists"); parent.array.element = field; return; }
  parentFields[last.index] = field;
}
function schemaEditorRemoveAtLocator(schema, locator) {
  const segments = locator?.segments || []; if (!segments.length) throw new Error("field locator is empty");
  const last = segments[segments.length - 1]; if (last.array) throw new Error("array elements are edited with their parent array");
  const parentFields = schemaEditorParentFields(schema, locator); parentFields.splice(last.index, 1);
}
function schemaEditorReferencedBy(schema, field) {
  const names = new Set([field?.id, field?.name].filter(Boolean)); const references = [];
  schemaEditorFieldsInDocument(schema).forEach(({ field: candidate, locator }) => { if (candidate === field) return; const refs = schemaEditorReferenceValues(candidate).filter((reference) => names.has(reference)); refs.forEach((reference) => references.push({ locator, reference })); });
  (schema.relationships || []).forEach((relationship) => { if (schemaEditorReferenceValues(relationship).some((reference) => names.has(reference))) references.push({ locator: null, reference: relationship.id || "relationship" }); });
  return references;
}
function schemaEditorMoveField(locator, direction) {
  const schema = schemaEditorCloneForChange(); const segments = locator?.segments || []; const last = segments.at(-1); if (!last || last.array) return;
  const fields = schemaEditorParentFields(schema, locator); const targetIndex = last.index + direction; if (targetIndex < 0 || targetIndex >= fields.length) return;
  [fields[last.index], fields[targetIndex]] = [fields[targetIndex], fields[last.index]];
  const nextLocator = schemaEditorLocator(locator.kind, locator.definition, segments.slice(0, -1).concat([{ index: targetIndex }]));
  try { commitSchemaChange(schema); state.schemaEditorTarget = nextLocator; renderSchemaWorkbench(); setStatus(`Moved ${fields[targetIndex].name || fields[targetIndex].id}; stable field IDs were preserved.`); } catch (error) { setStatus(`Field could not be moved: ${error.message}`, true); }
}
function schemaEditorDuplicateField(locator) {
  const schema = schemaEditorCloneForChange(); const field = schemaEditorFieldAt(schema, locator); if (!field) return; const fields = schemaEditorParentFields(schema, locator); const copy = cloneJson(field); const base = `${copy.id || "field"}_copy`; let id = base; let count = 2; const ids = new Set(fields.map((item) => item.id)); while (ids.has(id)) id = `${base}_${count++}`; copy.id = id; copy.name = `${copy.name || copy.id} copy`; const index = locator.segments.at(-1)?.index ?? fields.length - 1; fields.splice(index + 1, 0, copy); try { commitSchemaChange(schema); state.schemaEditorTarget = schemaEditorLocator(locator.kind, locator.definition, locator.segments.slice(0, -1).concat([{ index: index + 1 }])); renderSchemaWorkbench(); setStatus(`Field duplicated as ${id}.`); } catch (error) { setStatus(`Field could not be duplicated: ${error.message}`, true); }
}
function schemaEditorDeleteField(locator) {
  const schema = schemaEditorCloneForChange(); const field = schemaEditorFieldAt(schema, locator); if (!field) return; const references = schemaEditorReferencedBy(schema, field);
  if (references.length) { const detail = references.slice(0, 4).map((item) => item.reference).join(", "); setStatus(`Cannot delete ${field.id}; it is referenced by ${detail}. Retarget those dependencies first.`, true); return; }
  try { schemaEditorRemoveAtLocator(schema, locator); commitSchemaChange(schema); state.schemaEditorTarget = null; state.editingSchemaField = null; clearSchemaEditor(); renderSchemaWorkbench(); setStatus(`Field ${field.id} deleted.`); } catch (error) { setStatus(`Field could not be deleted: ${error.message}`, true); }
}
function schemaEditorAddRelationship(schema) {
  try {
    const id = $("#schema-rel-id").value.trim(); const kind = $("#schema-rel-kind").value; const fieldId = $("#schema-rel-field").value; const targetId = $("#schema-rel-target").value; if (!id || !fieldId) throw new Error("relationship ID and source field are required");
    const next = cloneJson(state.authoredSchema || schema); next.relationships ||= []; if (next.relationships.some((item) => item.id === id)) throw new Error(`relationship ${id} already exists`);
    let relationship = { id, kind, field_id: fieldId }; if (kind === "length") { if (!targetId) throw new Error("length relationships require a target field"); relationship.target_field_id = targetId; }
    else { relationship.algorithm = $("#schema-rel-algorithm").value; relationship.byte_order = "big"; const include = JSON.parse($("#schema-rel-include").value || "[]"); const exclude = JSON.parse($("#schema-rel-exclude").value || "[]"); if (!Array.isArray(include) || !Array.isArray(exclude)) throw new Error("coverage ranges must be JSON arrays"); relationship.covered_ranges = { include, exclude }; }
    next.relationships.push(relationship); commitSchemaChange(next); renderSchemaWorkbench(); setStatus(`Relationship ${id} added; server validation will report its status.`);
  } catch (error) { setStatus(`Relationship is not valid: ${error.message}`, true); }
}
function schemaEditorFieldFromForm() {
  const field = schemaFieldFromEditorOriginal();
  const definition = $("#schema-editor-definition")?.value || ""; if (definition) { field.definition = definition; field.type = "struct"; delete field.fields; }
  const offsetReference = $("#schema-editor-offset-reference")?.value; if (offsetReference) { const add = Number($("#schema-editor-offset-add")?.value || 0); field.offset = add ? { field: offsetReference, add } : { field: offsetReference }; }
  const lengthReference = $("#schema-editor-length-reference")?.value; if (lengthReference) field.length = { field: lengthReference };
  const countReference = $("#schema-editor-array-count-reference")?.value; if (field.array && countReference) field.array.count = { field: countReference };
  const conditionReference = $("#schema-editor-condition-reference")?.value; if (conditionReference) { const valueText = $("#schema-editor-condition-value")?.value || "1"; let value; try { value = JSON.parse(valueText); } catch { value = valueText; } field.presence = { op: $("#schema-editor-condition-op")?.value || "eq", args: [{ field: conditionReference }, value] }; }
  return field;
}
/* Keep the pre-workbench form parser intact as a private implementation so
 * the structured controls above can add common references without changing
 * the existing constraint semantics. */
function saveEditorField() {
  const schema = ensureEditorSchema(); const before = schemaSnapshot(); const field = schemaEditorFieldFromForm(); const target = state.schemaEditorTarget || (state.editingSchemaField === null || state.editingSchemaField === undefined ? null : schemaEditorLocator("root", "", [{ index: state.editingSchemaField }]));
  const authored = schemaEditorCloneForChange();
  try {
    if (target) { const previous = schemaEditorFieldAt(authored, target); if (!previous) throw new Error("selected field no longer exists"); field.id = previous.id; schemaEditorSetAtLocator(authored, target, field); }
    else { const list = schemaEditorListForInsert(authored, state.schemaEditorInsert || { kind: "scope", scope: schemaEditorScopeLocator() }); if (list.some((item) => item.id === field.id)) throw new Error(`field ID ${field.id} already exists in this scope`); list.push(field); }
    commitSchemaChange(authored, before); state.schemaEditorTarget = null; state.schemaEditorInsert = { kind: "scope", scope: schemaEditorScopeLocator() }; state.editingSchemaField = null; clearSchemaEditor(); renderSchemaWorkbench();
  } catch (error) { throw error; }
}
function populateSchemaEditor(field, locator = null) {
  populateSchemaEditorOriginal(field); state.schemaEditorTarget = locator; state.schemaEditorInsert = { kind: "scope", scope: schemaEditorScopeLocator() };
  const schema = ensureEditorSchema(); schemaEditorEnsureReferenceControls(schema); $("#schema-editor-definition").value = field.definition || "";
  const offset = field.offset && typeof field.offset === "object" ? field.offset.field || "" : ""; $("#schema-editor-offset-reference").value = offset; $("#schema-editor-offset-add").value = field.offset?.add || 0;
  $("#schema-editor-length-reference").value = field.length && typeof field.length === "object" ? field.length.field || "" : ""; $("#schema-editor-array-count-reference").value = field.array?.count && typeof field.array.count === "object" ? field.array.count.field || "" : "";
  const condition = field.presence && typeof field.presence === "object" ? field.presence : null; const conditionField = condition?.args?.[0]?.field || ""; $("#schema-editor-condition-reference").value = conditionField; $("#schema-editor-condition-op").value = condition?.op || "eq"; $("#schema-editor-condition-value").value = condition?.args?.[1] === undefined ? "1" : valueForEditor(condition.args[1]); renderSchemaSelectionSource();
}
function clearSchemaEditor() { clearSchemaEditorOriginal(); state.schemaEditorTarget = null; state.schemaEditorInsert = { kind: "scope", scope: schemaEditorScopeLocator() }; if (state.schemaWorkbenchUi) schemaEditorEnsureReferenceControls(ensureEditorSchema()); }
function schemaEditorEnsureReferenceControls(schema) {
  const form = $("#schema-editor-form"); if (!form || $("#schema-editor-definition")) return;
  const marker = form.querySelector(".schema-constraints");
  const controls = node("section", undefined, "schema-reference-controls"); controls.append(node("h4", "Common dependency controls"), node("p", "These controls create declarative references; the JSON fields remain available for advanced expressions."));
  const grid = node("div", undefined, "constraint-grid");
  const definitions = [["", "Inline structure"], ...schemaEditorDefinitionNames(schema).map((name) => [name, `Reusable: ${name}`])]; const definitionControl = schemaEditorSelect("Reusable definition", "schema-editor-definition", definitions);
  const options = schemaEditorFieldOptions(schema); const offsetControl = schemaEditorSelect("Offset reference", "schema-editor-offset-reference", options); const offsetAdd = schemaEditorTextField("Offset add", "schema-editor-offset-add", "0", "number");
  const lengthControl = schemaEditorSelect("Length reference", "schema-editor-length-reference", options); const countControl = schemaEditorSelect("Array count reference", "schema-editor-array-count-reference", options); const conditionControl = schemaEditorSelect("Condition field", "schema-editor-condition-reference", options); const conditionOp = schemaEditorSelect("Condition operator", "schema-editor-condition-op", [["eq", "equals"], ["ne", "not equal"], ["gt", "greater than"], ["gte", "at least"], ["lt", "less than"], ["lte", "at most"]]); const conditionValue = schemaEditorTextField("Condition value (JSON)", "schema-editor-condition-value", "1");
  [definitionControl, offsetControl, offsetAdd, lengthControl, countControl, conditionControl, conditionOp, conditionValue].forEach((control) => grid.append(control)); controls.append(grid); if (marker) form.insertBefore(controls, marker); else form.prepend(controls);
}
function schemaEditorRefreshReferenceControls(schema) {
  schemaEditorEnsureReferenceControls(schema);
  const fields = schemaEditorFieldOptions(schema); ["schema-editor-offset-reference", "schema-editor-length-reference", "schema-editor-array-count-reference", "schema-editor-condition-reference"].forEach((id) => { const select = $(`#${id}`); if (!select) return; const value = select.value; select.replaceChildren(); fields.forEach(([key, text]) => select.append(Object.assign(node("option", text), { value: key }))); select.value = fields.some(([key]) => key === value) ? value : ""; });
  const definition = $("#schema-editor-definition"); if (definition) { const value = definition.value; definition.replaceChildren(Object.assign(node("option", "Inline structure"), { value: "" })); schemaEditorDefinitionNames(schema).forEach((name) => definition.append(Object.assign(node("option", `Reusable: ${name}`), { value: name }))); definition.value = schemaEditorDefinitionNames(schema).includes(value) ? value : ""; }
}
function renderSchemaEditor() {
  schemaEditorMakeUi(); const schema = ensureEditorSchema(); schemaEditorRefreshReferenceControls(schema); schemaEditorRenderDefinitions(schema); schemaEditorRenderFieldTree(schema); schemaEditorRenderDependencies(schema); schemaEditorRenderRelationships(schema); renderSchemaLegacyFieldList(schema); renderSchemaSelectionSource(); updateSchemaHistoryButtons();
}
function renderSchemaLegacyFieldList(schema) {
  const view = $("#schema-editor-fields"); if (!view) return; view.replaceChildren(); const fields = schema.fields || [];
  fields.slice(0, 1000).forEach((field, index) => {
    const row = node("div", undefined, "field-row schema-editor-row"); const constraints = Object.keys(field.constraints || {}).length; row.append(node("strong", `${field.name} · ${field.id}`), node("span", `${field.type || "bytes"} · offset ${expressionText(field.offset)} · length ${expressionText(field.length)} · ${field.endian || "unknown"}${field.array ? ` · array count ${expressionText(field.array.count)}` : ""}${field.fields ? ` · ${field.fields.length} nested` : ""}`), node("span", `${field.description || "No description."}${constraints ? ` · ${constraints} constraint(s)` : ""}`));
    const actions = node("span", undefined, "annotation-actions"); const edit = schemaEditorButton("Edit"); edit.addEventListener("click", () => { const locator = schemaEditorLocator("root", "", [{ index }]); state.schemaEditorTarget = locator; state.schemaEditorScope = schemaEditorLocator(); populateSchemaEditor(field, locator); renderSchemaWorkbench(); $("#schema-editor-name")?.focus(); }); const remove = schemaEditorButton("Remove"); remove.addEventListener("click", () => schemaEditorDeleteField(schemaEditorLocator("root", "", [{ index }]))); actions.append(edit, remove); row.append(actions); view.append(row);
  });
  if (!fields.length) view.append(node("p", "No reviewed fields yet.", "muted"));
}
function exportReviewedSchemaJson() {
  try { const schema = validateSchema(ensureEditorSchema()); const blob = new Blob([JSON.stringify(state.authoredSchema || schema, null, 2)], { type: "application/json" }); const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = `${state.result?.source?.name || "packetscope-protocol"}.schema-v2.json`; link.click(); URL.revokeObjectURL(link.href); setStatus("Reviewed Schema V2 saved without losing nested definitions or relationships."); } catch (error) { setStatus(`Schema cannot be saved: ${error.message}`, true); }
}
async function restoreSchemaFile(file) {
  if (!file || file.size > 2 * 1024 * 1024) throw new Error("Protocol schema is too large."); const authored = JSON.parse(await file.text()); const schema = validateSchema(authored); if (!state.result) throw new Error("load a capture before applying a schema"); state.authoredSchema = cloneJson(authored); state.schema = schema; state.schemaValues = applySchema(schema); state.schemaUndo = []; state.schemaRedo = []; state.schemaEditorTarget = null; state.schemaEditorScope = schemaEditorLocator(); state.schemaEditorInsert = { kind: "scope", scope: schemaEditorScopeLocator() }; state.editingSchemaField = null; state.schemaEditorSelection = null; renderFields(); renderSchemaEditor(); updateSchemaHistoryButtons(); setStatus(`Restored reviewed schema with ${schemaEditorFieldsInDocument(schema).length} visible field node(s).`);
}
async function restoreSchemaFileFromInput(event) { try { await restoreSchemaFile(event.target.files[0]); } catch (error) { setStatus(`Protocol schema is not valid: ${error.message}`, true); } finally { event.target.value = ""; } }
function restoreSchemaWorkbenchFile(event) { restoreSchemaFileFromInput(event); }
function schemaEditorInstallRestoreAlias() { const input = $("#schema-editor-restore"); if (input && !input.dataset.bound) { input.dataset.bound = "true"; input.addEventListener("change", restoreSchemaWorkbenchFile); } }
function exportProject() {
  if (!state.result) return; const copy = cloneJson(state.result); copy.annotations = state.annotations; if (state.authoredSchema || state.schema) copy.authoredSchema = cloneJson(state.authoredSchema || state.schema); copy.project = { schema_version: 2, content_hash: contentHash(copy.packets), authored_schema: Boolean(copy.authoredSchema) };
  const blob = new Blob([JSON.stringify(copy, null, 2)], { type: "application/json" }); const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = `${state.result.source?.name || "packetscope-project"}.json`; link.click(); URL.revokeObjectURL(link.href); setStatus(copy.authoredSchema ? "Project exported with annotations and the reviewed schema." : "Project exported with annotations.");
}
function loadResult(result, options = {}) {
  validateProject(result); const priorAnnotations = state.annotations; state.result = result; state.selectedHypothesis = null; $("#stream-view").hidden = true;
  if (!options.preserveAnnotations) { state.schema = null; state.authoredSchema = null; state.schemaValues = []; state.hexSelection = null; }
  const imported = Array.isArray(result.annotations) ? result.annotations.filter(validAnnotation).slice(0, 1000) : []; let saved = [];
  if (!options.preserveAnnotations && options.restoreLocal !== false) { try { const candidate = JSON.parse(localStorage.getItem(sourceKey()) || "[]"); saved = Array.isArray(candidate) ? candidate.filter(validAnnotation).slice(0, 1000) : []; } catch { saved = []; } }
  state.annotations = options.preserveAnnotations ? priorAnnotations.slice(0, 1000) : (imported.length ? imported : saved); state.undo = []; state.redo = []; state.schemaUndo = []; state.schemaRedo = []; state.editingAnnotation = null; state.editingSchemaField = null; state.schemaEditorSelection = null; state.schemaEditorTarget = null; state.schemaEditorScope = schemaEditorLocator(); state.schemaEditorInsert = { kind: "scope", scope: schemaEditorScopeLocator() }; $("#annotation-submit").textContent = "Add annotation"; state.packetQuery = options.preserveAnnotations ? state.packetQuery : ""; $("#packet-search").value = state.packetQuery; state.demoProfile = result.demo?.profile || null;
  if (!options.preserveAnnotations && result.authoredSchema) { try { state.authoredSchema = cloneJson(result.authoredSchema); state.schema = validateSchema(result.authoredSchema); } catch (error) { setStatus(`Saved project schema was ignored: ${error.message}`, true); state.authoredSchema = null; state.schema = null; } }
  $("#results").hidden = false; $("#demo-evaluate").hidden = !state.demoProfile; render(); if (state.schema) { state.schemaValues = applySchema(state.schema); renderFields(); renderSchemaEditor(); } updateHexSelectionControls();
}
function validateProject(value) { if (!value || typeof value !== "object" || !Array.isArray(value.packets) || value.packets.length > 100000) throw new Error("packet list is missing or too large"); if (value.schema_version !== undefined && value.schema_version !== 2) throw new Error("unsupported schema version"); if (Array.isArray(value.annotations) && value.annotations.length > 1000) throw new Error("too many annotations"); if (value.project?.schema_version !== undefined && ![1, 2].includes(value.project.schema_version)) throw new Error("unsupported project schema version"); if (value.authoredSchema !== undefined) validateSchema(value.authoredSchema); }
function exportReviewedSchema(format) { try { const schema = validateSchema(ensureEditorSchema()); const responsePromise = fetch(`/api/schema/export/${format}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ schema: state.authoredSchema || schema }) }); responsePromise.then(async (response) => { const result = await response.json(); if (!response.ok) throw new Error(result.error || "schema export failed"); const extension = format === "kaitai" ? "ksy" : "lua"; const blob = new Blob([result.content], { type: "text/plain" }); const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = `packetscope-protocol.${extension}`; link.click(); URL.revokeObjectURL(link.href); setStatus(`${format === "kaitai" ? "Kaitai" : "Wireshark Lua"} export downloaded${result.warnings?.length ? ` with ${result.warnings.length} explicit warning(s)` : ""}.`); }).catch((error) => setStatus(error.message, true)); } catch (error) { setStatus(error.message, true); } }
initializeSchemaWorkbench = initializeSchemaWorkbench; // keep the initialization call above explicit for older browsers
schemaEditorInstallRestoreAlias();
