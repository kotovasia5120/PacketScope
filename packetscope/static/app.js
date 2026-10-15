const state = { result: null, annotations: [] };
const $ = (selector) => document.querySelector(selector);

$("#packet-file").addEventListener("change", (event) => {
  const file = event.target.files[0];
  $("#file-name").textContent = file ? `${file.name} · ${file.size.toLocaleString()} bytes` : "Nothing loaded yet";
});

$("#upload-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = $("#packet-file").files[0];
  if (!file) return;
  setStatus("Reading and analyzing locally…");
  const body = new FormData();
  body.append("file", file, file.name);
  body.append("format", $("#format").value);
  try {
    const response = await fetch("/api/analyze", { method: "POST", body });
    const value = await response.json();
    if (!response.ok) throw new Error(value.error || "Analysis failed");
    state.result = value; state.annotations = [];
    render(); setStatus(`Analyzed ${value.source.packet_count} packet(s) from ${value.source.name}.`);
  } catch (error) { setStatus(error.message, true); }
});

$("#packet-select").addEventListener("change", renderPacket);
$("#export-button").addEventListener("click", () => {
  if (!state.result) return;
  const result = { ...state.result, annotations: state.annotations };
  const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob); const link = document.createElement("a");
  link.href = url; link.download = "packetscope-result.json"; link.click(); URL.revokeObjectURL(url);
});
$("#annotation-form").addEventListener("submit", (event) => {
  event.preventDefault();
  state.annotations.push({ label: $("#annotation-label").value.trim(), start: Number($("#annotation-start").value), end: Number($("#annotation-end").value), source: "manual" });
  event.target.reset(); $("#annotation-start").value = "0"; $("#annotation-end").value = "1"; renderAnnotations();
});

function setStatus(text, error = false) { const node = $("#status"); node.textContent = text; node.classList.toggle("error", error); }
function render() {
  const result = state.result; $("#results").hidden = false;
  $("#summary-grid").innerHTML = [[result.source.packet_count, "packets"], [result.source.byte_count.toLocaleString(), "source bytes"], [result.hypotheses.length, "candidate hypotheses"], [result.observations.min_length, "shortest packet"]].map(([value, label]) => `<div class="metric"><strong>${escapeHtml(String(value))}</strong><span>${escapeHtml(label)}</span></div>`).join("");
  $("#packet-select").innerHTML = result.packets.map((packet) => `<option value="${packet.index}">Packet ${packet.index} · ${packet.payload.length / 2} bytes</option>`).join("");
  renderPacket(); renderComparison(); renderHypotheses(); renderAnnotations();
}
function renderPacket() {
  const packet = state.result?.packets.find((item) => item.index === Number($("#packet-select").value)); if (!packet) return;
  const bytes = packet.payload.match(/../g) || []; const rows = [];
  for (let start = 0; start < bytes.length; start += 16) { const row = bytes.slice(start, start + 16); const padded = row.concat(Array(16 - row.length).fill("  ")); const ascii = row.map((hex) => { const value = parseInt(hex, 16); return value >= 32 && value <= 126 ? String.fromCharCode(value) : "."; }).join(""); rows.push(`<div class="hex-line"><span class="offset">${start.toString(16).padStart(8, "0")}</span><span>${padded.join(" ")}</span><span class="ascii">${escapeHtml(ascii)}</span></div>`); }
  $("#hex-view").innerHTML = rows.join("") || "<span class=muted>empty packet</span>";
}
function renderComparison() { const regions = state.result.observations.comparison.regions; $("#comparison-view").innerHTML = regions.length ? `<div class="region-table">${regions.map((region) => `<div class="region-row"><strong class="${region.kind}">${escapeHtml(region.kind.replace("_", " "))}</strong><span>0x${region.start.toString(16)}–0x${region.end.toString(16)}</span><span>${escapeHtml(JSON.stringify(region.evidence))}</span></div>`).join("")}</div>` : `<p class="muted">At least two packets are needed for an aligned comparison.</p>`; }
function renderHypotheses() { $("#hypotheses-view").innerHTML = state.result.hypotheses.length ? state.result.hypotheses.map((item) => `<article class="hypothesis-card"><div class="hypothesis-title"><strong>${escapeHtml(item.kind.replace("_", " "))}</strong><span class="confidence">${Math.round(item.confidence * 100)}% confidence</span></div><p>Offset 0x${item.offset.toString(16)}, width ${item.width} byte(s). ${escapeHtml(item.evidence.join(" "))}</p><p>Caveat: ${escapeHtml(item.caveats.join(" "))}</p></article>`).join("") : `<p class="muted">No candidate matched the current evidence.</p>`; }
function renderAnnotations() { $("#annotations-view").innerHTML = state.annotations.map((item, index) => `<li><span><strong>${escapeHtml(item.label)}</strong> · offsets ${item.start}–${item.end}</span><button type="button" data-index="${index}">Remove</button></li>`).join("") || `<li class="muted">No manual annotations yet.</li>`; $("#annotations-view").querySelectorAll("button").forEach((button) => button.addEventListener("click", () => { state.annotations.splice(Number(button.dataset.index), 1); renderAnnotations(); })); }
function escapeHtml(value) { return value.replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[character])); }
