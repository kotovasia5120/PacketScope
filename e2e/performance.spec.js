const { test, expect } = require("@playwright/test");
const fs = require("fs");

function resultFor(packetCount, hypothesisCount = 0, packetBytes = 1) {
  const payload = "aa".repeat(packetBytes);
  return {
    schema_version: 2,
    source: { name: "synthetic-browser-benchmark.bin", format: "bin", packet_count: packetCount, byte_count: packetCount * packetBytes },
    packets: Array.from({ length: packetCount }, (_, index) => ({
      index, payload, raw_payload: payload, application_payload: payload,
      application_payload_offset: 0, protocol: { status: "unsupported_link_type" },
    })),
    hypotheses: Array.from({ length: hypothesisCount }, (_, index) => ({
      id: `synthetic-${index}`, field_type: "message_type", kind: "message_type",
      packet_id: 0, absolute_offset: index % 8, width_bits: 8, confidence: 0.5,
      evidence: [{ rationale: "synthetic benchmark evidence" }], caveats: ["benchmark only"],
    })),
    analysis: { status: "ok", scope: "application_payload", crc_status: "NOT_RUN" },
    observations: { comparison: { regions: [] } },
    annotations: [],
  };
}

test("renders bounded packet and hypothesis workloads without losing selection", async ({ page }, testInfo) => {
  await page.goto("/");
  const measurements = [];
  for (const packetCount of [100, 1000, 10000]) {
    const measurement = await page.evaluate((value) => {
      const start = performance.now();
      loadResult(value);
      return { render_ms: performance.now() - start, packet_count: value.packets.length, dom_nodes: document.querySelectorAll("*").length };
    }, resultFor(packetCount));
    measurements.push(measurement);
    await expect(page.locator("#packet-select option")).toHaveCount(packetCount);
    await page.locator("#packet-select").selectOption(String(packetCount - 1));
    await expect(page.locator("#packet-select")).toHaveValue(String(packetCount - 1));
  }
  const large = await page.evaluate((value) => {
    const start = performance.now();
    loadResult(value);
    return { render_ms: performance.now() - start, dom_nodes: document.querySelectorAll("*").length };
  }, resultFor(1, 300, 128 * 1024));
  measurements.push({ workload: "large-packet-and-300-hypotheses", ...large });
  await expect(page.locator("#hypotheses-view .hypothesis-card")).toHaveCount(300);
  fs.writeFileSync(testInfo.outputPath("browser-performance.json"), JSON.stringify(measurements, null, 2));
  await testInfo.attach("browser-performance.json", {
    body: Buffer.from(JSON.stringify(measurements, null, 2), "utf8"),
    contentType: "application/json",
  });
});
