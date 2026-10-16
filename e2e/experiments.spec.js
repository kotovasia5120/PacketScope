const fs = require("fs");
const { test, expect } = require("@playwright/test");

test.beforeEach(async ({ page }, testInfo) => {
  const errors = [];
  page.on("pageerror", (error) => errors.push(`${error.name}: ${error.message}`));
  page.on("response", (response) => { if (response.status() >= 500) errors.push(`${response.request().method()} ${response.url()} HTTP ${response.status()}`); });
  testInfo._experimentErrors = errors;
});

test.afterEach(async ({}, testInfo) => {
  expect(testInfo._experimentErrors || []).toEqual([]);
});

test("runs, reviews, annotates, exports, and restores a controlled experiment", async ({ page }, testInfo) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Open Experiments" }).click();
  await page.locator("#experiment-baseline-file").setInputFiles({ name: "baseline.bin", mimeType: "application/octet-stream", buffer: Buffer.from([0xaa, 0x01, 0x10]) });
  await page.locator("#experiment-changed-file").setInputFiles({ name: "changed.bin", mimeType: "application/octet-stream", buffer: Buffer.from([0xaa, 0x01, 0x20]) });
  await page.getByRole("button", { name: "Load captures" }).click();
  await expect(page.locator("#experiment-status")).toContainText("Loaded 1 baseline packet");
  await page.locator("#experiment-change-label").fill("device setting changed");
  await page.getByRole("button", { name: "Run experiment" }).click();
  await expect(page.locator("#experiment-status")).toContainText("Experiment complete");
  await expect(page.locator(".experiment-region").first()).toContainText("0x2");
  await expect(page.locator("#experiment-evidence")).toContainText(/baseline|P0/i);
  await expect(page.locator("#experiment-hex-baseline")).toContainText("10");
  await expect(page.locator("#experiment-hex-changed")).toContainText("20");
  await page.getByRole("button", { name: "Promote selected range" }).click();
  await page.locator("#experiment-annotation-label").fill("candidate setting byte");
  await page.getByRole("button", { name: "Save annotation", exact: true }).click();
  await expect(page.locator("#experiment-annotations")).toContainText("candidate setting byte");

  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export experiment report" }).click();
  const download = await downloadPromise;
  const reportPath = testInfo.outputPath("experiment-report.json");
  await download.saveAs(reportPath);
  await page.reload();
  await page.getByRole("button", { name: "Open Experiments" }).click();
  await page.locator("#experiment-restore-file").setInputFiles(reportPath);
  await expect(page.locator("#experiment-status")).toContainText("Restored experiment report");
  await expect(page.locator("#experiment-annotations")).toContainText("candidate setting byte");
  await expect(page.locator("#experiment-status")).toContainText("source captures again");
});

test("loads independent flow options for two PCAP captures", async ({ page }) => {
  const fixture = fs.readFileSync("tests/fixtures/phase6_multiflow.pcap");
  const changed = Buffer.from(fixture);
  const marker = Buffer.from("tcp-v4-a3");
  const markerOffset = changed.indexOf(marker);
  changed.write("tcp-v4-z3", markerOffset, "ascii");
  const flowId = "ipv4/tcp/192.0.2.30:8000<->192.0.2.40:9000";
  await page.goto("/");
  await page.getByRole("button", { name: "Open Experiments" }).click();
  await page.locator("#experiment-baseline-file").setInputFiles({ name: "baseline.pcap", mimeType: "application/vnd.tcpdump.pcap", buffer: fixture });
  await page.locator("#experiment-changed-file").setInputFiles({ name: "changed.pcap", mimeType: "application/vnd.tcpdump.pcap", buffer: changed });
  await page.locator("#experiment-baseline-format").selectOption("pcap");
  await page.locator("#experiment-changed-format").selectOption("pcap");
  await page.getByRole("button", { name: "Load captures" }).click();
  await expect(page.locator("#experiment-baseline-flow option")).toHaveCount(5);
  await page.locator("#experiment-baseline-flow").selectOption(flowId);
  await page.locator("#experiment-changed-flow").selectOption(flowId);
  await page.locator("#experiment-baseline-direction").selectOption("forward");
  await page.locator("#experiment-changed-direction").selectOption("reverse");
  await page.getByRole("button", { name: "Run experiment" }).click();
  await expect(page.locator("#experiment-status")).toContainText("Experiment complete");
  await expect(page.locator("#experiment-provenance")).toContainText("baseline.pcap");
});

test("constructs and validates a reviewed schema in the browser", async ({ page }, testInfo) => {
  await page.goto("/");
  await page.locator("#packet-file").setInputFiles({ name: "schema.bin", mimeType: "application/octet-stream", buffer: Buffer.from([0xaa, 0x01, 0x02, 0x03]) });
  await page.getByRole("button", { name: "Analyze locally" }).click();
  await expect(page.locator("#status")).toContainText("Analyzed 1 packet");
  await page.getByRole("button", { name: "Fields" }).click();
  await page.getByRole("button", { name: "Open schema editor" }).click();
  await page.locator("#schema-editor-name").fill("reviewed header");
  await page.locator("#schema-editor-type").selectOption("custom");
  await page.locator("#schema-editor-offset").fill("0");
  await page.locator("#schema-editor-width").fill("1");
  await page.getByRole("button", { name: "Add field", exact: true }).click();
  await page.getByRole("button", { name: "Apply reviewed schema" }).click();
  await expect(page.locator("#status")).toContainText("Applied reviewed schema");
  const kaitaiDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export Kaitai .ksy" }).click();
  await (await kaitaiDownload).saveAs(testInfo.outputPath("reviewed.schema.ksy"));
  const luaDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export Wireshark Lua" }).click();
  await (await luaDownload).saveAs(testInfo.outputPath("reviewed.dissector.lua"));
  await page.getByRole("button", { name: "Validate current capture" }).click();
  await expect(page.locator("#status")).toContainText("Schema validation complete");
  await expect(page.locator("#schema-validation")).toContainText("1/1 packet");
});
