const { test, expect } = require("@playwright/test");

// These tests use only deterministic built-in captures.  On failure Playwright
// retains a real Chromium screenshot and trace; console/error text is attached
// without serializing any packet payload.
test.beforeEach(async ({ page }, testInfo) => {
  const consoleLines = [];
  const pageErrors = [];
  const httpFailures = [];
  page.on("console", (message) => consoleLines.push(`${message.type()}: ${message.text()}`));
  page.on("pageerror", (error) => { pageErrors.push(`${error.name}: ${error.message}`); consoleLines.push(`pageerror: ${error.name}: ${error.message}`); });
  page.on("requestfailed", (request) => { httpFailures.push(`${request.method()} ${request.url()} ${request.failure()?.errorText || "failed"}`); });
  page.on("response", (response) => { if (response.status() >= 500) httpFailures.push(`${response.request().method()} ${response.url()} HTTP ${response.status()}`); });
  testInfo._packetscopeConsoleLines = consoleLines;
  testInfo._packetscopePageErrors = pageErrors;
  testInfo._packetscopeHttpFailures = httpFailures;
});

test.afterEach(async ({}, testInfo) => {
  expect(testInfo._packetscopePageErrors || []).toEqual([]);
  expect(testInfo._packetscopeHttpFailures || []).toEqual([]);
  await testInfo.attach("browser-console.txt", {
    body: Buffer.from((testInfo._packetscopeConsoleLines || []).join("\n"), "utf8"),
    contentType: "text/plain",
  });
});

test("opens, navigates, and completes both deterministic demo investigations", async ({ page }, testInfo) => {
  await page.goto("/");
  await expect(page).toHaveTitle(/PacketScope/);
  await expect(page.locator("#status")).toContainText("Ready");
  await page.getByRole("button", { name: "Load demo" }).click();
  await expect(page.locator("#summary-grid")).toContainText("8");
  await expect(page.locator("#hypotheses-view .hypothesis-card").first()).toBeVisible();
  await page.getByRole("button", { name: "Compare" }).click();
  await page.locator("#compare-select").selectOption(["0", "1", "2"]);
  await expect(page.locator("#compare-status")).toContainText("3 packets");
  await page.getByRole("button", { name: "Next diff" }).click();
  await page.getByRole("button", { name: "Fields" }).click();
  await expect(page.locator("#fields-view")).toContainText(/counter|length/i);
  await page.getByRole("button", { name: "CRC" }).click();
  await expect(page.locator("#crc-view")).toContainText("CRC-16");
  await page.getByRole("button", { name: "Overview" }).click();
  await page.getByRole("button", { name: "Evaluate reference" }).click();
  await expect(page.locator("#evaluation-view")).toContainText(/precision.*recall.*F1/i);
  await page.locator("#demo-profile").selectOption("crc32-le");
  await page.getByRole("button", { name: "Load demo" }).click();
  await expect(page.locator("#crc-view")).toContainText("CRC-32");
  await expect(page.locator("#hypotheses-view")).toContainText(/counter/i);
  await page.getByRole("button", { name: "Evaluate reference" }).click();
  await expect(page.locator("#evaluation-view")).toContainText(/F1/i);
  await page.screenshot({ path: testInfo.outputPath("demo-crc32-real-browser.png"), fullPage: true });
});

test("downloads, reimports, and reanalyzes a multi-flow capture by scope", async ({ page }, testInfo) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Load demo" }).click();
  const pcapDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download PCAP", exact: true }).click();
  const pcap = await pcapDownload;
  const pcapPath = testInfo.outputPath("crc16-demo.pcap");
  await pcap.saveAs(pcapPath);
  const pcapngDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download PCAPNG", exact: true }).click();
  const pcapng = await pcapngDownload;
  await pcapng.saveAs(testInfo.outputPath("crc16-demo.pcapng"));
  await page.locator("#packet-file").setInputFiles(pcapPath);
  await page.locator("#format").selectOption("pcap");
  await page.getByRole("button", { name: "Analyze locally" }).click();
  await expect(page.locator("#status")).toContainText(/Analyzed 8 packet/);
  await page.locator("#packet-file").setInputFiles("tests/fixtures/phase6_multiflow.pcap");
  await page.locator("#format").selectOption("pcap");
  await page.getByRole("button", { name: "Analyze locally" }).click();
  await expect(page.locator("#status")).toContainText(/Analyzed 10 packet/);
  await expect(page.locator("#flow-analysis-mode")).toContainText(/heterogeneous/i);
  await expect(page.locator("#flow-select option")).toHaveCount(5);
  const tcpFlow = "ipv4/tcp/192.0.2.30:8000<->192.0.2.40:9000";
  await page.locator("#flow-select").selectOption(tcpFlow);
  await expect(page.locator("#flow-analysis-mode")).toContainText("Analysis pending");
  await expect(page.locator("#status")).toContainText("Analysis scope updated");
  await expect(page.locator("#packet-select option")).toHaveCount(3);
  await expect(page.locator("#hypotheses-view")).toContainText(/magic|message|CRC/i);
  await page.locator("#direction-select").selectOption("reverse");
  await expect(page.locator("#status")).toContainText("Analysis scope updated");
  await expect(page.locator("#packet-select option")).toHaveCount(1);
  await expect(page.locator("#hypotheses-view")).toContainText("No candidate");
  await page.screenshot({ path: testInfo.outputPath("multiflow-reanalysis.png"), fullPage: true });
});

test("supports HEX interaction and project persistence", async ({ page }, testInfo) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Load demo" }).click();
  await expect(page.locator("#hex-view .hex-line").first()).toBeVisible();
  await page.locator("#hypotheses-view .hypothesis-card").first().click();
  await expect(page.locator("#hex-view .byte-hit").first()).toBeVisible();
  await page.locator("#payload-mode").selectOption("raw");
  await page.locator("#offset-search").fill("0x0");
  await page.getByRole("button", { name: "Go" }).click();
  await expect(page.locator("#status")).toContainText("0x0");
  await page.locator("#annotation-label").fill("confirmed header");
  await page.locator("#annotation-start").fill("0");
  await page.getByRole("button", { name: "Add annotation" }).click();
  await expect(page.locator("#annotations-view")).toContainText("confirmed header");
  await page.keyboard.press("Control+z");
  await expect(page.locator("#annotations-view")).not.toContainText("confirmed header");
  await page.keyboard.press("Control+y");
  await expect(page.locator("#annotations-view")).toContainText("confirmed header");

  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export JSON" }).click();
  const download = await downloadPromise;
  const projectPath = testInfo.outputPath("restored-project.json");
  await download.saveAs(projectPath);
  const beforeSummary = await page.locator("#summary-grid").innerText();
  await page.reload();
  await expect(page.locator("#status")).toContainText("Ready");
  await page.locator("#project-file").setInputFiles(projectPath);
  await expect(page.locator("#status")).toContainText("Restored saved project");
  await expect(page.locator("#annotations-view")).toContainText("confirmed header");
  const restoredSummary = await page.locator("#summary-grid").innerText();
  expect(restoredSummary.replace(/\s+/g, "")).toBe(beforeSummary.replace(/\s+/g, ""));
});

test("reports invalid project input without a page exception", async ({ page }) => {
  await page.goto("/");
  await page.locator("#project-file").setInputFiles({
    name: "invalid.json",
    mimeType: "application/json",
    buffer: Buffer.from(JSON.stringify({ schema_version: 999 })),
  });
  await expect(page.locator("#status")).toContainText("not valid");
  await expect(page.locator("#status")).toHaveClass(/error/);
});
