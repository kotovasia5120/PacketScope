const { test, expect } = require("@playwright/test");

// These tests use only deterministic built-in captures.  On failure Playwright
// retains a real Chromium screenshot and trace; console/error text is attached
// without serializing any packet payload.
test.beforeEach(async ({ page }, testInfo) => {
  const consoleLines = [];
  page.on("console", (message) => consoleLines.push(`${message.type()}: ${message.text()}`));
  page.on("pageerror", (error) => consoleLines.push(`pageerror: ${error.name}: ${error.message}`));
  testInfo._packetscopeConsoleLines = consoleLines;
});

test.afterEach(async ({}, testInfo) => {
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
  await page.locator("#demo-profile").selectOption("crc32-le");
  await page.getByRole("button", { name: "Load demo" }).click();
  await expect(page.locator("#crc-view")).toContainText("CRC-32");
  await expect(page.locator("#hypotheses-view")).toContainText(/counter/i);
  await page.screenshot({ path: testInfo.outputPath("demo-crc32-real-browser.png"), fullPage: true });
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
  await page.locator("#project-file").setInputFiles(projectPath);
  await expect(page.locator("#status")).toContainText("Restored saved project");
  await expect(page.locator("#annotations-view")).toContainText("confirmed header");
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
