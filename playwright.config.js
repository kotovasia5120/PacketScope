const { defineConfig } = require("@playwright/test");

module.exports = defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"], ["html", { outputFolder: "test-artifacts/playwright-report", open: "never" }]],
  use: {
    baseURL: "http://127.0.0.1:18765",
    browserName: "chromium",
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    video: "off",
  },
  webServer: {
    command: "python3 -m packetscope.cli serve --host 127.0.0.1 --port 18765",
    url: "http://127.0.0.1:18765/api/health",
    reuseExistingServer: false,
    timeout: 15_000,
  },
  outputDir: "test-artifacts/playwright",
});
