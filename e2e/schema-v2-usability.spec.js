const { test, expect } = require("@playwright/test");

test("undoes and redoes Schema V2 field lifecycle changes while keeping IDs stable", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Load demo" }).click();
  await page.getByRole("button", { name: "Fields" }).click();
  await page.getByRole("button", { name: "Open schema editor" }).click();

  await page.locator("#schema-editor-id").fill("stable-length");
  await page.locator("#schema-editor-name").fill("Length");
  await page.locator("#schema-editor-type").selectOption("uint8");
  await page.locator("#schema-editor-offset").fill("0");
  await page.locator("#schema-editor-width").fill("1");
  await page.getByRole("button", { name: "Add field", exact: true }).click();
  await expect(page.locator("#schema-editor-fields")).toContainText("Length · stable-length");
  await expect(page.locator("#schema-editor-undo")).toBeEnabled();

  await page.getByRole("button", { name: "Undo", exact: true }).click();
  await expect(page.locator("#schema-editor-fields")).toContainText("No reviewed fields yet.");
  await page.getByRole("button", { name: "Redo", exact: true }).click();
  await expect(page.locator("#schema-editor-fields")).toContainText("Length · stable-length");

  await page.getByRole("button", { name: "Edit", exact: true }).click();
  await page.locator("#schema-editor-name").fill("Payload length");
  await page.locator("#schema-editor-minimum").fill("1");
  await page.getByRole("button", { name: "Add field", exact: true }).click();
  await expect(page.locator("#schema-editor-fields")).toContainText("Payload length · stable-length");
  await expect(page.locator("#schema-editor-fields")).toContainText("1 constraint(s)");

  await page.keyboard.press("Control+z");
  await expect(page.locator("#schema-editor-fields")).toContainText("Length · stable-length");
  await expect(page.locator("#schema-editor-fields")).not.toContainText("Payload length");
  await page.keyboard.press("Control+y");
  await expect(page.locator("#schema-editor-fields")).toContainText("Payload length · stable-length");
  await expect(page.locator("#schema-editor-fields")).toContainText("1 constraint(s)");

  await page.getByRole("button", { name: "Remove", exact: true }).click();
  await expect(page.locator("#schema-editor-fields")).toContainText("No reviewed fields yet.");
  await page.getByRole("button", { name: "Undo", exact: true }).click();
  await expect(page.locator("#schema-editor-fields")).toContainText("Payload length · stable-length");
  const field = await page.evaluate(() => state.schema.fields[0]);
  expect(field.id).toBe("stable-length");
  expect(field.constraints.minimum).toBe("1");
});

test("creates a Schema V2 field from a HEX range beyond the rendered window", async ({ page }) => {
  await page.goto("/");
  await page.evaluate(() => loadResult({
    schema_version: 2,
    source: { name: "large-selection.bin", format: "bin", packet_count: 1, byte_count: 12000 },
    packets: [{ index: 0, payload: "aa".repeat(12000), application_payload: "aa".repeat(12000), raw_payload: "aa".repeat(12000), application_payload_offset: 0, protocol: { status: "unsupported_link_type" } }],
    hypotheses: [],
    analysis: { status: "ok", scope: "application_payload", crc_status: "NOT_RUN" },
    observations: { comparison: { regions: [] } },
    annotations: [],
  }));
  await expect(page.locator("#packet-select")).toHaveValue("0");
  await expect(page.locator("#hex-view .hex-line")).toHaveCount(512);

  await page.locator("#hex-selection-offset").fill("0x2345");
  await page.locator("#hex-selection-width").fill("4");
  await page.getByRole("button", { name: "Select byte range" }).click();
  await expect(page.locator("#hex-selection-status")).toContainText("Packet 0 · application_payload · offset 0x2345 · 4 byte(s)");
  await expect(page.locator("#hex-view .hex-selection")).toHaveCount(8);

  await page.getByRole("button", { name: "Create field from selection" }).click();
  await expect(page.locator("#schema-editor")).toBeVisible();
  await expect(page.locator("#schema-editor-selection-source")).toContainText("Packet 0 · application_payload · offset 0x2345 · 4 byte(s)");
  await expect(page.locator("#schema-editor-offset")).toHaveValue("9029");
  await expect(page.locator("#schema-editor-width")).toHaveValue("4");
  await expect(page.locator("#schema-editor-type")).toHaveValue("bytes");

  await page.getByRole("button", { name: "Add field", exact: true }).click();
  const field = await page.evaluate(() => state.schema.fields[0]);
  expect(field.coordinate_system).toBe("application_payload");
  expect(field.offset).toBe(9029);
  expect(field.length).toBe(4);
  expect(field.metadata.source_packet_index).toBe(0);
  expect(field.metadata.source_offset).toBe(9029);
  expect(field.metadata.source_width).toBe(4);
});
