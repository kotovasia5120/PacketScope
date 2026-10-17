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

test("builds a nested reusable dynamic protocol through the Schema Workbench", async ({ page }, testInfo) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Load demo" }).click();
  await page.getByRole("button", { name: "Fields" }).click();
  await page.getByRole("button", { name: "Open schema editor" }).click();

  const addField = async ({ id, name, type = "uint8", offset = "0", width = "1", array = false, countReference = "", conditionReference = "", conditionValue = "1" }) => {
    await page.locator("#schema-editor-id").fill(id);
    await page.locator("#schema-editor-name").fill(name);
    await page.locator("#schema-editor-type").selectOption(type);
    await page.locator("#schema-editor-offset").fill(offset);
    await page.locator("#schema-editor-width").fill(width);
    if (array) {
      await page.locator("#schema-editor-array").check();
      await page.locator("#schema-editor-array-type").selectOption("uint8");
      await page.locator("#schema-editor-array-length").fill("1");
      await page.locator("#schema-editor-array-count-reference").selectOption(countReference);
    }
    if (conditionReference) {
      await page.locator("#schema-editor-condition-reference").selectOption(conditionReference);
      await page.locator("#schema-editor-condition-value").fill(conditionValue);
    }
    await page.locator("#schema-editor-form").getByRole("button", { name: "Add field", exact: true }).click();
  };

  await page.locator("#schema-editor-definition-name").fill("record");
  await page.getByRole("button", { name: "Add definition" }).click();
  await expect(page.locator("#schema-editor-definitions")).toContainText("record");
  await page.getByRole("button", { name: "Add field to scope" }).click();
  await addField({ id: "record-type", name: "RecordType" });
  await addField({ id: "record-value", name: "Value", type: "bytes", offset: "1", width: "1" });

  await page.getByRole("button", { name: "Open root protocol", exact: true }).click();
  await addField({ id: "header", name: "Header", type: "struct", offset: "0", width: "2" });
  await page.locator("#schema-editor-tree").getByRole("button", { name: "Add child", exact: true }).click();
  await addField({ id: "magic", name: "Magic", type: "uint16", offset: "0", width: "2" });
  await page.getByRole("button", { name: "Open root protocol", exact: true }).click();
  await addField({ id: "flags", name: "Flags", offset: "2" });
  await addField({ id: "record-count", name: "RecordCount", offset: "3" });
  await addField({ id: "records", name: "Records", type: "array", offset: "4", width: "2", array: true, countReference: "record-count" });
  await addField({ id: "metadata", name: "OptionalMetadata", type: "bytes", offset: "6", width: "1", conditionReference: "flags", conditionValue: "1" });
  await addField({ id: "crc", name: "CRC16", type: "crc", offset: "7", width: "1" });

  await page.locator("#schema-rel-kind").selectOption("checksum");
  await page.locator("#schema-rel-field").selectOption("crc");
  await page.locator("#schema-rel-algorithm").selectOption("CRC-8");
  await page.locator("#schema-rel-include").fill("[[0, 8]]");
  await page.locator("#schema-rel-exclude").fill("[[7, 8]]");
  await page.getByRole("button", { name: "Add relationship" }).click();
  await expect(page.locator("#schema-editor-relationships")).toContainText("relationship");

  await page.getByRole("button", { name: "Apply reviewed schema" }).click();
  await expect(page.locator("#status")).toContainText(/Applied reviewed schema|Schema is not valid/);
  await expect(page.locator("#schema-editor-dependencies")).toContainText("record-count");

  const schemaDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export exact V2 JSON" }).click();
  const schemaPath = testInfo.outputPath("nested.schema-v2.json");
  await (await schemaDownload).saveAs(schemaPath);
  const authored = JSON.parse(require("fs").readFileSync(schemaPath, "utf8"));
  expect(authored.definitions.record.fields).toHaveLength(2);
  expect(authored.fields.find((field) => field.id === "records").array.count).toEqual({ field: "record-count" });
  expect(authored.relationships).toHaveLength(1);

  await page.getByRole("button", { name: "Overview", exact: true }).click();
  const projectDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export JSON" }).click();
  const projectPath = testInfo.outputPath("nested-project.json");
  await (await projectDownload).saveAs(projectPath);
  await page.locator("#project-file").setInputFiles(projectPath);
  await expect(page.locator("#status")).toContainText("Restored saved project");
  await expect(page.locator("#schema-editor-tree")).toContainText("Records");
});
