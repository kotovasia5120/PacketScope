const { test, expect } = require("@playwright/test");

test("applies bounded Schema V2 values, nesting, arrays, and diagnostics", async ({ page }) => {
  await page.goto("/");
  await page.locator("#packet-file").setInputFiles({
    name: "schema-v2.bin",
    mimeType: "application/octet-stream",
    buffer: Buffer.from([3, 0x61, 0x62, 0x63, 7, 8, 9, 0x11, 0x22]),
  });
  await page.getByRole("button", { name: "Analyze locally" }).click();
  await expect(page.locator("#status")).toContainText("Analyzed 1 packet");
  await page.getByRole("button", { name: "Fields" }).click();

  const schema = {
    schema_version: 2,
    name: "V2 first slice",
    coordinate_system: "raw_packet",
    fields: [
      { id: "length", name: "Length", description: "payload size", type: "uint8", offset: 0, length: 1, endian: "big" },
      { id: "payload", name: "Payload", type: "bytes", offset: 1, length: { field: "length" } },
      { id: "optional", name: "Optional", type: "uint8", offset: { field: "length", add: 1 }, length: 1, endian: "big", presence: { op: "eq", args: [{ field: "length" }, 3] } },
      { id: "items", name: "Items", type: "array", offset: 5, array: { count: 2, element: { type: "uint8", length: 1, endian: "big" } } },
      { id: "nested", name: "Nested", type: "struct", offset: 7, fields: [{ id: "child", name: "Child", type: "uint8", offset: 0, length: 1, endian: "big" }, { id: "child2", name: "Child 2", type: "uint8", offset: 1, length: 1, endian: "big" }] },
    ],
  };
  await page.locator("#schema-file").setInputFiles({ name: "v2.schema.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(schema)) });
  await expect(page.locator("#status")).toContainText("Applied protocol schema to 1 packet");
  await expect(page.locator("#fields-view")).toContainText("Applied schema: V2 first slice");
  await expect(page.locator("#fields-view")).toContainText("V2");
  await expect(page.locator("#fields-view")).toContainText("Items[0]");
  await expect(page.locator("#fields-view")).toContainText("Child");
  await expect(page.locator("#fields-view")).toContainText("RESOLVED");

  const invalidSchema = { schema_version: 2, fields: [{ id: "bad", name: "Bad", type: "bytes", offset: { field: "missing" }, length: 1 }] };
  await page.locator("#schema-file").setInputFiles({ name: "invalid-reference.schema.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(invalidSchema)) });
  await expect(page.locator("#fields-view")).toContainText("INVALID");
  await expect(page.locator("#fields-view")).toContainText("missing_reference");
});

test("edits structured constraints and validates an independent capture", async ({ page }) => {
  await page.goto("/");
  await page.locator("#packet-file").setInputFiles({
    name: "constraint-editor.bin",
    mimeType: "application/octet-stream",
    buffer: Buffer.from([5]),
  });
  await page.getByRole("button", { name: "Analyze locally" }).click();
  await expect(page.locator("#status")).toContainText("Analyzed 1 packet");
  await page.getByRole("button", { name: "Fields" }).click();
  await page.getByRole("button", { name: "Open schema editor" }).click();

  await page.locator("#schema-editor-id").fill("value");
  await page.locator("#schema-editor-name").fill("Value");
  await page.locator("#schema-editor-type").selectOption("uint8");
  await page.locator("#schema-editor-offset").fill("0");
  await page.locator("#schema-editor-width").fill("1");
  await page.locator("#schema-editor-minimum").fill("2");
  await page.locator("#schema-editor-maximum").fill("10");
  await page.locator("#schema-editor-enum").fill("[5, 6, 7]");
  await page.locator("#schema-editor-enum-policy").selectOption("diagnostic");
  await page.locator("#schema-editor-allowed").fill("[5, 6, 7]");
  await page.locator("#schema-editor-forbidden").fill("[0]");
  await page.locator("#schema-editor-mask").fill("7");
  await page.locator("#schema-editor-reserved").fill("[3]");
  await page.locator("#schema-editor-required-flags").fill("[1]");
  await page.locator("#schema-editor-forbidden-flags").fill("[8]");
  await page.locator("#schema-editor-constraints-json").fill('{"width_bits":8}');
  await page.getByRole("button", { name: "Add field", exact: true }).click();
  await expect(page.locator("#status")).toContainText("Schema field saved");
  await page.getByRole("button", { name: "Apply reviewed schema" }).click();
  await expect(page.locator("#status")).toContainText("Applied reviewed schema");
  await expect(page.locator("#schema-editor-fields")).toContainText("constraint(s)");

  const independent = [
    '{"index":0,"timestamp":0,"direction":"rx","source":"fixture","raw":"BQ=="}',
    '{"index":1,"timestamp":1,"direction":"rx","source":"fixture","raw":"AQ=="}',
    '{"index":2,"timestamp":2,"direction":"rx","source":"fixture","raw":""}',
  ].join("\n");
  await page.locator("#schema-validation-file").setInputFiles({ name: "independent.jsonl", mimeType: "application/jsonl", buffer: Buffer.from(independent) });
  await page.locator("#schema-validation-format").selectOption("jsonl");
  await page.getByRole("button", { name: "Run validation" }).click();
  await expect(page.locator("#schema-validation-status")).toContainText("Validation complete");
  await expect(page.locator("#schema-validation-scope")).toContainText("Whole capture");
  await expect(page.locator("#schema-validation-summary")).toContainText("1/3 packet");
  await expect(page.locator("#independent-schema-validation-report")).toContainText(/fully validated/i);
  await expect(page.locator("#independent-schema-validation-report")).toContainText("Packet 0");
  await expect(page.locator("#independent-schema-validation-report")).toContainText("Packet 1");
  await expect(page.locator("#independent-schema-validation-report")).toContainText("Packet 2");
  await expect(page.locator("#independent-schema-validation-report")).toContainText(/minimum|truncated_field/i);
});
