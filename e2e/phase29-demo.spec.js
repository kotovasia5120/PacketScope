const { test, expect } = require("@playwright/test");

const capture = [
  '{"direction":"forward","index":0,"raw":"UFgQBQAACAEgAAByZXF1ZXN0AEVN","source":"phase29-device","timestamp":1700200000}',
  '{"direction":"reverse","index":1,"raw":"UFiQAgBlCQIgEQAhEgByZXNwb25zZQHgWg==","source":"phase29-device","timestamp":1700200001}',
  '{"direction":"forward","index":2,"raw":"UFgQAQACCAMgIgAhIwAiJAByZXF1ZXN0AkaR","source":"phase29-device","timestamp":1700200002}',
  '{"direction":"reverse","index":3,"raw":"UFiQBgBnCQEgMwByZXNwb25zZQO2Tw==","source":"phase29-device","timestamp":1700200003}',
  '{"direction":"forward","index":4,"raw":"UFgQAQAECAIgRAAhRQByZXF1ZXN0BCzF","source":"phase29-device","timestamp":1700200004}',
  '{"direction":"reverse","index":5,"raw":"UFiQAgBpCQMgVQAhVgAiVwByZXNwb25zZQU=","source":"phase29-device","timestamp":1700200005}',
].join("\n") + "\n";

const reviewedSchema = {
  schema_version: 2,
  name: "Phase 29 request response protocol",
  coordinate_system: "raw_packet",
  fields: [
    { id: "magic", type: "bytes", offset: 0, length: 2, constraints: { exact: "5058" } },
    { id: "message_type", type: "uint8", offset: 2, length: 1, endian: "big", constraints: { enum: { values: [16, 144], names: { "16": "request", "144": "response" } } } },
    { id: "flags", type: "uint8", offset: 3, length: 1, endian: "big", constraints: { flags: { request: 1, response: 2, has_extension: 4 } } },
    { id: "sequence", type: "uint16", offset: 4, length: 2, endian: "big" },
    { id: "payload_length", type: "uint8", offset: 6, length: 1, endian: "big" },
    { id: "record_count", type: "uint8", offset: 7, length: 1, endian: "big" },
    { id: "records", type: "array", offset: 8, array: { count: { field: "record_count" }, max_items: 4, element: { id: "record", type: "struct", offset: 0, fields: [
      { id: "record_id", type: "uint8", offset: 0, length: 1, endian: "big" },
      { id: "record_value", type: "uint16", offset: 1, length: 2, endian: "little" },
    ] } } },
    { id: "payload", type: "bytes", offset: { op: "add", args: [8, { op: "multiply", args: [{ field: "record_count" }, 3] }] }, length: { field: "payload_length" } },
    { id: "crc", type: "crc", offset: { op: "add", args: [{ op: "add", args: [8, { op: "multiply", args: [{ field: "record_count" }, 3] }] }, { field: "payload_length" }] }, length: 2, endian: "big" },
  ],
  relationships: [
    { id: "payload-length", kind: "length", field_id: "payload_length", target_field_id: "payload" },
    { id: "message-crc", kind: "checksum", field_id: "crc", algorithm: "CRC-16/CCITT-FALSE", byte_order: "big" },
  ],
};

test("runs the deterministic request-response investigation and preserves validation evidence", async ({ page }, testInfo) => {
  await page.goto("/");
  await page.locator("#packet-file").setInputFiles({ name: "phase29.jsonl", mimeType: "application/jsonl", buffer: Buffer.from(capture) });
  await page.getByRole("button", { name: "Analyze locally" }).click();
  await expect(page.locator("#status")).toContainText(/Analyzed 6 packet/);

  await page.getByRole("button", { name: "Fields" }).click();
  await page.locator("#schema-file").setInputFiles({ name: "phase29-reviewed.schema.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(reviewedSchema)) });
  await expect(page.locator("#status")).toContainText(/Applied protocol schema|Applied reviewed schema/);
  await expect(page.locator("#fields-view")).toContainText("Phase 29 request response protocol");
  await expect(page.locator("#fields-view")).toContainText("records[0]");

  await page.locator("#schema-validation-file").setInputFiles({ name: "phase29-independent.jsonl", mimeType: "application/jsonl", buffer: Buffer.from(capture) });
  await page.locator("#schema-validation-format").selectOption("jsonl");
  await page.getByRole("button", { name: "Run validation" }).click();
  await expect(page.locator("#schema-validation-status")).toContainText("Validation complete");
  await expect(page.locator("#independent-schema-validation-report")).toContainText(/4\/6 packet/);
  await expect(page.locator("#independent-schema-validation-report")).toContainText("VIOLATED");
  await expect(page.locator("#independent-schema-validation-report")).toContainText("INCOMPLETE");
  await expect(page.locator("#independent-schema-validation-report")).toContainText(/fully validated/i);

  await page.getByRole("button", { name: "Overview", exact: true }).click();
  const projectDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export JSON" }).click();
  const projectPath = testInfo.outputPath("phase29-project.json");
  await (await projectDownload).saveAs(projectPath);
  await page.locator("#project-file").setInputFiles(projectPath);
  await expect(page.locator("#status")).toContainText("Restored saved project");
});
