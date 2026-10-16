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
