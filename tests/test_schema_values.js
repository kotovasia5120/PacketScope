const test = require("node:test");
const assert = require("node:assert/strict");

const { apply } = require("../packetscope/static/schema-values.js");

test("schema values preserve UINT32, UINT64, and INT64 boundaries", () => {
  const payload = "ff".repeat(24) + "80" + "00".repeat(7) + "00".repeat(7) + "80";
  const packet = {
    index: 0,
    raw_payload: payload,
    application_payload: payload,
  };
  const schema = {
    schema_version: 1,
    coordinate_system: "raw_packet",
    fields: [
      { name: "u32 big", type: "UINT32", offset: 0, width: 4, endian: "big" },
      { name: "u32 little", type: "UINT32", offset: 4, width: 4, endian: "little" },
      { name: "u64 big", type: "UINT64", offset: 8, width: 8, endian: "big" },
      { name: "u64 little", type: "UINT64", offset: 16, width: 8, endian: "little" },
      { name: "i64 big", type: "INT64", offset: 24, width: 8, endian: "big" },
      { name: "i64 little", type: "INT64", offset: 32, width: 8, endian: "little" },
    ],
  };
  const fields = apply(schema, [packet])[0].fields;
  assert.deepEqual(fields.map((field) => field.value), [
    "4294967295", "4294967295", "18446744073709551615", "18446744073709551615",
    "-9223372036854775808", "-9223372036854775808",
  ]);
  assert.ok(fields.every((field) => typeof field.value === "string"));
  assert.ok(fields.every((field) => field.value_encoding === "decimal_string"));
});

test("schema application returns null for unavailable or truncated values", () => {
  const schema = {
    schema_version: 1,
    coordinate_system: "application_payload",
    fields: [{ name: "missing", offset: 0, width: 2, endian: "big" }],
  };
  const unavailable = apply(schema, [{ index: 0, raw_payload: "aabb", application_payload_available: false }])[0].fields[0];
  assert.equal(unavailable.available, false);
  assert.equal(unavailable.value, null);
  const truncated = apply(schema, [{ index: 1, application_payload: "aa" }])[0].fields[0];
  assert.equal(truncated.available, false);
  assert.equal(truncated.value, null);
});
