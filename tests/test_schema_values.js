const test = require("node:test");
const assert = require("node:assert/strict");

const { apply, validate } = require("../packetscope/static/schema-values.js");

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

test("a false condition is a resolved absence, not an unknown dependency", () => {
  const schema = {
    schema_version: 2,
    coordinate_system: "raw_packet",
    fields: [
      { id: "flag", name: "Flag", type: "uint8", offset: 0, length: 1, endian: "big" },
      { id: "optional", name: "Optional", type: "uint8", offset: 1, length: 1, endian: "big", presence: { op: "eq", args: [{ field: "flag" }, 1] } },
    ],
  };
  const optional = apply(schema, [{ index: 0, raw_payload: "0007" }])[0].fields[1];
  assert.equal(optional.status, "RESOLVED");
  assert.equal(optional.present, false);
  assert.equal(optional.available, false);
  assert.equal(optional.diagnostics[0].code, "conditional_absent");
});

test("schema v2 preserves signed and definition metadata", () => {
  const schema = validate({
    schema_version: 2,
    metadata: { source: "fixture" },
    definitions: {
      header: {
        description: "Reusable header",
        metadata: { reviewed: true },
        fields: [{ name: "version", type: "uint8", offset: 0, length: 1, metadata: { origin: "manual" } }],
      },
    },
    fields: [{ id: "header", name: "Header", type: "struct", definition: "header", offset: 0, metadata: { origin: "manual" } }],
  });
  assert.deepEqual(schema.metadata, { source: "fixture" });
  assert.equal(schema.definitions.header.description, "Reusable header");
  assert.deepEqual(schema.definitions.header.metadata, { reviewed: true });
  assert.equal(schema.fields[0].definition, "header");
  assert.equal(schema.definitions.header.fields[0].metadata.origin, "manual");
  const field = apply(schema, [{ index: 0, raw_payload: "07" }])[0].fields[0];
  assert.equal(field.status, "RESOLVED");
  assert.equal(field.fields[0].value, 7);
});

test("signed int8, int16, and int32 decode with browser integer semantics", () => {
  const schema = validate({
    schema_version: 2,
    fields: [
      { id: "i8", type: "int8", offset: 0, length: 1 },
      { id: "i16", type: "int16", offset: 1, length: 2 },
      { id: "i32", type: "int32", offset: 3, length: 4 },
    ],
  });
  const fields = apply(schema, [{ index: 0, raw_payload: "ff80000080000000" }])[0].fields;
  assert.deepEqual(fields.map((field) => field.value), [-1, -32768, 8388608]);
  assert.ok(fields.every((field) => field.value_encoding === "decimal"));
});

test("numeric, enum, mask, flags, reserved, and exclusion constraints are deterministic", () => {
  const schema = validate({
    schema_version: 2,
    fields: [
      { id: "number", type: "int8", offset: 0, length: 1, constraints: { minimum: -2, maximum: 0, exact: -1 } },
      { id: "enum", type: "uint8", offset: 1, length: 1, constraints: { enum: { values: [1, 2], policy: "diagnostic" } } },
      { id: "bits", type: "uint8", offset: 2, length: 1, constraints: { mask: 7, reserved: 8, flags: { read: 1, write: 2, exec: 4 }, required_flags: ["read"], mutual_exclusion: ["write", "exec"] } },
    ],
  });
  const fields = apply(schema, [{ index: 0, raw_payload: "ff030f" }])[0].fields;
  assert.equal(fields[0].status, "RESOLVED");
  assert.equal(fields[1].status, "RESOLVED");
  assert.equal(fields[1].value, 3);
  assert.deepEqual(fields[1].diagnostics.map((item) => item.code), ["enum_unknown"]);
  assert.equal(fields[2].status, "INVALID");
  assert.deepEqual(fields[2].diagnostics.map((item) => item.code), ["mask", "mutual_exclusion", "reserved"]);
});

test("constraint normalization rejects oversized reviewed value sets", () => {
  assert.throws(() => validate({
    schema_version: 2,
    fields: [{ id: "x", type: "uint8", offset: 0, length: 1, constraints: { allowed: Array.from({ length: 10001 }, (_, index) => index) } }],
  }), /allowed values exceed the limit/);
  assert.throws(() => validate({
    schema_version: 2,
    fields: [{ id: "x", type: "uint8", offset: 0, length: 1, constraints: [] }],
  }), /constraints must be an object/);
});

test("conditional absence, unresolved dependencies, and truncation keep distinct statuses", () => {
  const schema = validate({
    schema_version: 2,
    fields: [
      { id: "gate", type: "uint8", offset: 0, length: 1 },
      { id: "optional", type: "uint8", offset: 1, length: 1, presence: { op: "eq", args: [{ field: "gate" }, 1], }, constraints: { exact: 9 } },
      { id: "truncated", type: "uint8", offset: 2, length: 1, constraints: { minimum: 9 } },
      { id: "dependent", type: "uint8", offset: { field: "truncated" }, length: 1 },
      { id: "unresolved", type: "uint8", offset: { field: "missing" }, length: 1 },
    ],
  });
  const fields = apply(schema, [{ index: 0, raw_payload: "0001" }])[0].fields;
  assert.equal(fields[1].status, "RESOLVED");
  assert.equal(fields[1].present, false);
  assert.equal(fields[1].diagnostics[0].code, "conditional_absent");
  assert.equal(fields[2].status, "OUT_OF_BOUNDS");
  assert.equal(fields[2].diagnostics[0].code, "truncated_field");
  assert.equal(fields[3].status, "OUT_OF_BOUNDS");
  assert.equal(fields[4].status, "INVALID");
  assert.equal(fields[4].diagnostics[0].code, "missing_reference");
});

test("shared Schema V2 parity fixture matches authoritative field results", () => {
  const fixture = require("./fixtures/schema_v2_parity.json");
  const result = apply(validate(fixture.schema), [{ index: 0, raw_payload: fixture.packet_hex }])[0];
  const fields = Object.fromEntries(result.fields.map((field) => [field.id, field]));
  for (const [fieldId, expected] of Object.entries(fixture.expected)) {
    const actual = fields[fieldId];
    assert.equal(actual.status, expected.status, fieldId);
    for (const key of ["value", "present", "offset", "length"]) {
      if (Object.prototype.hasOwnProperty.call(expected, key)) assert.deepEqual(actual[key], expected[key], fieldId);
    }
    assert.deepEqual((actual.diagnostics || []).map((item) => item.code), expected.diagnostic_codes || [], fieldId);
  }
});


test("V1 migration uses the canonical stable field identity", () => {
  const fixture = require("./fixtures/schema_v2_parity.json");
  assert.equal(validate(fixture.v1_schema).fields[0].id, fixture.v1_expected_id);
});
