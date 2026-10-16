/* Shared, dependency-free schema application for the browser and Node tests.
 *
 * Schema V2 is a small data language.  The evaluator below deliberately has
 * no dynamic code path: expressions are evaluated by an explicit allow-list
 * and every result carries a bounded, inspectable status and diagnostics.
 * V1 is migrated to V2 at the boundary, while the value shape keeps the V1
 * fields used by the existing browser UI (`available`, `value_encoding`, and
 * `packetId`).
 */
(function (root, factory) {
  const api = factory();
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.PacketScopeSchema = api;
})(typeof globalThis !== "undefined" ? globalThis : this, () => {
  const COORDINATE_SYSTEMS = new Set(["raw_packet", "application_payload"]);
  const STATUS = new Set(["RESOLVED", "UNKNOWN", "UNAVAILABLE", "INVALID", "CYCLIC", "OUT_OF_BOUNDS", "LIMIT_EXCEEDED"]);
  const DEFAULT_BUDGETS = Object.freeze({
    max_packets: 100000,
    max_fields: 1000,
    max_array_items: 10000,
    max_total_array_items: 100000,
    max_bytes_per_packet: 16 * 1024 * 1024,
    max_field_length: 16 * 1024 * 1024,
    max_expression_depth: 32,
    max_expression_value: 2 ** 31,
    max_nesting: 16,
    max_output_fields: 100000,
  });
  const INTEGER_WIDTHS = Object.freeze({
    u8: [1, false], uint8: [1, false], byte: [1, false],
    u16: [2, false], uint16: [2, false],
    u32: [4, false], uint32: [4, false],
    u64: [8, false], uint64: [8, false],
    u128: [16, false], uint128: [16, false],
    i8: [1, true], int8: [1, true],
    i16: [2, true], int16: [2, true],
    i32: [4, true], int32: [4, true],
    i64: [8, true], int64: [8, true],
    i128: [16, true], int128: [16, true],
  });
  const OP_ALIASES = Object.freeze({
    plus: "add", equal: "eq", equals: "eq", not_equal: "ne",
    less_than: "lt", less_equal: "lte", greater_than: "gt", greater_equal: "gte",
    le: "lte", ge: "gte", "==": "eq", "!=": "ne", "<": "lt", "<=": "lte", ">": "gt", ">=": "gte",
  });
  const ALLOWED_OPS = new Set(["add", "eq", "ne", "lt", "lte", "gt", "gte"]);
  const STATUS_PRIORITY = Object.freeze({ RESOLVED: 0, UNKNOWN: 1, UNAVAILABLE: 2, OUT_OF_BOUNDS: 3, INVALID: 4, CYCLIC: 5, LIMIT_EXCEEDED: 6 });

  function diagnostic(status, code, message, extra = {}) {
    return Object.assign({ status, code, message }, extra);
  }

  function hexBytes(value) {
    return (String(value ?? "").match(/[0-9a-f]{2}/gi) || []).map((part) => part.toLowerCase());
  }

  function bytesFor(packet, coordinateSystem) {
    if (!COORDINATE_SYSTEMS.has(coordinateSystem)) throw new Error("unsupported schema coordinate system");
    if (coordinateSystem === "raw_packet") return hexBytes(packet.raw_payload ?? packet.payload);
    if (packet.application_payload_available === false) return null;
    return hexBytes(packet.application_payload ?? packet.payload);
  }

  function integerValue(raw, endian, type) {
    const ordered = endian === "little" ? raw.slice().reverse() : raw;
    let value = 0n;
    ordered.forEach((part) => { value = (value << 8n) | BigInt(Number.parseInt(part, 16)); });
    const normalizedType = String(type || "").toUpperCase();
    if ((normalizedType === "INT64" || normalizedType === "I64") && raw.length === 8 && value >= (1n << 63n)) value -= 1n << 64n;
    return value.toString(10);
  }

  function clone(value) {
    return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
  }

  function slug(value) {
    const result = String(value || "field").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
    return result || "field";
  }

  // A synchronous deterministic identity is needed because applying schemas
  // is intentionally synchronous.  It is not used for security.
  function stableHash(value) {
    let hash = 2166136261;
    const text = String(value);
    for (let index = 0; index < text.length; index += 1) {
      hash ^= text.charCodeAt(index);
      hash = Math.imul(hash, 16777619);
    }
    return (hash >>> 0).toString(16).padStart(8, "0");
  }

  function stableId(field, index, parentId = "") {
    const identity = JSON.stringify({
      name: field.name || field.type || "field",
      type: field.type || field.kind || "bytes",
      offset: field.offset ?? field.offset_expr ?? 0,
      length: field.length ?? field.width ?? field.length_expr ?? null,
      coordinate_system: field.coordinate_system || "raw_packet",
    });
    return `${parentId ? `${parentId}.` : ""}${slug(field.name || field.type || "field")}_${stableHash(identity)}`;
  }

  function budgetInt(raw, name, fallback, maximum) {
    const candidate = raw && Object.prototype.hasOwnProperty.call(raw, name) ? raw[name] : fallback;
    if (typeof candidate === "boolean" || !Number.isInteger(Number(candidate)) || Number(candidate) <= 0 || Number(candidate) > maximum) throw new Error(`schema budget ${name} is outside the limit`);
    return Number(candidate);
  }

  function budgetsFor(raw) {
    const value = raw || {};
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("schema budgets must be an object");
    return {
      max_packets: budgetInt(value, "max_packets", DEFAULT_BUDGETS.max_packets, 1000000),
      max_fields: budgetInt(value, "max_fields", DEFAULT_BUDGETS.max_fields, 1000),
      max_array_items: budgetInt(value, "max_array_items", value.max_items ?? DEFAULT_BUDGETS.max_array_items, 1000000),
      max_total_array_items: budgetInt(value, "max_total_array_items", DEFAULT_BUDGETS.max_total_array_items, 2000000),
      max_bytes_per_packet: budgetInt(value, "max_bytes_per_packet", DEFAULT_BUDGETS.max_bytes_per_packet, 16 * 1024 * 1024),
      max_field_length: budgetInt(value, "max_field_length", DEFAULT_BUDGETS.max_field_length, 16 * 1024 * 1024),
      max_expression_depth: budgetInt(value, "max_expression_depth", DEFAULT_BUDGETS.max_expression_depth, 128),
      max_expression_value: budgetInt(value, "max_expression_value", DEFAULT_BUDGETS.max_expression_value, Number.MAX_SAFE_INTEGER),
      max_nesting: budgetInt(value, "max_nesting", DEFAULT_BUDGETS.max_nesting, 64),
      max_output_fields: budgetInt(value, "max_output_fields", DEFAULT_BUDGETS.max_output_fields, 1000000),
    };
  }

  function validateExpressionShape(value, depth = 0) {
    if (depth > DEFAULT_BUDGETS.max_expression_depth) throw new Error("schema expression depth exceeds the limit");
    if (value === null || typeof value === "string" || typeof value === "boolean" || typeof value === "number") {
      if (typeof value === "number" && !Number.isFinite(value)) throw new Error("schema expression number is not finite");
      return clone(value);
    }
    if (Array.isArray(value)) {
      if (value.length > 32) throw new Error("schema expression has too many arguments");
      return value.map((item) => validateExpressionShape(item, depth + 1));
    }
    if (!value || typeof value !== "object") throw new Error("schema expression contains an unsupported value");
    if (Object.keys(value).length > 32) throw new Error("schema expression has too many keys");
    const result = {};
    Object.keys(value).sort().forEach((key) => { result[key] = validateExpressionShape(value[key], depth + 1); });
    return result;
  }

  function normalizeField(raw, index, parentId = "", requireId = false) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error(`schema field ${index} must be an object`);
    if (requireId && !(typeof raw.id === "string" && raw.id.trim())) throw new Error(`schema field ${index} is missing a stable id`);
    const id = typeof raw.id === "string" && raw.id.trim() ? raw.id.trim().slice(0, 120) : stableId(raw, index, parentId);
    const name = typeof raw.name === "string" && raw.name.trim() ? raw.name.trim().slice(0, 120) : id;
    const description = raw.description ?? raw.desc ?? "";
    if (typeof description !== "string" || description.length > 2000) throw new Error(`schema field ${index} has an invalid description`);
    const type = String(raw.type ?? raw.kind ?? "bytes").trim().toLowerCase().slice(0, 40);
    if (!type) throw new Error(`schema field ${index} has an invalid type`);
    const coordinate = raw.coordinate_system ?? raw.coordinate?.system ?? raw.coordinate?.coordinate_system;
    if (coordinate !== undefined && !COORDINATE_SYSTEMS.has(coordinate)) throw new Error(`schema field ${index} coordinate_system is invalid`);
    const endian = String(raw.endian ?? "big").toLowerCase();
    if (!["big", "little", "unknown"].includes(endian)) throw new Error(`schema field ${index} endian is invalid`);
    const offset = validateExpressionShape(raw.offset ?? raw.offset_expr ?? 0);
    const lengthValue = raw.length ?? raw.width ?? raw.length_expr;
    const length = lengthValue === undefined ? null : validateExpressionShape(lengthValue);
    const presence = validateExpressionShape(raw.presence ?? raw.when ?? raw.condition ?? true);
    let nested = null;
    if (raw.fields !== undefined && raw.fields !== null) {
      if (!Array.isArray(raw.fields) || raw.fields.length > 1000) throw new Error(`schema field ${index} nested fields exceed the limit`);
      nested = raw.fields.map((child, childIndex) => normalizeField(child, childIndex, id, false));
    }
    let array = null;
    let arrayRaw = raw.array;
    if (arrayRaw === true) arrayRaw = {};
    if (arrayRaw === undefined && (raw.count !== undefined || raw.element !== undefined || type === "array")) arrayRaw = { count: raw.count, element: raw.element };
    if (arrayRaw !== undefined && arrayRaw !== null) {
      if (!arrayRaw || typeof arrayRaw !== "object" || Array.isArray(arrayRaw)) throw new Error(`schema field ${index} array descriptor is invalid`);
      const elementRaw = arrayRaw.element ?? raw.element ?? { type: raw.element_type ?? "bytes", length: raw.element_length ?? 1 };
      array = {
        count: arrayRaw.count ?? arrayRaw.length ?? raw.count ?? null,
        element: normalizeField(elementRaw, 0, `${id}[]`, false),
        max_items: arrayRaw.max_items ?? arrayRaw.max_count ?? null,
      };
      array.count = array.count === null ? null : validateExpressionShape(array.count);
      if (array.max_items !== null && (!Number.isInteger(Number(array.max_items)) || Number(array.max_items) <= 0 || Number(array.max_items) > 1000000)) throw new Error(`schema field ${index} array max_items is out of bounds`);
      if (array.max_items !== null) array.max_items = Number(array.max_items);
    }
    return {
      id, name, description, type, coordinate_system: coordinate ?? null,
      offset, length, endian,
      encoding: String(raw.encoding ?? "").slice(0, 40), presence,
      fields: nested, array,
      constraints: clone(raw.constraints ?? {}), metadata: clone(raw.metadata ?? {}),
      checksum: raw.checksum === undefined ? null : clone(raw.checksum),
      relationship: raw.relationship === undefined ? null : clone(raw.relationship),
    };
  }

  function walkFields(fields, callback) {
    fields.forEach((field) => {
      callback(field);
      if (Array.isArray(field.fields)) walkFields(field.fields, callback);
      if (field.array?.element) {
        callback(field.array.element);
        if (Array.isArray(field.array.element.fields)) walkFields(field.array.element.fields, callback);
      }
    });
  }

  function refsInExpression(expression, refs = new Set()) {
    if (Array.isArray(expression)) expression.forEach((item) => refsInExpression(item, refs));
    else if (expression && typeof expression === "object") {
      ["field", "ref", "field_ref", "field_id"].forEach((key) => { if (typeof expression[key] === "string" && (key !== "field_id" || ["field", "field_ref", "field_reference", "reference", "ref"].includes(String(expression.kind || "")))) refs.add(expression[key]); });
      Object.keys(expression).forEach((key) => refsInExpression(expression[key], refs));
    }
    return refs;
  }

  function expressionsFor(field) {
    const values = [field.offset, field.length, field.presence];
    if (field.array) values.push(field.array.count);
    return values;
  }

  function graphDiagnostics(fields) {
    const all = [];
    walkFields(fields, (field) => all.push(field));
    const byId = new Map();
    all.forEach((field) => byId.set(field.id, field));
    const byName = new Map(all.map((field) => [field.name, field]));
    const dependencies = new Map();
    const missingRefs = [];
    all.forEach((field) => {
      const refs = new Set();
      expressionsFor(field).forEach((expression) => refsInExpression(expression, refs));
      const resolved = new Set();
      refs.forEach((ref) => {
        const target = byId.get(ref) || byName.get(ref);
        if (target) resolved.add(target.id);
        else missingRefs.push({ field, ref });
        if (!target) return;
      });
      dependencies.set(field.id, resolved);
    });
    const diagnostics = missingRefs.map(({ field, ref }) => diagnostic("INVALID", "missing_reference", `field reference ${ref} does not exist`, { field_id: field.id, reference: ref }));
    const visiting = new Set(); const visited = new Set(); const cyclic = new Set();
    function visit(id, stack) {
      if (visiting.has(id)) { const start = stack.indexOf(id); stack.slice(start < 0 ? 0 : start).forEach((item) => cyclic.add(item)); return; }
      if (visited.has(id)) return;
      visiting.add(id); stack.push(id); (dependencies.get(id) || []).forEach((dependency) => visit(dependency, stack)); stack.pop(); visiting.delete(id); visited.add(id);
    }
    all.filter((field) => field.id).forEach((field) => visit(field.id, []));
    Array.from(cyclic).sort().forEach((id) => diagnostics.push(diagnostic("CYCLIC", "dependency_cycle", "field dependency cycle prevents evaluation", { field_id: id })));
    diagnostics.sort((a, b) => `${a.field_id}:${a.code}:${a.reference || ""}`.localeCompare(`${b.field_id}:${b.code}:${b.reference || ""}`));
    return { byId, byName, dependencies, diagnostics, cyclic, missing: new Set(missingRefs.map((item) => `${item.field.id}:${item.ref}`)) };
  }

  function normalizeV2(schema) {
    if (!schema || typeof schema !== "object" || schema.schema_version !== 2) throw new Error("unsupported protocol schema version");
    if (!COORDINATE_SYSTEMS.has(schema.coordinate_system ?? "raw_packet")) throw new Error("schema coordinate_system is invalid");
    if (!Array.isArray(schema.fields) || schema.fields.length > 1000) throw new Error("schema fields are missing or exceed the limit");
    const checked = {
      schema_version: 2,
      name: String(schema.name ?? "PacketScope protocol").slice(0, 120) || "PacketScope protocol",
      description: String(schema.description ?? "").slice(0, 2000),
      coordinate_system: schema.coordinate_system ?? "raw_packet",
      budgets: budgetsFor(schema.budgets ?? schema.limits),
      fields: schema.fields.map((field, index) => normalizeField(field, index, "", true)),
      source: clone(schema.source ?? {}), metadata: clone(schema.metadata ?? {}),
      definitions: {}, relationships: clone(schema.relationships ?? schema.checksums ?? []),
    };
    if (!Array.isArray(checked.relationships) || checked.relationships.length > checked.budgets.max_fields) throw new Error("schema relationships are invalid or exceed the limit");
    const ids = new Set(); let count = 0;
    walkFields(checked.fields, (field) => { count += 1; if (count > checked.budgets.max_fields) throw new Error("schema fields are missing or exceed the limit"); if (ids.has(field.id)) throw new Error(`schema field ids must be unique: ${field.id}`); ids.add(field.id); field.coordinate_system = field.coordinate_system || checked.coordinate_system; });
    const graph = graphDiagnostics(checked.fields);
    checked.diagnostics = graph.diagnostics;
    checked.dependencies = Object.fromEntries(Array.from(graph.dependencies.entries()).map(([id, refs]) => [id, Array.from(refs).sort()]));
    Object.defineProperty(checked, "_graph", { value: graph, enumerable: false });
    return checked;
  }

  function normalizeV1(schema) {
    if (!schema || typeof schema !== "object" || schema.schema_version !== 1 || !Array.isArray(schema.fields) || schema.fields.length > 1000) throw new Error("unsupported schema version, coordinate system, or fields are missing");
    const coordinate = schema.coordinate_system ?? "raw_packet";
    if (!COORDINATE_SYSTEMS.has(coordinate)) throw new Error("schema coordinate_system is invalid");
    const fields = schema.fields.map((field, index) => {
      if (!field || typeof field !== "object" || typeof field.name !== "string" || !field.name.trim() || !Number.isInteger(field.offset) || field.offset < 0 || !Number.isInteger(field.width) || field.width < 1 || field.width > 16 * 1024 * 1024) throw new Error("schema field has an invalid offset or width");
      const fieldCoordinate = field.coordinate_system ?? coordinate;
      if (!COORDINATE_SYSTEMS.has(fieldCoordinate)) throw new Error("schema field coordinate system is invalid");
      const endian = field.endian ?? "unknown";
      if (!["big", "little", "unknown"].includes(endian)) throw new Error("schema field endian is invalid");
      const type = String(field.type ?? "custom").toUpperCase();
      if ((type === "UINT32" && field.width !== 4) || ((type === "UINT64" || type === "INT64") && field.width !== 8)) throw new Error("schema integer type does not match field width");
      return {
        id: stableId(field, index), name: field.name.trim().slice(0, 120), description: "Migrated from Schema V1 fixed-range field.",
        type: String(field.type ?? "custom").toLowerCase(), offset: field.offset, length: field.width,
        endian, coordinate_system: fieldCoordinate,
        constraints: clone(field.constraints ?? {}), metadata: { legacy_v1: true, origin: field.origin, review_status: field.review_status, evidence_refs: clone(field.evidence_refs ?? []), known_limitations: clone(field.known_limitations ?? []) },
      };
    });
    return normalizeV2({ schema_version: 2, name: schema.name ?? "PacketScope protocol", coordinate_system: coordinate, fields, source: { migrated_from_schema_version: 1, source: clone(schema.source ?? {}) } });
  }

  function migrate(schema) {
    return schema && schema.schema_version === 1 ? normalizeV1(schema) : normalizeV2(schema);
  }

  function validate(schema) {
    return migrate(schema);
  }

  function numeric(value) {
    if (typeof value === "bigint") return value;
    if (typeof value === "number" && Number.isInteger(value) && Number.isSafeInteger(value)) return BigInt(value);
    if (typeof value === "string" && /^-?\d+$/.test(value)) { try { return BigInt(value); } catch { return null; } }
    return null;
  }

  function publicInteger(value) {
    const number = numeric(value);
    if (number === null) return value;
    return number <= BigInt(Number.MAX_SAFE_INTEGER) && number >= BigInt(Number.MIN_SAFE_INTEGER) ? Number(number) : number.toString(10);
  }

  function compareValues(left, right, op) {
    const leftNumber = numeric(left); const rightNumber = numeric(right);
    const a = leftNumber !== null && rightNumber !== null ? leftNumber : left;
    const b = leftNumber !== null && rightNumber !== null ? rightNumber : right;
    if (op === "eq") return a === b;
    if (op === "ne") return a !== b;
    if (op === "lt") return a < b;
    if (op === "lte") return a <= b;
    if (op === "gt") return a > b;
    return a >= b;
  }

  function evalExpression(expression, values, budgets, depth = 0) {
    if (depth > budgets.max_expression_depth) return { status: "LIMIT_EXCEEDED", value: null, diagnostics: [diagnostic("LIMIT_EXCEEDED", "expression_depth", "expression depth exceeds the schema budget")] };
    if (expression === null) return { status: "UNKNOWN", value: null, diagnostics: [diagnostic("UNKNOWN", "missing_expression", "expression is not declared")] };
    if (typeof expression === "boolean" || typeof expression === "number" || typeof expression === "string") return { status: "RESOLVED", value: expression, diagnostics: [] };
    if (!expression || typeof expression !== "object" || Array.isArray(expression)) return { status: "INVALID", value: null, diagnostics: [diagnostic("INVALID", "expression_form", "expression object is invalid")] };
    const kind = String(expression.kind || "").toLowerCase();
    const refKey = ["field", "ref", "field_ref"].find((key) => Object.prototype.hasOwnProperty.call(expression, key));
    const kindReference = !refKey && ["field", "field_ref", "field_reference", "reference", "ref"].includes(kind) ? ["field_id", "id", "name"].find((key) => typeof expression[key] === "string") : null;
    if (refKey || kindReference) {
      const reference = expression[refKey || kindReference];
      if (typeof reference !== "string") return { status: "INVALID", value: null, diagnostics: [diagnostic("INVALID", "reference_type", "field reference must be a string")] };
      const entry = values[reference];
      if (!entry) return { status: "INVALID", value: null, diagnostics: [diagnostic("INVALID", "missing_reference", `field reference ${reference} does not exist`, { reference })] };
      if (entry.status !== "RESOLVED") return { status: entry.status, value: null, diagnostics: [diagnostic(entry.status, "dependency_status", `field reference ${reference} is not resolved`, { reference })] };
      let result = { status: "RESOLVED", value: entry.internal, diagnostics: [] };
      if (Object.prototype.hasOwnProperty.call(expression, "add")) result = applyOperation("add", [result, evalExpression(expression.add, values, budgets, depth + 1)], budgets);
      return result;
    }
    if (Object.prototype.hasOwnProperty.call(expression, "static")) return evalExpression(expression.static, values, budgets, depth + 1);
    if (Object.prototype.hasOwnProperty.call(expression, "const") || Object.prototype.hasOwnProperty.call(expression, "constant") || ["constant", "const", "literal", "static"].includes(kind)) return evalExpression(expression.const ?? expression.constant ?? expression.value, values, budgets, depth + 1);
    let operation = expression.op ?? expression.kind;
    if (["comparison", "compare", "boolean", "arithmetic"].includes(operation)) operation = expression.operator ?? expression.operation;
    const aliases = Object.keys(OP_ALIASES);
    if (!operation) operation = [...ALLOWED_OPS, ...aliases].find((key) => Object.prototype.hasOwnProperty.call(expression, key));
    operation = OP_ALIASES[String(operation || "").toLowerCase()] || String(operation || "").toLowerCase();
    if (!ALLOWED_OPS.has(operation)) return { status: "INVALID", value: null, diagnostics: [diagnostic("INVALID", "unsupported_operation", `operation ${operation || "(missing)"} is not allowed`)] };
    let args = expression.args ?? expression.terms ?? expression.operands ?? expression.values;
    if (args === undefined && Object.prototype.hasOwnProperty.call(expression, "left")) args = [expression.left, expression.right];
    if (args === undefined && Object.prototype.hasOwnProperty.call(expression, operation)) args = expression[operation];
    if (!Array.isArray(args)) args = [args];
    if (args.length > 32) return { status: "LIMIT_EXCEEDED", value: null, diagnostics: [diagnostic("LIMIT_EXCEEDED", "expression_arguments", "expression has too many arguments")] };
    const evaluated = args.map((item) => evalExpression(item, values, budgets, depth + 1));
    const failed = evaluated.find((item) => item.status !== "RESOLVED");
    if (failed) return failed;
    return applyOperation(operation, evaluated, budgets);
  }

  function applyOperation(operation, evaluated, budgets) {
    const values = evaluated.map((item) => item.value);
    if (operation === "add") {
      if (!values.length) return { status: "INVALID", value: null, diagnostics: [diagnostic("INVALID", "add_operands", "add requires operands")] };
      const numbers = values.map(numeric); if (numbers.some((item) => item === null)) return { status: "INVALID", value: null, diagnostics: [diagnostic("INVALID", "numeric_operands", "add requires integer operands")] };
      const result = numbers.reduce((sum, item) => sum + item, 0n);
      if (result < -BigInt(budgets.max_expression_value) || result > BigInt(budgets.max_expression_value)) return { status: "LIMIT_EXCEEDED", value: null, diagnostics: [diagnostic("LIMIT_EXCEEDED", "expression_value", "expression result exceeds the schema budget")] };
      return { status: "RESOLVED", value: result, diagnostics: [] };
    }
    if (!["eq", "ne", "lt", "lte", "gt", "gte"].includes(operation) || values.length !== 2) return { status: "INVALID", value: null, diagnostics: [diagnostic("INVALID", "comparison_operands", "comparison requires two operands")] };
    return { status: "RESOLVED", value: compareValues(values[0], values[1], operation), diagnostics: [] };
  }

  function mergeStatus(current, candidate) {
    return (STATUS_PRIORITY[candidate] ?? 4) > (STATUS_PRIORITY[current] ?? 0) ? candidate : current;
  }

  function decode(raw, field) {
    const type = field.type.toLowerCase();
    const integer = INTEGER_WIDTHS[type];
    const legacy = field.metadata?.legacy_v1 === true;
    if (legacy && !integer && !["uint", "unsigned", "unsigned_integer", "int", "signed", "signed_integer", "integer", "bool", "boolean", "text", "string", "utf8", "ascii", "bytes", "raw", "opaque", "custom", "hex", "checksum", "crc"].includes(type)) return { status: "RESOLVED", value: raw.join(""), internal: raw.join(""), encoding: "hex", diagnostics: [] };
    if (integer || ["uint", "unsigned", "unsigned_integer", "int", "signed", "signed_integer", "integer"].includes(type)) {
      const width = integer ? integer[0] : raw.length; const signed = integer ? integer[1] : ["int", "signed", "signed_integer"].includes(type);
      if (integer && raw.length !== width) return { status: "INVALID", value: null, internal: null, diagnostics: [diagnostic("INVALID", "integer_width", "integer field width does not match its type")] };
      if (!integer && (width <= 0 || width > 16)) return { status: "INVALID", value: null, internal: null, diagnostics: [diagnostic("INVALID", "integer_width", "generic integer width is unsupported")] };
      if (!["big", "little"].includes(field.endian)) {
        if (legacy) return { status: "RESOLVED", value: raw.join(""), internal: raw.join(""), encoding: "hex", diagnostics: [] };
        return { status: "INVALID", value: null, internal: null, diagnostics: [diagnostic("INVALID", "integer_endian", "integer fields require big or little endian")] };
      }
      const ordered = field.endian === "little" ? raw.slice().reverse() : raw; let value = 0n;
      ordered.forEach((part) => { value = (value << 8n) | BigInt(Number.parseInt(part, 16)); });
      if (signed && value >= (1n << BigInt(raw.length * 8 - 1))) value -= 1n << BigInt(raw.length * 8);
      return { status: "RESOLVED", value: legacy ? value.toString(10) : publicInteger(value), internal: value, encoding: legacy ? "decimal_string" : "decimal", diagnostics: [] };
    }
    if (["bool", "boolean"].includes(type)) { const value = raw.some((part) => part !== "00"); return { status: "RESOLVED", value, internal: value, encoding: "boolean", diagnostics: [] }; }
    if (["text", "string", "utf8", "ascii"].includes(type)) {
      try {
        const bytes = Uint8Array.from(raw.map((item) => Number.parseInt(item, 16)));
        const value = typeof TextDecoder !== "undefined" ? new TextDecoder(field.encoding || (type === "ascii" ? "ascii" : "utf-8"), { fatal: true }).decode(bytes) : raw.join("");
        return { status: "RESOLVED", value, internal: value, encoding: "text", diagnostics: [] };
      } catch { return { status: "INVALID", value: null, internal: null, diagnostics: [diagnostic("INVALID", "text_decode", "field text could not be decoded")] }; }
    }
    if (["bytes", "raw", "opaque", "custom", "hex", "checksum", "crc"].includes(type)) return { status: "RESOLVED", value: raw.join(""), internal: raw.join(""), encoding: "hex", diagnostics: [] };
    return { status: "INVALID", value: null, internal: null, diagnostics: [diagnostic("INVALID", "unsupported_type", `field type ${type} is unsupported`)] };
  }

  function publicField(field, result, present = true, items = undefined) {
    const output = {
      id: field.id, name: field.name, description: field.description || "", status: result.status,
      present, available: result.status === "RESOLVED" && present,
      offset: result.offset ?? null, length: result.length ?? null, width: result.length ?? null,
      coordinate_system: field.coordinate_system, value: present ? (result.value ?? null) : null,
      value_encoding: result.encoding ?? null, diagnostics: (result.diagnostics || []).slice(0, 32),
    };
    if (items) output.items = items;
    return output;
  }

  function parseField(field, context, baseOffset, depth = 0, store = true) {
    const { data, metadata, values, checked } = context; const budgets = checked.budgets;
    if (depth > budgets.max_nesting) { const result = { status: "LIMIT_EXCEEDED", diagnostics: [diagnostic("LIMIT_EXCEEDED", "nesting", "nested structure exceeds the schema budget")] }; return [publicField(field, result, false), result]; }
    const presence = evalExpression(field.presence, values, budgets);
    if (presence.status !== "RESOLVED") { const result = { status: presence.status, diagnostics: presence.diagnostics }; if (store) values[field.id] = result; return [publicField(field, result, false), result]; }
    if (!Boolean(presence.value)) { const result = { status: "RESOLVED", diagnostics: [diagnostic("RESOLVED", "conditional_absent", "field is not present because its condition is false")] }; if (store) values[field.id] = result; return [publicField(field, result, false), result]; }
    const offsetResult = evalExpression(field.offset, values, budgets);
    const relative = offsetResult.status === "RESOLVED" ? numeric(offsetResult.value) : null;
    if (offsetResult.status !== "RESOLVED") { const result = { status: offsetResult.status, diagnostics: offsetResult.diagnostics }; if (store) values[field.id] = result; return [publicField(field, result), result]; }
    if (relative === null || relative < 0n) { const result = { status: "INVALID", diagnostics: [diagnostic("INVALID", "offset", "field offset must be a non-negative integer")] }; if (store) values[field.id] = result; return [publicField(field, result), result]; }
    const absolute = Number(relative) + baseOffset;
    if (!Number.isSafeInteger(absolute) || absolute > budgets.max_bytes_per_packet) { const result = { status: "LIMIT_EXCEEDED", offset: absolute, diagnostics: [diagnostic("LIMIT_EXCEEDED", "packet_budget", "field offset exceeds the packet budget")] }; if (store) values[field.id] = result; return [publicField(field, result), result]; }
    if (data === null || !metadata.available) { const result = { status: "UNAVAILABLE", offset: absolute, diagnostics: [diagnostic("UNAVAILABLE", "coordinate_unavailable", "declared coordinate system is unavailable for this packet")] }; if (store) values[field.id] = result; return [publicField(field, result), result]; }
    if (field.array) return parseArray(field, context, absolute, depth, store);
    if (Array.isArray(field.fields) || ["struct", "structure"].includes(field.type)) {
      if (!Array.isArray(field.fields)) { const result = { status: "INVALID", offset: absolute, diagnostics: [diagnostic("INVALID", "nested_fields", "structured field has no fields")] }; if (store) values[field.id] = result; return [publicField(field, result), result]; }
      const childValues = {}; const childOutputs = []; let end = absolute; let status = "RESOLVED";
      field.fields.slice(0, budgets.max_fields).forEach((child) => { const childContext = Object.assign({}, context, { values: Object.assign({}, values, childValues) }); const [output, result] = parseField(child, childContext, absolute, depth + 1); childValues[child.id] = result; childValues[child.name] = result; childOutputs.push(output); if (Number.isInteger(result.offset) && Number.isInteger(result.length)) end = Math.max(end, result.offset + result.length); status = mergeStatus(status, result.status); });
      let length = end - absolute;
      if (field.length !== null) { const lengthResult = evalExpression(field.length, values, budgets); if (lengthResult.status !== "RESOLVED") status = mergeStatus(status, lengthResult.status); else { const declared = numeric(lengthResult.value); if (declared === null || declared < 0n) status = mergeStatus(status, "INVALID"); else length = Number(declared); } }
      if (length > budgets.max_field_length || absolute + length > budgets.max_bytes_per_packet) status = mergeStatus(status, "LIMIT_EXCEEDED");
      else if (absolute + length > data.length) status = mergeStatus(status, "OUT_OF_BOUNDS");
      const result = { status, value: Object.fromEntries(childOutputs.map((item) => [item.id, item.value])), internal: Object.fromEntries(field.fields.map((child) => [child.id, childValues[child.id]?.internal])), offset: absolute, length, diagnostics: status === "RESOLVED" ? [] : [diagnostic(status, "nested_status", "nested structure contains a non-resolved field")] };
      const output = publicField(field, result); output.fields = childOutputs; if (store) values[field.id] = result; return [output, result];
    }
    const lengthResult = field.length === null ? null : evalExpression(field.length, values, budgets);
    let length;
    if (lengthResult === null) length = INTEGER_WIDTHS[field.type]?.[0] ?? null;
    else if (lengthResult.status !== "RESOLVED") { const result = { status: lengthResult.status, offset: absolute, diagnostics: lengthResult.diagnostics }; if (store) values[field.id] = result; return [publicField(field, result), result]; }
    else { const numericLength = numeric(lengthResult.value); length = numericLength === null || numericLength < 0n ? null : Number(numericLength); }
    if (!Number.isSafeInteger(length) || length < 0) { const result = { status: "INVALID", offset: absolute, diagnostics: [diagnostic("INVALID", "length", "field length must be a non-negative integer")] }; if (store) values[field.id] = result; return [publicField(field, result), result]; }
    if (length > budgets.max_field_length || absolute + length > budgets.max_bytes_per_packet) { const result = { status: "LIMIT_EXCEEDED", offset: absolute, length, diagnostics: [diagnostic("LIMIT_EXCEEDED", "field_length", "field range exceeds the schema budget")] }; if (store) values[field.id] = result; return [publicField(field, result), result]; }
    if (absolute + length > data.length) { const result = { status: "OUT_OF_BOUNDS", offset: absolute, length, diagnostics: [diagnostic("OUT_OF_BOUNDS", "truncated_field", "field range extends beyond captured bytes")] }; if (store) values[field.id] = result; return [publicField(field, result), result]; }
    const decoded = decode(data.slice(absolute, absolute + length), field); const result = Object.assign(decoded, { offset: absolute, length }); const output = publicField(field, result); if (store) values[field.id] = result; return [output, result];
  }

  function parseArray(field, context, absolute, depth, store) {
    const { data, values, checked } = context; const countResult = evalExpression(field.array.count, values, checked.budgets); const baseResult = { offset: absolute };
    if (countResult.status !== "RESOLVED") { const result = Object.assign(baseResult, { status: countResult.status, diagnostics: countResult.diagnostics }); if (store) values[field.id] = result; return [publicField(field, result), result]; }
    const countValue = numeric(countResult.value); const maxItems = Math.min(field.array.max_items || checked.budgets.max_array_items, checked.budgets.max_array_items);
    if (countValue === null || countValue < 0n) { const result = Object.assign(baseResult, { status: "INVALID", diagnostics: [diagnostic("INVALID", "array_count", "array count must be a non-negative integer")] }); if (store) values[field.id] = result; return [publicField(field, result), result]; }
    if (countValue > BigInt(maxItems)) { const result = Object.assign(baseResult, { status: "LIMIT_EXCEEDED", diagnostics: [diagnostic("LIMIT_EXCEEDED", "array_items", "array count exceeds the schema budget")] }); if (store) values[field.id] = result; return [publicField(field, result), result]; }
    const count = Number(countValue); context.runtime.arrayItems += count;
    if (context.runtime.arrayItems > checked.budgets.max_total_array_items) { const result = Object.assign(baseResult, { status: "LIMIT_EXCEEDED", diagnostics: [diagnostic("LIMIT_EXCEEDED", "array_items_total", "total array items exceed the schema budget")] }); if (store) values[field.id] = result; return [publicField(field, result), result]; }
    let cursor = absolute; let status = "RESOLVED"; const items = []; const publicValues = []; const element = field.array.element;
    for (let index = 0; index < count; index += 1) {
      const [output, result] = parseField(element, context, cursor, depth + 1, false); output.index = index; items.push(output); publicValues.push(output.value); status = mergeStatus(status, result.status); if (Number.isInteger(result.offset) && Number.isInteger(result.length)) cursor = result.offset + result.length; else break;
    }
    const length = Math.max(0, cursor - absolute); const result = { status, value: publicValues, internal: items.map((item) => item.value), offset: absolute, length, diagnostics: status === "RESOLVED" ? [] : [diagnostic(status, "array_status", "array contains a non-resolved element")] }; const output = publicField(field, result, true, items); if (store) values[field.id] = result; return [output, result];
  }

  function apply(schema, packetList) {
    const checked = migrate(schema); const source = Array.isArray(packetList) ? packetList : []; const values = [];
    const limit = Math.min(source.length, checked.budgets.max_packets, 100000); const truncated = source.length > limit;
    for (let packetIndex = 0; packetIndex < limit; packetIndex += 1) {
      const packet = source[packetIndex]; const fields = []; const valueMap = {}; const runtime = { arrayItems: 0 }; const cache = new Map();
      function contextFor(field) {
        const coordinate = field.coordinate_system || checked.coordinate_system;
        if (!cache.has(coordinate)) { const bytes = bytesFor(packet, coordinate); cache.set(coordinate, { data: bytes, metadata: { available: bytes !== null } }); }
        return cache.get(coordinate);
      }
      const graph = checked._graph; const topFields = checked.fields; const state = new Map(); const order = [];
      function visit(field) { if (state.get(field.id) === 1 || state.get(field.id) === 2) return; state.set(field.id, 1); (graph.dependencies.get(field.id) || []).forEach((dependency) => { const target = graph.byId.get(dependency); if (target && topFields.includes(target)) visit(target); }); state.set(field.id, 2); order.push(field); }
      topFields.forEach(visit);
      const outputs = new Map();
      order.forEach((field) => {
        if (graph.cyclic.has(field.id)) { const result = { status: "CYCLIC", diagnostics: [diagnostic("CYCLIC", "dependency_cycle", "field dependency cycle prevents evaluation")] }; valueMap[field.id] = result; outputs.set(field.id, publicField(field, result, false)); return; }
        const missing = (graph.diagnostics || []).filter((item) => item.field_id === field.id && item.code === "missing_reference");
        if (missing.length) { const result = { status: "INVALID", diagnostics: missing }; valueMap[field.id] = result; outputs.set(field.id, publicField(field, result)); return; }
        const coordinate = contextFor(field); const context = { data: coordinate.data, metadata: coordinate.metadata, values: valueMap, checked, runtime }; const [output, result] = parseField(field, context, 0); outputs.set(field.id, output); valueMap[field.id] = result; valueMap[field.name] = result;
      });
      checked.fields.forEach((field) => fields.push(outputs.get(field.id) || publicField(field, { status: "INVALID", diagnostics: [diagnostic("INVALID", "not_evaluated", "field was not evaluated")] })));
      const packetStatus = fields.reduce((status, field) => mergeStatus(status, field.status), "RESOLVED");
      values.push({ packetId: packet.index, packet_id: packet.index, status: packetStatus, fields, diagnostics: checked.diagnostics.slice(0, 32) });
    }
    Object.defineProperties(values, {
      values: { value: values, enumerable: false },
      schema_version: { value: 2, enumerable: false },
      status: { value: truncated ? "LIMIT_EXCEEDED" : "RESOLVED", enumerable: false },
      diagnostics: { value: truncated ? [diagnostic("LIMIT_EXCEEDED", "packet_count", "packet input exceeded the application budget", { limit })] : [], enumerable: false },
      schema_diagnostics: { value: checked.diagnostics.slice(), enumerable: false },
      budgets: { value: checked.budgets, enumerable: false },
    });
    return values;
  }

  return { apply, bytesFor, integerValue, migrate, migrateSchema: migrate, validate, normalize: validate, statuses: STATUS };
});
