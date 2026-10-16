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
  const MAX_DEFINITIONS = 128;
  const MAX_CONSTRAINT_VALUES = 10000;
  const OP_ALIASES = Object.freeze({
    plus: "add", minus: "subtract", sub: "subtract", mul: "multiply", times: "multiply", bounded_mul: "multiply",
    bit_and: "mask", and_bits: "mask", bitand: "mask", bit_or: "bitor", bit_xor: "xor",
    equal: "eq", equals: "eq", not_equal: "ne",
    less_than: "lt", less_equal: "lte", greater_than: "gt", greater_equal: "gte",
    le: "lte", ge: "gte", logical_and: "and", logical_or: "or", all: "and", any: "or",
    conjunction: "and", disjunction: "or", align_up: "align", alignment: "align", bitmask: "mask",
    bounded_multiply: "multiply", "==": "eq", "!=": "ne", "<": "lt", "<=": "lte", ">": "gt", ">=": "gte",
  });
  const ALLOWED_OPS = new Set(["add", "subtract", "multiply", "mask", "bitor", "xor", "min", "max", "align", "eq", "ne", "lt", "lte", "gt", "gte", "and", "or", "not", "negate"]);
  const STATUS_PRIORITY = Object.freeze({ RESOLVED: 0, UNKNOWN: 1, UNAVAILABLE: 2, OUT_OF_BOUNDS: 3, INVALID: 4, CYCLIC: 5, LIMIT_EXCEEDED: 6 });

  function diagnostic(status, code, message, extra = {}) {
    function safe(value) {
      if (typeof value === "bigint") return publicInteger(value);
      if (Array.isArray(value)) return value.map(safe);
      if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, safe(item)]));
      return value;
    }
    return Object.assign({ status, code, message }, safe(extra));
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
    const integer = INTEGER_WIDTHS[String(type || "").toLowerCase()];
    if (integer?.[1] && raw.length === integer[0] && value >= (1n << BigInt(raw.length * 8 - 1))) value -= 1n << BigInt(raw.length * 8);
    else if ((normalizedType === "INT64" || normalizedType === "I64") && raw.length === 8 && value >= (1n << 63n)) value -= 1n << 64n;
    return value.toString(10);
  }

  function clone(value) {
    return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
  }

  function jsonSafe(value, depth = 0) {
    if (depth > DEFAULT_BUDGETS.max_expression_depth * 2) throw new Error("schema JSON nesting exceeds the limit");
    if (value === undefined) return undefined;
    if (value === null || typeof value === "string" || typeof value === "boolean") return value;
    if (typeof value === "number") {
      if (!Number.isFinite(value)) throw new Error("schema numbers must be finite");
      if (Number.isInteger(value) && !Number.isSafeInteger(value)) throw new Error("schema integer exceeds the limit");
      return value;
    }
    if (Array.isArray(value)) {
      if (value.length > 100000) throw new Error("schema list exceeds the limit");
      return value.map((item) => jsonSafe(item, depth + 1));
    }
    if (!value || typeof value !== "object") throw new Error("schema contains a non-JSON value");
    if (Object.keys(value).length > 32) throw new Error("schema object exceeds the limit");
    const result = {};
    Object.keys(value).sort().forEach((key) => { const item = jsonSafe(value[key], depth + 1); if (item !== undefined) result[key] = item; });
    return result;
  }

  function normalizeConstraints(raw, index) {
    if (raw === undefined) return {};
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error(`schema field ${index} constraints must be an object`);
    const constraints = jsonSafe(raw);
    if (Object.keys(constraints).length > 32) throw new Error(`schema field ${index} constraints have too many keys`);
    ["allowed", "forbidden"].forEach((key) => {
      if (Array.isArray(constraints[key]) && constraints[key].length > MAX_CONSTRAINT_VALUES) throw new Error(`schema field ${index} ${key} values exceed the limit`);
    });
    const enumValue = constraints.enum;
    if (Array.isArray(enumValue) && enumValue.length > MAX_CONSTRAINT_VALUES) throw new Error(`schema field ${index} enum values exceed the limit`);
    if (enumValue && typeof enumValue === "object" && !Array.isArray(enumValue)) {
      const values = enumValue.values ?? enumValue.allowed ?? Object.keys(enumValue);
      if (Array.isArray(values) && values.length > MAX_CONSTRAINT_VALUES) throw new Error(`schema field ${index} enum values exceed the limit`);
    }
    return constraints;
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
    return `${parentId ? `${parentId}.` : ""}${slug(field.name || field.type || "field")}_${index}`;
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
    const rawId = raw.id ?? raw.field_id;
    if (requireId && !(typeof rawId === "string" && rawId.trim())) throw new Error(`schema field ${index} is missing a stable id`);
    if (rawId !== undefined && (typeof rawId !== "string" || !rawId.trim())) throw new Error(`schema field ${index} id is invalid`);
    const id = typeof rawId === "string" && rawId.trim() ? rawId.trim().slice(0, 120) : stableId(raw, index, parentId);
    if (raw.name !== undefined && (typeof raw.name !== "string" || !raw.name.trim() || raw.name.length > 120)) throw new Error(`schema field ${index} has an invalid name`);
    const name = raw.name === undefined ? id : raw.name.trim().slice(0, 120);
    const description = raw.description ?? raw.desc ?? "";
    if (typeof description !== "string" || description.length > 2000) throw new Error(`schema field ${index} has an invalid description`);
    const type = String(raw.type ?? raw.kind ?? "bytes").trim().toLowerCase().slice(0, 40);
    if (!type) throw new Error(`schema field ${index} has an invalid type`);
    const coordinateMetadata = raw.coordinate;
    if (coordinateMetadata !== undefined && coordinateMetadata !== null && (typeof coordinateMetadata !== "object" || Array.isArray(coordinateMetadata))) throw new Error(`schema field ${index} coordinate metadata is invalid`);
    const coordinate = raw.coordinate_system ?? coordinateMetadata?.system ?? coordinateMetadata?.coordinate_system;
    if (coordinate !== undefined && !COORDINATE_SYSTEMS.has(coordinate)) throw new Error(`schema field ${index} coordinate_system is invalid`);
    const endian = String(raw.endian ?? "big").toLowerCase();
    if (!["big", "little", "unknown"].includes(endian)) throw new Error(`schema field ${index} endian is invalid`);
    const integerTypes = new Set([...Object.keys(INTEGER_WIDTHS), "uint", "unsigned", "unsigned_integer", "int", "signed", "signed_integer", "integer"]);
    if (raw.signed !== undefined && raw.signed !== null && typeof raw.signed !== "boolean") throw new Error(`schema field ${index} signed is invalid`);
    if (raw.signed !== undefined && raw.signed !== null && !integerTypes.has(type)) throw new Error(`schema field ${index} signed is only valid for integer fields`);
    const offset = validateExpressionShape(raw.offset ?? raw.offset_expr ?? 0);
    let lengthValue = raw.length ?? raw.width ?? raw.length_expr;
    if (lengthValue === undefined && raw.width_bits !== undefined) {
      if (typeof raw.width_bits !== "number" || !Number.isInteger(raw.width_bits) || raw.width_bits <= 0 || raw.width_bits % 8) throw new Error(`schema field ${index} width_bits is invalid`);
      lengthValue = raw.width_bits / 8;
    }
    if (typeof raw.offset === "boolean" || typeof lengthValue === "boolean") throw new Error(`schema field ${index} offset/length is invalid`);
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
    const definition = raw.definition ?? raw.use;
    if (definition !== undefined && (typeof definition !== "string" || !definition.trim())) throw new Error(`schema field ${index} definition is invalid`);
    return {
      id, name, description, type, coordinate_system: coordinate ?? null,
      coordinate: coordinateMetadata === undefined ? null : jsonSafe(coordinateMetadata),
      offset, length, endian, signed: raw.signed ?? null,
      encoding: String(raw.encoding ?? "").slice(0, 40), presence,
      fields: nested, array,
      definition: definition === undefined ? null : definition.trim(), constraints: normalizeConstraints(raw.constraints, index), path: `${parentId ? `${parentId}.` : ""}${id}`,
      metadata: jsonSafe(raw.metadata ?? {}), algorithm: raw.algorithm === undefined ? null : jsonSafe(raw.algorithm),
      byte_order: raw.byte_order === undefined ? null : jsonSafe(raw.byte_order),
      checksum: raw.checksum === undefined ? null : jsonSafe(raw.checksum),
      relationship: raw.relationship === undefined ? null : jsonSafe(raw.relationship),
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

  function fillCoordinates(fields, coordinateSystem) {
    (fields || []).forEach((field) => {
      field.coordinate_system = field.coordinate_system || coordinateSystem;
      if (!COORDINATE_SYSTEMS.has(field.coordinate_system)) throw new Error(`field ${field.id} coordinate_system is invalid`);
      if (Array.isArray(field.fields)) fillCoordinates(field.fields, field.coordinate_system);
      if (field.array?.element) fillCoordinates([field.array.element], field.coordinate_system);
    });
  }

  function preflightFieldTree(fields, maxFields, maxDepth, path, count) {
    if (!Array.isArray(fields)) return;
    const pending = fields.map((item, index) => ({ item, depth: 0, path: `${path}[${index}]` })).reverse();
    while (pending.length) {
      const current = pending.pop(); count.value += 1;
      if (count.value > maxFields) throw new Error("schema fields are missing or exceed the limit");
      if (current.depth > maxDepth) throw new Error(`${current.path} exceeds the nesting limit`);
      const item = current.item;
      if (!item || typeof item !== "object" || Array.isArray(item)) continue;
      const nested = item.fields;
      if (Array.isArray(nested)) {
        if (nested.length > maxFields) throw new Error("schema fields are missing or exceed the limit");
        nested.slice().reverse().forEach((child, index) => pending.push({ item: child, depth: current.depth + 1, path: `${current.path}.fields[${nested.length - 1 - index}]` }));
      }
      let array = item.array;
      if (array === true) array = {};
      else if (array === undefined && (item.count !== undefined || item.element !== undefined || String(item.type || "").toLowerCase() === "array")) array = { count: item.count, element: item.element };
      if (array && typeof array === "object" && !Array.isArray(array)) {
        let element = array.element ?? item.element;
        if (element === undefined) element = { type: item.element_type ?? "bytes", length: item.element_length };
        pending.push({ item: element, depth: current.depth + 1, path: `${current.path}.array.element` });
      }
    }
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
    const constraints = field.constraints || {};
    const relation = constraints.length_relationship ?? constraints.length_relation ?? (constraints.length_of !== undefined ? { target: constraints.length_of } : constraints.matches_length !== undefined ? { target: constraints.matches_length } : null);
    if (relation && typeof relation === "object") values.push({ field: relation.target ?? relation.field ?? relation.field_id ?? relation.target_field ?? relation.target_field_id });
    return values;
  }

  function graphDiagnostics(fields, definitions = {}) {
    const all = [];
    walkFields(fields, (field) => all.push(field));
    Object.keys(definitions).sort().forEach((name) => walkFields(definitions[name].fields || [], (field) => all.push(field)));
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
    all.forEach((field) => {
      if (field.definition && !Object.prototype.hasOwnProperty.call(definitions, field.definition)) diagnostics.push(diagnostic("INVALID", "missing_definition", `definition ${field.definition} does not exist`, { field_id: field.id, reference: field.definition }));
    });
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
    const normalizedBudgets = budgetsFor(schema.budgets ?? schema.limits);
    const fieldCount = { value: 0 };
    preflightFieldTree(schema.fields, normalizedBudgets.max_fields, normalizedBudgets.max_nesting, "fields", fieldCount);
    const checked = {
      schema_version: 2,
      name: String(schema.name ?? "PacketScope protocol").slice(0, 120) || "PacketScope protocol",
      description: String(schema.description ?? "").slice(0, 2000),
      coordinate_system: schema.coordinate_system ?? "raw_packet",
      budgets: normalizedBudgets,
      fields: schema.fields.map((field, index) => normalizeField(field, index, "", true)),
      coordinate: schema.coordinate === undefined ? null : jsonSafe(schema.coordinate),
      coordinates: jsonSafe(schema.coordinates ?? {}),
      source: jsonSafe(schema.source ?? {}), metadata: jsonSafe(schema.metadata ?? {}),
      definitions: {}, relationships: [],
    };
    const definitionsRaw = schema.definitions ?? {};
    if (!definitionsRaw || typeof definitionsRaw !== "object" || Array.isArray(definitionsRaw) || Object.keys(definitionsRaw).length > MAX_DEFINITIONS) throw new Error("schema definitions are invalid or exceed the limit");
    Object.keys(definitionsRaw).sort().forEach((name) => {
      if (!name.trim() || name.length > 120) throw new Error("schema definition name is invalid");
      const rawDefinition = definitionsRaw[name];
      if (!rawDefinition || typeof rawDefinition !== "object" || Array.isArray(rawDefinition)) throw new Error(`schema definition ${name} must be an object`);
      const definitionFields = rawDefinition.fields ?? [];
      if (!Array.isArray(definitionFields) || definitionFields.length > checked.budgets.max_fields) throw new Error(`schema definition ${name} fields exceed the limit`);
      preflightFieldTree(definitionFields, checked.budgets.max_fields, checked.budgets.max_nesting, `definitions.${name}.fields`, fieldCount);
      checked.definitions[name] = {
        name: String(rawDefinition.name ?? name).slice(0, 120), description: String(rawDefinition.description ?? "").slice(0, 2000),
        metadata: jsonSafe(rawDefinition.metadata ?? {}), fields: definitionFields.map((field, index) => normalizeField(field, index, name, false)),
      };
    });
    const relationshipsRaw = schema.relationships ?? schema.checksums ?? schema.checksum_relationships ?? schema.length_relationships ?? [];
    if (!Array.isArray(relationshipsRaw) || relationshipsRaw.length > checked.budgets.max_fields) throw new Error("schema relationships are invalid or exceed the limit");
    const lengthRelationshipSchema = schema.relationships === undefined && schema.checksums === undefined && schema.checksum_relationships === undefined && schema.length_relationships !== undefined;
    checked.relationships = relationshipsRaw.map((relationship, index) => {
      if (!relationship || typeof relationship !== "object" || Array.isArray(relationship)) throw new Error(`schema relationship ${index} must be an object`);
      const item = jsonSafe(relationship); if (item.id === undefined) item.id = `relationship_${index}`; if (item.kind === undefined) item.kind = lengthRelationshipSchema ? "length" : "checksum"; return item;
    });
    const ids = new Set(); let count = 0;
    fillCoordinates(checked.fields, checked.coordinate_system);
    Object.keys(checked.definitions).sort().forEach((name) => fillCoordinates(checked.definitions[name].fields, checked.coordinate_system));
    walkFields(checked.fields, (field) => { count += 1; if (count > checked.budgets.max_fields) throw new Error("schema fields are missing or exceed the limit"); if (ids.has(field.id)) throw new Error(`schema field ids must be unique: ${field.id}`); ids.add(field.id); field.coordinate_system = field.coordinate_system || checked.coordinate_system; });
    Object.keys(checked.definitions).sort().forEach((name) => walkFields(checked.definitions[name].fields, (field) => { count += 1; if (count > checked.budgets.max_fields) throw new Error("schema fields are missing or exceed the limit"); if (ids.has(field.id)) throw new Error(`schema field ids must be unique: ${field.id}`); ids.add(field.id); field.coordinate_system = field.coordinate_system || checked.coordinate_system; }));
    const graph = graphDiagnostics(checked.fields, checked.definitions);
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
    if (Array.isArray(expression)) return { status: "INVALID", value: null, diagnostics: [diagnostic("INVALID", "expression_object_required", "expression lists are only valid as operation arguments")] };
    if (!expression || typeof expression !== "object" || Array.isArray(expression)) return { status: "INVALID", value: null, diagnostics: [diagnostic("INVALID", "expression_form", "expression object is invalid")] };
    const kind = String(expression.kind || "").toLowerCase();
    if (Object.prototype.hasOwnProperty.call(expression, "static") && Object.keys(expression).length === 1) return evalExpression(expression.static, values, budgets, depth + 1);
    if (["constant", "const", "literal", "static"].includes(kind)) return evalExpression(expression.value ?? expression.constant ?? expression.const, values, budgets, depth + 1);
    const refKey = ["field", "ref", "field_ref"].find((key) => Object.prototype.hasOwnProperty.call(expression, key));
    const kindReference = !refKey && ["field", "field_ref", "field_reference", "reference", "ref"].includes(kind) ? ["field_id", "id", "name"].find((key) => typeof expression[key] === "string") : null;
    if (refKey || kindReference) {
      const reference = expression[refKey || kindReference];
      if (typeof reference !== "string") return { status: "INVALID", value: null, diagnostics: [diagnostic("INVALID", "reference_type", "field reference must be a string")] };
      const entry = values[reference];
      if (!entry) return { status: "INVALID", value: null, diagnostics: [diagnostic("INVALID", "missing_reference", `field reference ${reference} does not exist`, { reference })] };
      if (entry.status !== "RESOLVED") return { status: entry.status, value: null, diagnostics: [diagnostic(entry.status, "dependency_status", `field reference ${reference} is not resolved`, { reference })] };
      let result = { status: "RESOLVED", value: entry.internal, diagnostics: [] };
      for (const operation of ["add", "subtract", "multiply", "mask", "min", "max", "align"]) {
        if (Object.prototype.hasOwnProperty.call(expression, operation)) {
          result = applyOperation(operation, [result, evalExpression(expression[operation], values, budgets, depth + 1)], budgets);
          if (result.status !== "RESOLVED") return result;
        }
      }
      return result;
    }
    let operation = expression.op ?? kind;
    if (["comparison", "compare", "boolean", "arithmetic"].includes(operation)) operation = expression.operator ?? expression.operation;
    const aliases = Object.keys(OP_ALIASES);
    if (!operation) operation = [...ALLOWED_OPS, ...aliases].find((key) => Object.prototype.hasOwnProperty.call(expression, key));
    operation = OP_ALIASES[String(operation || "").toLowerCase()] || String(operation || "").toLowerCase();
    if (!ALLOWED_OPS.has(operation)) return { status: "INVALID", value: null, diagnostics: [diagnostic("INVALID", "unsupported_operation", `operation ${operation || "(missing)"} is not allowed`)] };
    let args = expression.args ?? expression.terms ?? expression.operands ?? expression.values;
    if (args === undefined && Object.prototype.hasOwnProperty.call(expression, "left")) args = [expression.left, expression.right];
    if (args === undefined && ["not", "negate"].includes(operation)) args = [expression.value ?? expression.arg ?? expression.input];
    if (args === undefined && operation === "mask") args = [expression.value ?? expression.input, expression.mask];
    if (args === undefined && operation === "align") args = [expression.value, expression.alignment ?? expression.boundary];
    if (args === undefined && operation === "multiply" && Object.prototype.hasOwnProperty.call(expression, "factor")) args = [expression.value, expression.factor];
    if (args === undefined && Object.prototype.hasOwnProperty.call(expression, operation)) args = expression[operation];
    if (!Array.isArray(args)) args = [args];
    if (args.length > 32) return { status: "LIMIT_EXCEEDED", value: null, diagnostics: [diagnostic("LIMIT_EXCEEDED", "expression_arguments", "expression has too many arguments")] };
    const evaluated = args.map((item) => evalExpression(item, values, budgets, depth + 1));
    const failed = evaluated.find((item) => item.status !== "RESOLVED");
    if (failed) return failed;
    const result = applyOperation(operation, evaluated, budgets);
    const boundedLimit = operation === "multiply" ? expression.max ?? expression.limit ?? expression.bound : null;
    if (result.status === "RESOLVED" && boundedLimit !== null && boundedLimit !== undefined) {
      const limitResult = evalExpression(boundedLimit, values, budgets, depth + 1); const limit = limitResult.status === "RESOLVED" ? numeric(limitResult.value) : null; const resultNumber = numeric(result.value);
      if (limit === null || resultNumber === null) return { status: "INVALID", value: null, diagnostics: [diagnostic("INVALID", "multiply_limit", "bounded multiply limit must be an integer")] };
      if ((resultNumber < 0n ? -resultNumber : resultNumber) > (limit < 0n ? -limit : limit)) return { status: "LIMIT_EXCEEDED", value: null, diagnostics: [diagnostic("LIMIT_EXCEEDED", "multiply_limit", "bounded multiply exceeds its declared limit")] };
    }
    return result;
  }

  function applyOperation(operation, evaluated, budgets) {
    const values = evaluated.map((item) => item.value);
    const numbers = () => { const converted = values.map(numeric); return converted.every((item) => item !== null) ? converted : null; };
    if (["add", "subtract", "multiply", "mask", "bitor", "xor", "min", "max", "align"].includes(operation)) {
      const converted = numbers(); if (!converted || !converted.length) return { status: "INVALID", value: null, diagnostics: [diagnostic("INVALID", "numeric_operands", `${operation} requires integer operands`)] };
      let result;
      if (operation === "add") result = converted.reduce((sum, item) => sum + item, 0n);
      else if (operation === "subtract") result = converted.length > 1 ? converted.slice(1).reduce((sum, item) => sum - item, converted[0]) : -converted[0];
      else if (operation === "multiply") result = converted.reduce((product, item) => product * item, 1n);
      else if (operation === "mask") { if (converted.length !== 2) return { status: "INVALID", value: null, diagnostics: [diagnostic("INVALID", "mask_operands", "mask requires a value and a mask")] }; result = converted[0] & converted[1]; }
      else if (operation === "bitor") result = converted.reduce((value, item) => value | item, 0n);
      else if (operation === "xor") result = converted.reduce((value, item) => value ^ item, 0n);
      else if (operation === "min") result = converted.reduce((value, item) => value < item ? value : item);
      else if (operation === "max") result = converted.reduce((value, item) => value > item ? value : item);
      else { if (converted.length !== 2 || converted[1] <= 0n) return { status: "INVALID", value: null, diagnostics: [diagnostic("INVALID", "alignment", "alignment requires a positive boundary")] }; result = ((converted[0] + converted[1] - 1n) / converted[1]) * converted[1]; }
      if (result < -BigInt(budgets.max_expression_value) || result > BigInt(budgets.max_expression_value)) return { status: "LIMIT_EXCEEDED", value: null, diagnostics: [diagnostic("LIMIT_EXCEEDED", "expression_value", "expression result exceeds the schema budget")] };
      return { status: "RESOLVED", value: result, diagnostics: [] };
    }
    if (["eq", "ne", "lt", "lte", "gt", "gte"].includes(operation)) {
      if (values.length !== 2) return { status: "INVALID", value: null, diagnostics: [diagnostic("INVALID", "comparison_operands", "comparison requires two operands")] };
      return { status: "RESOLVED", value: Boolean(compareValues(values[0], values[1], operation)), diagnostics: [] };
    }
    if (["and", "or"].includes(operation)) {
      if (!values.every((value) => typeof value === "boolean" || (typeof value === "number" && Number.isInteger(value)))) return { status: "INVALID", value: null, diagnostics: [diagnostic("INVALID", "boolean_operands", `${operation} requires boolean operands`)] };
      return { status: "RESOLVED", value: operation === "and" ? values.every(Boolean) : values.some(Boolean), diagnostics: [] };
    }
    if (operation === "not") {
      if (values.length !== 1 || !(typeof values[0] === "boolean" || (typeof values[0] === "number" && Number.isInteger(values[0])))) return { status: "INVALID", value: null, diagnostics: [diagnostic("INVALID", "boolean_operand", "not requires one boolean operand")] };
      return { status: "RESOLVED", value: !Boolean(values[0]), diagnostics: [] };
    }
    if (operation === "negate") {
      const converted = numbers(); if (!converted || converted.length !== 1) return { status: "INVALID", value: null, diagnostics: [diagnostic("INVALID", "numeric_operand", "negate requires one integer operand")] };
      if (-converted[0] < -BigInt(budgets.max_expression_value) || -converted[0] > BigInt(budgets.max_expression_value)) return { status: "LIMIT_EXCEEDED", value: null, diagnostics: [diagnostic("LIMIT_EXCEEDED", "expression_value", "expression result exceeds the schema budget")] };
      return { status: "RESOLVED", value: -converted[0], diagnostics: [] };
    }
    return { status: "INVALID", value: null, diagnostics: [diagnostic("INVALID", "unsupported_operation", `operation ${operation} is unsupported`)] };
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
      const width = integer ? integer[0] : raw.length; let signed = integer ? integer[1] : ["int", "signed", "signed_integer"].includes(type);
      if (integer && raw.length !== width) return { status: "INVALID", value: null, internal: null, diagnostics: [diagnostic("INVALID", "integer_width", "integer field width does not match its type")] };
      if (!integer && (width <= 0 || width > 16)) return { status: "INVALID", value: null, internal: null, diagnostics: [diagnostic("INVALID", "integer_width", "generic integer width is unsupported")] };
      let signedOverride = field.signed;
      if (signedOverride === null || signedOverride === undefined) {
        const constraintSigned = field.constraints && field.constraints.signed;
        if (typeof constraintSigned === "boolean") signedOverride = constraintSigned;
      }
      if (signedOverride !== null && signedOverride !== undefined) {
        if (integer && signedOverride !== signed) return { status: "INVALID", value: null, internal: null, diagnostics: [diagnostic("INVALID", "integer_signedness", "signedness conflicts with the declared integer type")] };
        signed = signedOverride;
      }
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

  function constraintNumber(value) {
    if (typeof value === "boolean") return null;
    if (typeof value === "bigint") return value;
    if (typeof value === "number" && Number.isInteger(value) && Number.isSafeInteger(value)) return BigInt(value);
    if (typeof value === "string" && /^-?\d+$/.test(value.trim())) { try { return BigInt(value.trim()); } catch { return null; } }
    return null;
  }

  function constraintEqual(actual, expected) {
    const actualNumber = constraintNumber(actual); const expectedNumber = constraintNumber(expected);
    if (actualNumber !== null && expectedNumber !== null) return actualNumber === expectedNumber;
    return typeof actual === typeof expected && actual === expected;
  }

  function constraintValues(raw) {
    if (!Array.isArray(raw)) return { values: null, error: "constraint values must be an array" };
    if (raw.length > MAX_CONSTRAINT_VALUES) return { values: null, error: "constraint values exceed the limit" };
    return { values: raw, error: null };
  }

  function maskValue(raw) {
    const number = constraintNumber(raw);
    if (number !== null && number >= 0n) return number;
    if (Array.isArray(raw)) {
      let mask = 0n;
      for (const bit of raw) {
        const bitNumber = constraintNumber(bit);
        if (bitNumber === null || bitNumber < 0n || bitNumber >= 128n) return null;
        mask |= 1n << bitNumber;
      }
      return mask;
    }
    return null;
  }

  function constraintDiag(code, message, extra = {}) { return diagnostic("INVALID", code, message, extra); }

  function constraintRelationDescriptor(field, constraints) {
    let relation = constraints.length_relationship ?? constraints.length_relation;
    if (relation === undefined && constraints.length_of !== undefined) relation = { target: constraints.length_of };
    if (relation === undefined && constraints.matches_length !== undefined) relation = { target: constraints.matches_length };
    if (relation === undefined || relation === null) return null;
    if (typeof relation === "string") return { target: relation };
    if (!relation || typeof relation !== "object" || Array.isArray(relation)) return { target: relation };
    return Object.assign({}, relation);
  }

  function validateFieldConstraints(field, result, values, checked) {
    const constraints = field.constraints || {};
    if (!constraints || typeof constraints !== "object" || Array.isArray(constraints)) return { status: "INVALID", diagnostics: [constraintDiag("constraints_type", "field constraints must be an object")] };
    const actual = result.internal !== undefined && result.internal !== null ? result.internal : result.value;
    const diagnostics = []; let invalid = false;
    function requireNumber(raw, code, label) {
      const number = constraintNumber(raw);
      if (number === null) diagnostics.push(constraintDiag(code, `${label} must be an integer`));
      return number;
    }
    const numericActual = constraintNumber(actual);
    for (const [key, aliases, comparator, reason] of [
      ["minimum", ["minimum", "min"], (value, bound) => value >= bound, "value is below the minimum"],
      ["maximum", ["maximum", "max"], (value, bound) => value <= bound, "value is above the maximum"],
      ["exact", ["exact", "equals", "equal"], (value, bound) => value === bound, "value does not equal the required value"],
    ]) {
      const declaredName = aliases.find((name) => Object.prototype.hasOwnProperty.call(constraints, name));
      if (!declaredName) continue;
      const declared = constraints[declaredName];
      if (key === "exact") {
        if (!constraintEqual(actual, declared)) { diagnostics.push(constraintDiag("exact", reason, { expected: declared, actual })); invalid = true; }
        continue;
      }
      const bound = requireNumber(declared, `${key}_type`, key);
      if (bound === null) invalid = true;
      else if (numericActual === null) { diagnostics.push(constraintDiag(`${key}_value`, `${key} requires an integer field value`)); invalid = true; }
      else if (!comparator(numericActual, bound)) { diagnostics.push(constraintDiag(key, reason, { expected: declared, actual: result.value })); invalid = true; }
    }

    for (const [key, aliases, reason] of [
      ["allowed", ["allowed", "one_of"], "value is not in the allowed set"],
      ["forbidden", ["forbidden", "not_allowed", "disallowed"], "value is in the forbidden set"],
    ]) {
      const declaredName = aliases.find((name) => Object.prototype.hasOwnProperty.call(constraints, name));
      if (!declaredName) continue;
      const declared = constraints[declaredName]; const candidates = constraintValues(declared);
      if (candidates.error) { diagnostics.push(constraintDiag(`${key}_type`, candidates.error)); invalid = true; }
      else if (key === "allowed" && !candidates.values.some((candidate) => constraintEqual(actual, candidate))) { diagnostics.push(constraintDiag("allowed", reason, { actual, allowed: candidates.values })); invalid = true; }
      else if (key === "forbidden" && candidates.values.some((candidate) => constraintEqual(actual, candidate))) { diagnostics.push(constraintDiag("forbidden", reason, { actual, forbidden: candidates.values })); invalid = true; }
    }

    const enumValue = constraints.enum; let enumPolicy = constraints.enum_policy ?? "strict"; let enumValues = enumValue;
    if (enumValue && typeof enumValue === "object" && !Array.isArray(enumValue)) {
      enumPolicy = enumValue.policy ?? enumValue.unknown_policy ?? enumPolicy;
      enumValues = enumValue.values ?? enumValue.allowed ?? Object.keys(enumValue);
    }
    if (enumValue !== undefined) {
      const policies = new Set(["strict", "diagnostic", "warn", "allow_unknown", "permissive", "open", "ignore"]);
      if (!policies.has(enumPolicy)) { diagnostics.push(constraintDiag("enum_policy", "enum policy is unsupported")); invalid = true; }
      else {
        const candidates = constraintValues(enumValues);
        if (candidates.error) { diagnostics.push(constraintDiag("enum_type", candidates.error)); invalid = true; }
        else if (!candidates.values.some((candidate) => constraintEqual(actual, candidate))) {
          if (enumPolicy === "strict") { diagnostics.push(constraintDiag("enum", "value is not declared by the enum", { actual, enum: candidates.values })); invalid = true; }
          else if (enumPolicy !== "ignore") diagnostics.push(diagnostic("RESOLVED", "enum_unknown", "value is not declared by the enum; policy permits it", { actual, enum: candidates.values, policy: enumPolicy }));
        }
      }
    }

    const width = constraints.width ?? constraints.width_bytes;
    if (width !== undefined) {
      const expectedWidth = requireNumber(width, "width_type", "width");
      const expectedNumber = expectedWidth === null ? null : Number(expectedWidth);
      if (expectedNumber !== null && ![expectedNumber, expectedNumber > 0 && expectedNumber % 8 === 0 ? expectedNumber / 8 : -1].includes(result.length)) { diagnostics.push(constraintDiag("width", "field byte width does not match the constraint", { expected: expectedWidth, actual: result.length })); invalid = true; }
    }
    if (constraints.width_bits !== undefined) {
      const expectedBits = requireNumber(constraints.width_bits, "width_bits_type", "width_bits");
      if (expectedBits === null || expectedBits <= 0n || expectedBits % 8n) { diagnostics.push(constraintDiag("width_bits", "width_bits must be a positive multiple of eight")); invalid = true; }
      else if (result.length !== Number(expectedBits / 8n)) { diagnostics.push(constraintDiag("width_bits", "field byte width does not match width_bits", { expected: expectedBits, actual: (result.length || 0) * 8 })); invalid = true; }
    }
    if (constraints.signed !== undefined) {
      const expectedSigned = constraints.signed;
      const integerTypes = new Set([...Object.keys(INTEGER_WIDTHS), "uint", "unsigned", "unsigned_integer", "int", "signed", "signed_integer", "integer"]);
      if (typeof expectedSigned !== "boolean") { diagnostics.push(constraintDiag("signed_type", "signed constraint must be boolean")); invalid = true; }
      else if (!integerTypes.has(field.type)) { diagnostics.push(constraintDiag("signed_type", "signed constraint requires an integer field")); invalid = true; }
      else if (field.signed !== null && field.signed !== undefined && field.signed !== expectedSigned) { diagnostics.push(constraintDiag("signed", "field signedness conflicts with its constraint", { expected: expectedSigned, actual: field.signed })); invalid = true; }
    }

    const bitConstraintPresent = ["mask", "bit_mask", "bitmask", "reserved", "reserved_bits", "flags", "required_flags", "forbidden_flags", "mutual_exclusion", "mutually_exclusive", "exclusive"].some((key) => Object.prototype.hasOwnProperty.call(constraints, key));
    if (numericActual !== null) {
      const maskName = ["mask", "bit_mask", "bitmask"].find((key) => Object.prototype.hasOwnProperty.call(constraints, key));
      if (maskName) {
        const rawMask = constraints[maskName]; const maskInput = rawMask && typeof rawMask === "object" && !Array.isArray(rawMask) ? (rawMask.mask ?? rawMask.allowed ?? rawMask) : rawMask; const mask = maskValue(maskInput);
        const expected = rawMask && typeof rawMask === "object" && !Array.isArray(rawMask) ? rawMask.value ?? rawMask.expected : undefined;
        if (mask === null) { diagnostics.push(constraintDiag("mask_type", "bit mask must be a non-negative integer or bit list")); invalid = true; }
        else if (expected !== undefined) { const expectedNumber = requireNumber(expected, "mask_value", "mask value"); if (expectedNumber === null || (numericActual & mask) !== (expectedNumber & mask)) { diagnostics.push(constraintDiag("mask", "masked value does not match the expected bits", { mask, expected: expectedNumber, actual: numericActual & mask })); invalid = true; } }
        else if ((numericActual & ~mask) !== 0n) { diagnostics.push(constraintDiag("mask", "value contains bits outside the allowed mask", { mask, actual: numericActual })); invalid = true; }
      }
      const reservedRaw = constraints.reserved ?? constraints.reserved_bits;
      if (reservedRaw !== undefined) {
        const reservedInput = reservedRaw && typeof reservedRaw === "object" && !Array.isArray(reservedRaw) ? (reservedRaw.mask ?? reservedRaw.bits ?? reservedRaw) : reservedRaw; const reservedMask = maskValue(reservedInput);
        if (reservedMask === null) { diagnostics.push(constraintDiag("reserved_type", "reserved bits must be a non-negative mask or bit list")); invalid = true; }
        else if ((numericActual & reservedMask) !== 0n) { diagnostics.push(constraintDiag("reserved", "reserved bits are set", { mask: reservedMask, actual: numericActual & reservedMask })); invalid = true; }
      }
      const flags = constraints.flags; const flagMasks = new Map();
      if (flags && typeof flags === "object" && !Array.isArray(flags)) Object.entries(flags).filter(([name]) => !["required", "forbidden", "reserved", "mutual_exclusion"].includes(name)).forEach(([name, mask]) => flagMasks.set(String(name), maskValue(mask)));
      else if (Array.isArray(flags)) {
        if (flags.length > MAX_CONSTRAINT_VALUES) { diagnostics.push(constraintDiag("flags_type", "flags exceed the limit")); invalid = true; }
        else flags.forEach((flag, index) => { const name = flag && typeof flag === "object" && !Array.isArray(flag) ? flag.name ?? `flag_${index}` : `flag_${index}`; const mask = flag && typeof flag === "object" && !Array.isArray(flag) ? flag.mask ?? flag.value ?? flag.bit : flag; if (typeof name !== "string") { diagnostics.push(constraintDiag("flags_type", "flag names must be strings")); invalid = true; } else flagMasks.set(name, maskValue(mask)); });
      } else if (flags !== undefined) { diagnostics.push(constraintDiag("flags_type", "flags must be an object or array of flag descriptors")); invalid = true; }
      const requiredFlags = constraints.required_flags ?? constraints.required; const forbiddenFlags = constraints.forbidden_flags;
      if (flagMasks.size) {
        for (const [flagKey, flagSet, reason] of [["required_flags", requiredFlags, "required flag is not set"], ["forbidden_flags", forbiddenFlags, "forbidden flag is set"]]) {
          if (flagSet === undefined) continue; const names = Array.isArray(flagSet) ? flagSet : [flagSet];
          if (!names.every((name) => (typeof name === "string" && flagMasks.has(name)) || maskValue(name) !== null)) { diagnostics.push(constraintDiag(`${flagKey}_type`, `${flagKey} must name declared flags`)); invalid = true; continue; }
          names.forEach((name) => { const flagMask = typeof name === "string" ? flagMasks.get(name) : maskValue(name); if (flagMask === null || flagMask === undefined) { diagnostics.push(constraintDiag("flag_mask", `flag ${name} has an invalid mask`)); invalid = true; } else if (flagKey === "required_flags" ? (numericActual & flagMask) === 0n : (numericActual & flagMask) !== 0n) { diagnostics.push(constraintDiag(flagKey, reason, { flag: name, mask: flagMask })); invalid = true; } });
        }
      } else if (requiredFlags !== undefined || forbiddenFlags !== undefined) {
        for (const [flagKey, flagSet, reason] of [["required_flags", requiredFlags, "required flag is not set"], ["forbidden_flags", forbiddenFlags, "forbidden flag is set"]]) {
          if (flagSet === undefined) continue; const masks = Array.isArray(flagSet) ? flagSet : [flagSet];
          masks.forEach((rawMask) => { const flagMask = maskValue(rawMask); if (flagMask === null) { diagnostics.push(constraintDiag(`${flagKey}_type`, `${flagKey} must contain flag names or masks`)); invalid = true; } else if (flagKey === "required_flags" ? (numericActual & flagMask) === 0n : (numericActual & flagMask) !== 0n) { diagnostics.push(constraintDiag(flagKey, reason, { mask: flagMask })); invalid = true; } });
        }
      }
      const exclusions = constraints.mutual_exclusion ?? constraints.mutually_exclusive ?? constraints.exclusive;
      if (exclusions !== undefined) {
        const namedExclusions = flagMasks.size > 0 && Array.isArray(exclusions) && exclusions.every((item) => typeof item === "string");
        const groups = namedExclusions || (Array.isArray(exclusions) && exclusions.every((item) => !item || (typeof item !== "object" && !Array.isArray(item)))) ? [exclusions] : Array.isArray(exclusions) ? exclusions : [exclusions];
        groups.forEach((group) => { const rawItems = Array.isArray(group) ? group : [group]; const masks = rawItems.map((item) => flagMasks.size && rawItems.every((entry) => typeof entry === "string") ? flagMasks.get(item) : maskValue(item && typeof item === "object" && !Array.isArray(item) ? item.mask : item)); if (masks.length < 2 || masks.some((mask) => mask === null || mask === undefined)) { diagnostics.push(constraintDiag("mutual_exclusion_type", "mutual exclusion must contain at least two valid flags or masks")); invalid = true; } else if (masks.filter((mask) => (numericActual & mask) !== 0n).length > 1) { diagnostics.push(constraintDiag("mutual_exclusion", "mutually exclusive flags are set", { masks })); invalid = true; } });
      }
    } else if (bitConstraintPresent) { diagnostics.push(constraintDiag("bit_constraint_type", "bit masks and flags require an integer field")); invalid = true; }

    const relation = constraintRelationDescriptor(field, constraints);
    if (relation !== null) {
      const target = relation.target ?? relation.field ?? relation.field_id ?? relation.target_field ?? relation.target_field_id;
      if (typeof target !== "string") { diagnostics.push(constraintDiag("length_relationship", "length relationship target must be a field id")); invalid = true; }
      else {
        const targetResult = values[target];
        if (!targetResult) { diagnostics.push(constraintDiag("length_relationship", `length relationship target ${target} does not exist`, { reference: target })); invalid = true; }
        else if (targetResult.status !== "RESOLVED") return { status: targetResult.status, diagnostics: [diagnostic(targetResult.status, "length_relationship_dependency", `length relationship target ${target} is not resolved`, { reference: target })] };
        else if (!Number.isInteger(targetResult.length)) return { status: "UNKNOWN", diagnostics: [diagnostic("UNKNOWN", "length_relationship_absent", `length relationship target ${target} has no concrete length`, { reference: target })] };
        else {
          let expected = targetResult.length; const mode = String(relation.mode ?? relation.kind ?? "length").toLowerCase();
          if (["total", "through_end", "end"].includes(mode)) expected = (targetResult.offset || 0) + (targetResult.length || 0);
          else if (["after", "bytes_after"].includes(mode)) expected = (checked._current_data_length || 0) - (targetResult.offset || 0);
          const adjustment = constraintNumber(relation.adjust ?? relation.offset ?? 0);
          if (adjustment === null) { diagnostics.push(constraintDiag("length_relationship", "length relationship adjustment must be an integer")); invalid = true; }
          else { expected += Number(adjustment); if (numericActual === null || numericActual !== BigInt(expected)) { diagnostics.push(constraintDiag("length_relationship", "length does not match the related field", { reference: target, expected, actual: numericActual, mode })); invalid = true; } }
        }
      }
    }
    return { status: invalid ? "INVALID" : "RESOLVED", diagnostics };
  }

  function publicField(field, result, present = true, items = undefined) {
    const diagnostics = (result.diagnostics || []).map((item) => Object.assign({ field_id: field.id, path: field.path || field.id, offset: result.offset ?? null, length: result.length ?? null }, item));
    const output = {
      id: field.id, path: field.path || field.id, name: field.name, description: field.description || "", status: result.status,
      present, available: result.status === "RESOLVED" && present,
      offset: result.offset ?? null, length: result.length ?? null, width: result.length ?? null,
      coordinate_system: field.coordinate_system, value: present ? (result.value ?? null) : null,
      value_encoding: result.encoding ?? null,
      diagnostics: diagnostics.sort((left, right) => `${left.code || ""}:${left.message || ""}:${left.reference || ""}`.localeCompare(`${right.code || ""}:${right.message || ""}:${right.reference || ""}`)).slice(0, 32),
    };
    if (items) output.items = items;
    return output;
  }

  function resolveNonnegativeLength(expression, values, budgets) {
    const evaluated = evalExpression(expression, values, budgets);
    if (evaluated.status !== "RESOLVED") return { status: evaluated.status, length: null, diagnostics: evaluated.diagnostics || [] };
    const value = numeric(evaluated.value);
    if (value === null || value < 0n) return { status: "INVALID", length: null, diagnostics: [diagnostic("INVALID", "length", "length must be a non-negative integer")] };
    return { status: "RESOLVED", length: Number(value), diagnostics: [] };
  }

  function parseField(field, context, baseOffset, depth = 0, store = true) {
    const { data, metadata, values, checked } = context; const budgets = checked.budgets;
    const runtime = context.runtime;
    if (runtime.outputFields >= budgets.max_output_fields) { const result = { status: "LIMIT_EXCEEDED", diagnostics: [diagnostic("LIMIT_EXCEEDED", "output_fields", "decoded field output exceeds the schema budget")] }; return [publicField(field, result, false), result]; }
    runtime.outputFields += 1;
    if (depth > budgets.max_nesting) { const result = { status: "LIMIT_EXCEEDED", diagnostics: [diagnostic("LIMIT_EXCEEDED", "nesting", "nested structure exceeds the schema budget")] }; return [publicField(field, result, false), result]; }
    if (data !== null && data.length > budgets.max_bytes_per_packet) { const result = { status: "LIMIT_EXCEEDED", diagnostics: [diagnostic("LIMIT_EXCEEDED", "packet_bytes", "packet coordinate bytes exceed the schema budget")] }; return [publicField(field, result, false), result]; }
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
    let nestedFields = field.fields;
    if (field.definition !== null && field.definition !== undefined) {
      const definition = checked.definitions[field.definition];
      if (!definition) { const result = { status: "INVALID", offset: absolute, diagnostics: [diagnostic("INVALID", "missing_definition", `definition ${field.definition} does not exist`)] }; if (store) values[field.id] = result; return [publicField(field, result), result]; }
      nestedFields = definition.fields;
    }
    if (Array.isArray(nestedFields) || ["struct", "structure"].includes(field.type)) {
      if (!Array.isArray(nestedFields)) { const result = { status: "INVALID", offset: absolute, diagnostics: [diagnostic("INVALID", "nested_fields", "structured field has no fields")] }; if (store) values[field.id] = result; return [publicField(field, result), result]; }
      let explicitLength = null;
      if (field.length !== null) {
        const lengthResult = resolveNonnegativeLength(field.length, values, budgets);
        if (lengthResult.status !== "RESOLVED") { const result = { status: lengthResult.status, offset: absolute, diagnostics: lengthResult.diagnostics }; if (store) values[field.id] = result; return [publicField(field, result), result]; }
        explicitLength = lengthResult.length;
        if (explicitLength > budgets.max_field_length) { const result = { status: "LIMIT_EXCEEDED", offset: absolute, length: explicitLength, diagnostics: [diagnostic("LIMIT_EXCEEDED", "field_length", "field length exceeds the schema budget")] }; if (store) values[field.id] = result; return [publicField(field, result), result]; }
        if (absolute + explicitLength > budgets.max_bytes_per_packet) { const result = { status: "LIMIT_EXCEEDED", offset: absolute, length: explicitLength, diagnostics: [diagnostic("LIMIT_EXCEEDED", "packet_budget", "field range exceeds the packet budget")] }; if (store) values[field.id] = result; return [publicField(field, result), result]; }
        if (absolute + explicitLength > data.length) { const result = { status: "OUT_OF_BOUNDS", offset: absolute, length: explicitLength, diagnostics: [diagnostic("OUT_OF_BOUNDS", "truncated_field", "field range extends beyond captured bytes")] }; if (store) values[field.id] = result; return [publicField(field, result), result]; }
      }
      const childValues = {}; const childOutputs = []; let end = absolute; let status = "RESOLVED";
      nestedFields.slice(0, budgets.max_fields).forEach((child) => { const childContext = Object.assign({}, context, { values: Object.assign({}, values, childValues) }); const [output, result] = parseField(child, childContext, absolute, depth + 1); childValues[child.id] = result; childValues[child.name] = result; childOutputs.push(output); if (Number.isInteger(result.offset) && Number.isInteger(result.length)) end = Math.max(end, result.offset + result.length); status = mergeStatus(status, result.status); });
      let length = explicitLength === null ? end - absolute : explicitLength;
      if (length > budgets.max_field_length || absolute + length > budgets.max_bytes_per_packet) status = mergeStatus(status, "LIMIT_EXCEEDED");
      else if (absolute + length > data.length) status = mergeStatus(status, "OUT_OF_BOUNDS");
      const result = { status, value: Object.fromEntries(childOutputs.map((item) => [item.id, item.value])), internal: Object.fromEntries(nestedFields.map((child) => [child.id, childValues[child.id]?.internal])), offset: absolute, length, diagnostics: status === "RESOLVED" ? [] : [diagnostic(status, "nested_status", "nested structure contains a non-resolved field")] };
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
    const decoded = decode(data.slice(absolute, absolute + length), field); const result = Object.assign(decoded, { offset: absolute, length });
    if (decoded.status === "RESOLVED") {
      checked._current_data_length = data.length;
      const constraintResult = validateFieldConstraints(field, result, values, checked);
      result.diagnostics.push(...constraintResult.diagnostics);
      if (constraintResult.status !== "RESOLVED") result.status = constraintResult.status;
    }
    const output = publicField(field, result); if (store) values[field.id] = result; return [output, result];
  }

  function parseArray(field, context, absolute, depth, store) {
    const { data, values, checked } = context; const countResult = evalExpression(field.array.count, values, checked.budgets); const baseResult = { offset: absolute };
    let declaredLength = null;
    if (field.length !== null) {
      const lengthResult = resolveNonnegativeLength(field.length, values, checked.budgets);
      if (lengthResult.status !== "RESOLVED") { const result = Object.assign(baseResult, { status: lengthResult.status, diagnostics: lengthResult.diagnostics }); if (store) values[field.id] = result; return [publicField(field, result), result]; }
      declaredLength = lengthResult.length;
      if (declaredLength > checked.budgets.max_field_length) { const result = Object.assign(baseResult, { status: "LIMIT_EXCEEDED", length: declaredLength, diagnostics: [diagnostic("LIMIT_EXCEEDED", "field_length", "field length exceeds the schema budget")] }); if (store) values[field.id] = result; return [publicField(field, result), result]; }
      if (absolute + declaredLength > checked.budgets.max_bytes_per_packet) { const result = Object.assign(baseResult, { status: "LIMIT_EXCEEDED", length: declaredLength, diagnostics: [diagnostic("LIMIT_EXCEEDED", "packet_budget", "field range exceeds the packet budget")] }); if (store) values[field.id] = result; return [publicField(field, result), result]; }
      if (absolute + declaredLength > data.length) { const result = Object.assign(baseResult, { status: "OUT_OF_BOUNDS", length: declaredLength, diagnostics: [diagnostic("OUT_OF_BOUNDS", "truncated_field", "field range extends beyond captured bytes")] }); if (store) values[field.id] = result; return [publicField(field, result), result]; }
    }
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
    let length = Math.max(0, cursor - absolute);
    if (declaredLength !== null) { if (length > declaredLength) status = mergeStatus(status, "OUT_OF_BOUNDS"); else length = declaredLength; }
    const result = { status, value: publicValues, internal: items.map((item) => item.value), offset: absolute, length, diagnostics: status === "RESOLVED" ? [] : [diagnostic(status, "array_status", "array contains a non-resolved element")] }; const output = publicField(field, result, true, items); if (store) values[field.id] = result; return [output, result];
  }

  function apply(schema, packetList) {
    const checked = migrate(schema); const source = Array.isArray(packetList) ? packetList : []; const values = [];
    const limit = Math.min(source.length, checked.budgets.max_packets, 100000); const truncated = source.length > limit;
    for (let packetIndex = 0; packetIndex < limit; packetIndex += 1) {
      const packet = source[packetIndex]; const fields = []; const valueMap = {}; const runtime = { arrayItems: 0, outputFields: 0 }; const cache = new Map();
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
        const missing = (graph.diagnostics || []).filter((item) => item.field_id === field.id && ["missing_reference", "missing_definition"].includes(item.code));
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
