/* Shared, dependency-free schema application for the browser and Node tests.
 * Values are strings so JSON serialization never routes a 64-bit integer
 * through an IEEE-754 Number.  Incomplete ranges return null, never a
 * misleading partial hex string.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.PacketScopeSchema = api;
})(typeof globalThis !== "undefined" ? globalThis : this, () => {
  const COORDINATE_SYSTEMS = new Set(["raw_packet", "application_payload"]);

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
    if (normalizedType === "INT64" && raw.length === 8 && value >= (1n << 63n)) value -= 1n << 64n;
    return value.toString(10);
  }

  function apply(schema, packetList) {
    const defaultCoordinateSystem = schema.coordinate_system || "raw_packet";
    if (!COORDINATE_SYSTEMS.has(defaultCoordinateSystem)) throw new Error("schema coordinate_system is invalid");
    return packetList.slice(0, 100000).map((packet) => {
      const cache = new Map();
      const fields = schema.fields.map((field) => {
        const coordinateSystem = field.coordinate_system || defaultCoordinateSystem;
        if (!cache.has(coordinateSystem)) cache.set(coordinateSystem, bytesFor(packet, coordinateSystem));
        const bytes = cache.get(coordinateSystem);
        const raw = bytes === null ? [] : bytes.slice(field.offset, field.offset + field.width);
        const available = bytes !== null && raw.length === field.width;
        let value = null;
        let valueEncoding = null;
        if (available) {
          if (["big", "little"].includes(field.endian) && field.width <= 8) {
            value = integerValue(raw, field.endian, field.type);
            valueEncoding = "decimal_string";
          } else {
            value = raw.join("");
            valueEncoding = "hex";
          }
        }
        return {
          name: field.name,
          offset: field.offset,
          width: field.width,
          coordinate_system: coordinateSystem,
          value,
          value_encoding: valueEncoding,
          available,
        };
      });
      return { packetId: packet.index, fields };
    });
  }

  return { apply, bytesFor, integerValue };
});
