/** Reorder a plain-object request before CBOR encoding. INS is a number. */
export function orderCborRequest(ins, request, fieldOrders) {
  const command = `0x${ins.toString(16).padStart(2, '0').toUpperCase()}`;

  return orderMap(request, '$', fieldOrders[command]);
}

function orderMap(value, path, orders) {
  const order = orders?.[path];

  if (!order || value === null || typeof value !== 'object') {
    return value;
  }

  const prototype = Object.getPrototypeOf(value);

  if (prototype !== Object.prototype && prototype !== null) {
    return value;
  }

  const remaining = new Map(Object.entries(value));
  const entries = [];

  for (const key of order) {
    if (remaining.has(key)) {
      entries.push([key, remaining.get(key)]);
      remaining.delete(key);
    }
  }

  return Object.fromEntries(
    [...entries, ...remaining].map(([key, child]) => [
      key,
      orderMap(child, `${path}.${key}`, orders),
    ]),
  );
}
