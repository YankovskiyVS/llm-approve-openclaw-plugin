const OBJECT_PROTOTYPE = Object.prototype;
const ARRAY_PROTOTYPE = Array.prototype;
const GET_OWN_PROPERTY_NAMES = Object.getOwnPropertyNames;
const GET_OWN_PROPERTY_SYMBOLS = Object.getOwnPropertySymbols;
const GET_OWN_PROPERTY_DESCRIPTOR = Object.getOwnPropertyDescriptor;
const GET_PROTOTYPE_OF = Object.getPrototypeOf;
const HAS_OWN = Object.hasOwn;
const REFLECT_OWN_KEYS = Reflect.ownKeys;

const STANDARD_OBJECT_PROTOTYPE_NAMES = Object.freeze([
  '__defineGetter__',
  '__defineSetter__',
  '__lookupGetter__',
  '__lookupSetter__',
  '__proto__',
  'constructor',
  'hasOwnProperty',
  'isPrototypeOf',
  'propertyIsEnumerable',
  'toLocaleString',
  'toString',
  'valueOf',
]);

const STANDARD_ARRAY_PROTOTYPE_NAMES = Object.freeze([
  'length',
  'constructor',
  'at',
  'concat',
  'copyWithin',
  'fill',
  'find',
  'findIndex',
  'findLast',
  'findLastIndex',
  'lastIndexOf',
  'pop',
  'push',
  'reverse',
  'shift',
  'unshift',
  'slice',
  'sort',
  'splice',
  'includes',
  'indexOf',
  'join',
  'keys',
  'entries',
  'values',
  'forEach',
  'filter',
  'flat',
  'flatMap',
  'map',
  'every',
  'some',
  'reduce',
  'reduceRight',
  'toReversed',
  'toSorted',
  'toSpliced',
  'with',
  'toLocaleString',
  'toString',
]);
const STANDARD_ARRAY_PROTOTYPE_SYMBOLS = Object.freeze([
  Symbol.iterator,
  Symbol.unscopables,
]);

function containsExact(values, expected) {
  for (let index = 0; index < values.length; index += 1) {
    if (values[index] === expected) return true;
  }
  return false;
}

function freezeDescriptorSnapshot(prototype) {
  const keys = REFLECT_OWN_KEYS(prototype);
  const snapshot = new Array(keys.length);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    snapshot[index] = Object.freeze({
      key,
      descriptor: Object.freeze({ ...GET_OWN_PROPERTY_DESCRIPTOR(prototype, key) }),
    });
  }
  return Object.freeze(snapshot);
}

const OBJECT_PROTOTYPE_SNAPSHOT = freezeDescriptorSnapshot(OBJECT_PROTOTYPE);
const ARRAY_PROTOTYPE_SNAPSHOT = freezeDescriptorSnapshot(ARRAY_PROTOTYPE);

function matchingSnapshotEntry(snapshot, key) {
  for (let index = 0; index < snapshot.length; index += 1) {
    if (snapshot[index].key === key) return snapshot[index];
  }
  return null;
}

function descriptorMatches(current, baseline) {
  const currentFields = REFLECT_OWN_KEYS(current);
  const baselineFields = REFLECT_OWN_KEYS(baseline);
  if (currentFields.length !== baselineFields.length) return false;
  for (let index = 0; index < currentFields.length; index += 1) {
    const field = currentFields[index];
    if (!containsExact(baselineFields, field)
      || HAS_OWN(current, field) !== HAS_OWN(baseline, field)
      || current[field] !== baseline[field]) return false;
  }
  return true;
}

function descriptorMatchesSnapshot(prototype, snapshot) {
  const keys = REFLECT_OWN_KEYS(prototype);
  if (keys.length !== snapshot.length) return false;
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    const baseline = matchingSnapshotEntry(snapshot, key);
    const current = GET_OWN_PROPERTY_DESCRIPTOR(prototype, key);
    if (baseline === null || !current || !descriptorMatches(current, baseline.descriptor)) {
      return false;
    }
  }
  return true;
}

function exactKeys(values, expected) {
  if (values.length !== expected.length) return false;
  for (let index = 0; index < values.length; index += 1) {
    if (!containsExact(expected, values[index])) return false;
  }
  return true;
}

export function objectPrototypeIsPristine() {
  try {
    return exactKeys(
      GET_OWN_PROPERTY_NAMES(OBJECT_PROTOTYPE),
      STANDARD_OBJECT_PROTOTYPE_NAMES,
    )
      && GET_OWN_PROPERTY_SYMBOLS(OBJECT_PROTOTYPE).length === 0
      && GET_PROTOTYPE_OF(OBJECT_PROTOTYPE) === null
      && descriptorMatchesSnapshot(OBJECT_PROTOTYPE, OBJECT_PROTOTYPE_SNAPSHOT);
  } catch {
    return false;
  }
}

export function arrayPrototypeIsPristine() {
  try {
    return exactKeys(
      GET_OWN_PROPERTY_NAMES(ARRAY_PROTOTYPE),
      STANDARD_ARRAY_PROTOTYPE_NAMES,
    )
      && exactKeys(
        GET_OWN_PROPERTY_SYMBOLS(ARRAY_PROTOTYPE),
        STANDARD_ARRAY_PROTOTYPE_SYMBOLS,
      )
      && GET_PROTOTYPE_OF(ARRAY_PROTOTYPE) === OBJECT_PROTOTYPE
      && descriptorMatchesSnapshot(ARRAY_PROTOTYPE, ARRAY_PROTOTYPE_SNAPSHOT);
  } catch {
    return false;
  }
}
