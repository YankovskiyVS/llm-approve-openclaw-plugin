const STANDARD_OBJECT_PROTOTYPE_NAMES = new Set([
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

export function objectPrototypeIsPristine() {
  try {
    const names = Object.getOwnPropertyNames(Object.prototype);
    return names.length === STANDARD_OBJECT_PROTOTYPE_NAMES.size
      && names.every((name) => STANDARD_OBJECT_PROTOTYPE_NAMES.has(name))
      && Object.getOwnPropertySymbols(Object.prototype).length === 0;
  } catch {
    return false;
  }
}
