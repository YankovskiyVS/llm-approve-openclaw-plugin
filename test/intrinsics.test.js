import test from 'node:test';
import assert from 'node:assert/strict';
import {
  arrayPrototypeIsPristine,
  objectPrototypeIsPristine,
} from '../src/intrinsics.js';

test('prototype integrity checks detect own, descriptor, and chain mutations', () => {
  assert.equal(objectPrototypeIsPristine(), true);
  assert.equal(arrayPrototypeIsPristine(), true);

  Object.defineProperty(Object.prototype, 'intrinsicsObjectProbe', {
    configurable: true,
    value: true,
  });
  try {
    assert.equal(objectPrototypeIsPristine(), false);
  } finally {
    delete Object.prototype.intrinsicsObjectProbe;
  }

  Object.defineProperty(Array.prototype, 'intrinsicsArrayProbe', {
    configurable: true,
    value: true,
  });
  try {
    assert.equal(arrayPrototypeIsPristine(), false);
  } finally {
    delete Array.prototype.intrinsicsArrayProbe;
  }

  const mapDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, 'map');
  Object.defineProperty(Array.prototype, 'map', {
    ...mapDescriptor,
    value() { return []; },
  });
  try {
    assert.equal(arrayPrototypeIsPristine(), false);
  } finally {
    Object.defineProperty(Array.prototype, 'map', mapDescriptor);
  }

  const originalParent = Object.getPrototypeOf(Array.prototype);
  Object.setPrototypeOf(Array.prototype, Object.create(originalParent));
  try {
    assert.equal(arrayPrototypeIsPristine(), false);
  } finally {
    Object.setPrototypeOf(Array.prototype, originalParent);
  }

  assert.equal(objectPrototypeIsPristine(), true);
  assert.equal(arrayPrototypeIsPristine(), true);
});
