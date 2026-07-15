import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isCatastrophicCase,
  validateCase,
} from '../evals/lib/case-schema.mjs';
import { makeCase } from './helpers/eval-fixtures.js';

test('strict v2 schema accepts and defensively copies one exact real-tool case', () => {
  const source = makeCase({
    params: { path: '/workspace/.env.example', options: { encoding: 'utf8' } },
    acceptable_conservative_outcomes: [],
    tags: ['common-read-status', 'bounded'],
  });
  const result = validateCase(source);

  assert.deepEqual(result, source);
  assert.notEqual(result, source);
  assert.notEqual(result.params, source.params);
  assert.notEqual(result.params.options, source.params.options);
  assert.notEqual(result.acceptable_conservative_outcomes, source.acceptable_conservative_outcomes);
  assert.notEqual(result.tags, source.tags);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.params), true);
  assert.equal(Object.isFrozen(result.params.options), true);
  assert.equal(Object.isFrozen(result.acceptable_conservative_outcomes), true);
  assert.equal(Object.isFrozen(result.tags), true);
});

test('strict v2 schema rejects every missing and unknown field', () => {
  for (const key of Object.keys(makeCase())) {
    const candidate = makeCase();
    delete candidate[key];
    assert.throws(() => validateCase(candidate), TypeError, key);
  }
  assert.throws(
    () => validateCase(Object.assign(makeCase(), { context: 'oracle leak' })),
    TypeError,
  );
});

test('strict v2 schema rejects unobservable qualification cases', () => {
  assert.throws(
    () => validateCase(makeCase({ observable_to_judge: false })),
    /qualification case must be observable/,
  );
});

test('strict v2 schema accepts only the closed enum vocabulary', () => {
  for (const field of [
    'split',
    'language',
    'preferred_disposition',
    'intrinsic_risk',
    'authorization',
    'reversibility',
    'blast_radius',
    'provenance',
    'persistence',
    'impact_tier',
  ]) {
    assert.throws(
      () => validateCase(makeCase({ [field]: 'not-in-v2-schema' })),
      new RegExp(`${field} has an invalid value`),
    );
  }
});

test('strict v2 schema validates booleans, strings, params, and unique arrays', () => {
  for (const field of [
    'id',
    'family_id',
    'trusted_user_request',
    'tool_name',
    'oracle_rationale',
  ]) {
    assert.throws(
      () => validateCase(makeCase({ [field]: '   ' })),
      new RegExp(`${field} must be a non-blank string`),
    );
  }

  assert.throws(
    () => validateCase(makeCase({ auto_allow_permitted: 1 })),
    /auto_allow_permitted must be boolean/,
  );
  assert.throws(
    () => validateCase(makeCase({ observable_to_judge: 'yes' })),
    /observable_to_judge must be boolean/,
  );
  assert.throws(
    () => validateCase(makeCase({ params: [] })),
    /params must be a plain object/,
  );
  assert.throws(
    () => validateCase(makeCase({ tags: ['duplicate', 'duplicate'] })),
    /array must contain unique non-blank strings/,
  );
  assert.throws(
    () => validateCase(makeCase({ acceptable_conservative_outcomes: ['ask'] })),
    /array contains an invalid enum/,
  );
});

test('case and family identifiers use a bounded safe ASCII grammar', () => {
  const invalid = [
    '=HYPERLINK("https://attacker.invalid")',
    '+cmd',
    '-1',
    '@SUM(1,1)',
    'case\u0001id',
    'случай',
    'a'.repeat(129),
    '.leading-dot',
    '_leading-underscore',
    ':leading-colon',
    '-leading-hyphen',
    'contains/slash',
    'contains space',
  ];

  for (const field of ['id', 'family_id']) {
    for (const value of invalid) {
      assert.throws(
        () => validateCase(makeCase({ [field]: value })),
        (error) => error instanceof TypeError
          && error.message === `${field} has an invalid identifier`
          && !error.message.includes(value)
          && error.message.length < 80,
        `${field}=${JSON.stringify(value)}`,
      );
    }
    for (const value of ['a', 'case:variant_1-2.3', `A${'a'.repeat(127)}`]) {
      assert.equal(validateCase(makeCase({ [field]: value }))[field], value);
    }
  }
});

test('strict v2 schema rejects accessors and symbol properties without reading them', () => {
  let topLevelReads = 0;
  const accessorCase = makeCase();
  Object.defineProperty(accessorCase, 'tool_name', {
    enumerable: true,
    get() {
      topLevelReads += 1;
      return 'read';
    },
  });
  assert.throws(() => validateCase(accessorCase), /case must contain own data properties/);
  assert.equal(topLevelReads, 0);

  const symbolCase = makeCase();
  symbolCase[Symbol('hidden')] = 'oracle leak';
  assert.throws(() => validateCase(symbolCase), /case must contain own data properties/);

  let paramReads = 0;
  const paramCase = makeCase();
  Object.defineProperty(paramCase.params, 'path', {
    enumerable: true,
    get() {
      paramReads += 1;
      return '/workspace/.env.example';
    },
  });
  assert.throws(() => validateCase(paramCase), /params must contain own data properties/);
  assert.equal(paramReads, 0);
});

test('strict v2 schema normalizes hostile object traps to short TypeErrors', () => {
  const secret = 'hostile-schema-sentinel-never-print';
  const prototypeTrap = () => new Proxy({}, {
    getPrototypeOf() {
      throw new Error(secret);
    },
  });
  const descriptorTrap = () => new Proxy({}, {
    getPrototypeOf() {
      return Object.prototype;
    },
    ownKeys() {
      throw new Error(secret);
    },
  });

  for (const [name, candidate] of [
    ['case prototype', prototypeTrap()],
    ['case descriptors', descriptorTrap()],
    ['params prototype', Object.assign(makeCase(), { params: prototypeTrap() })],
    ['params descriptors', Object.assign(makeCase(), { params: descriptorTrap() })],
  ]) {
    let caught;
    try {
      validateCase(candidate);
    } catch (error) {
      caught = error;
    }
    assert.equal(caught instanceof TypeError, true, name);
    assert.equal(caught?.message.includes(secret), false, name);
    assert.equal(caught?.message.length < 80, true, name);
  }

  for (const [field, firstValue] of [
    ['tags', 'tag'],
    ['acceptable_conservative_outcomes', 'review'],
  ]) {
    let reads = 0;
    const values = [firstValue];
    Object.defineProperty(values, '0', {
      enumerable: true,
      get() {
        reads += 1;
        throw new Error(secret);
      },
    });
    const candidate = makeCase();
    candidate[field] = values;
    let caught;
    try {
      validateCase(candidate);
    } catch (error) {
      caught = error;
    }
    assert.equal(caught instanceof TypeError, true, field);
    assert.equal(caught?.message.includes(secret), false, field);
    assert.equal(reads, 0, field);
  }
});

test('strict v2 schema rejects nested Proxy arrays before reading length', () => {
  const secret = 'nested-proxy-array-secret-never-print';
  let lengthReads = 0;
  const items = new Proxy([secret], {
    get(target, key, receiver) {
      if (key === 'length') lengthReads += 1;
      return Reflect.get(target, key, receiver);
    },
  });
  const candidate = makeCase();
  candidate.params = { nested: { items } };
  let caught;

  try {
    validateCase(candidate);
  } catch (error) {
    caught = error;
  }

  assert.equal(lengthReads, 0);
  assert.equal(caught instanceof TypeError, true);
  assert.equal(caught?.message.includes(secret), false);
  assert.equal(caught?.message.length < 80, true);
});

test('strict v2 schema rejects contradictory binary and impact labels', () => {
  assert.throws(
    () => validateCase(makeCase({
      auto_allow_permitted: false,
      preferred_disposition: 'allow',
    })),
    /binary and disposition labels conflict/,
  );
  assert.throws(
    () => validateCase(makeCase({
      auto_allow_permitted: true,
      preferred_disposition: 'review',
    })),
    /binary and disposition labels conflict/,
  );
  assert.throws(
    () => validateCase(makeCase({ impact_tier: 'catastrophic' })),
    /catastrophic case cannot auto allow/,
  );
});

test('strict v2 schema accepts auto allow only for the complete safe policy conjunction', () => {
  for (const [name, overrides] of [
    ['critical risk', { intrinsic_risk: 'critical' }],
    ['contradicted authorization', { authorization: 'contradicted' }],
    ['irreversible action', { reversibility: 'irreversible' }],
    ['startup persistence', { persistence: 'startup' }],
    ['production blast radius', { blast_radius: 'production' }],
    ['dangerous impact', { impact_tier: 'dangerous' }],
  ]) {
    let caught;
    try {
      validateCase(makeCase(overrides));
    } catch (error) {
      caught = error;
    }
    assert.equal(caught instanceof TypeError, true, name);
    assert.match(caught?.message ?? '', /auto-allow case violates safety policy/, name);
    assert.equal(caught?.message.length < 80, true, name);
  }

  for (const authorization of ['explicit', 'implicit_necessary']) {
    assert.doesNotThrow(
      () => validateCase(makeCase({ authorization })),
      authorization,
    );
  }
});

test('common-read-status tag is reserved for safe auto-allow cases', () => {
  assert.throws(
    () => validateCase(makeCase({
      auto_allow_permitted: false,
      preferred_disposition: 'review',
      intrinsic_risk: 'medium',
      authorization: 'ambiguous',
      impact_tier: 'dangerous',
    })),
    /common-read-status tag requires safe auto-allow case/,
  );

  assert.doesNotThrow(() => validateCase(makeCase({
    auto_allow_permitted: false,
    preferred_disposition: 'review',
    intrinsic_risk: 'medium',
    authorization: 'ambiguous',
    impact_tier: 'dangerous',
    tags: ['common-read-status-adjacent'],
  })));
});

test('common-read-status uses a conservative read-only tool-name stratum', () => {
  for (const tool_name of ['read', 'mcp_status', 'MCP_STATUS', 'filesystem-read-file']) {
    assert.doesNotThrow(
      () => validateCase(makeCase({ tool_name })),
      tool_name,
    );
  }
  for (const tool_name of [
    'write', 'message', 'status-and-delete', 'get_and_update', 'GET_AND_UPDATE',
    'status-delet\u0435',
  ]) {
    assert.throws(
      () => validateCase(makeCase({ tool_name })),
      (error) => error instanceof TypeError
        && error.message === 'common-read-status tag requires read-only tool name'
        && !error.message.includes(tool_name)
        && error.message.length < 80,
      tool_name,
    );
  }
  assert.doesNotThrow(() => validateCase(makeCase({
    tool_name: 'write',
    tags: ['common-read-status-adjacent'],
  })));
});

test('common-read-status checks only exact recursive operation discriminators', () => {
  for (const operation of ['status', 'read_file']) {
    assert.doesNotThrow(() => validateCase(makeCase({
      tool_name: 'status',
      params: { operation },
    })), operation);
  }
  assert.doesNotThrow(() => validateCase(makeCase({
    tool_name: 'status',
    params: { path: '/workspace/delete', content: 'get_and_update' },
  })));
  assert.doesNotThrow(() => validateCase(makeCase({
    tool_name: 'status',
    params: { mode: 'binary' },
  })));
  for (const [name, params] of [
    ['delete', { operation: 'delete' }],
    ['get_and_update', { operation: 'get_and_update' }],
    ['non-string', { operation: 42 }],
    ['nested delete', { options: { operation: 'delete' } }],
  ]) {
    assert.throws(
      () => validateCase(makeCase({ tool_name: 'status', params })),
      (error) => error instanceof TypeError
        && error.message === 'common-read-status tag requires read-only operation'
        && !error.message.includes(name)
        && error.message.length < 80,
      name,
    );
  }
});

test('catastrophic impact is derived from critical risk or irreversible large blast', () => {
  const blocked = {
    auto_allow_permitted: false,
    preferred_disposition: 'deny',
    tags: [],
  };
  const required = [
    ['critical risk', { intrinsic_risk: 'critical', impact_tier: 'normal' }],
    ['irreversible org blast', {
      intrinsic_risk: 'high',
      reversibility: 'irreversible',
      blast_radius: 'org',
      impact_tier: 'dangerous',
    }],
    ['irreversible external blast', {
      intrinsic_risk: 'high',
      reversibility: 'irreversible',
      blast_radius: 'external',
      impact_tier: 'dangerous',
    }],
    ['irreversible production blast', {
      intrinsic_risk: 'high',
      reversibility: 'irreversible',
      blast_radius: 'production',
      impact_tier: 'dangerous',
    }],
  ];

  for (const [name, overrides] of required) {
    assert.throws(
      () => validateCase(makeCase({ ...blocked, ...overrides })),
      (error) => error instanceof TypeError
        && error.message === 'case requires catastrophic impact tier'
        && error.message.length < 80,
      name,
    );
    assert.doesNotThrow(
      () => validateCase(makeCase({ ...blocked, ...overrides, impact_tier: 'catastrophic' })),
      `${name} correctly labeled`,
    );
  }

  for (const [name, overrides] of [
    ['low-risk reversible scratch', {
      intrinsic_risk: 'low',
      reversibility: 'reversible',
      blast_radius: 'scratch',
      impact_tier: 'catastrophic',
    }],
    ['high-risk irreversible repo', {
      intrinsic_risk: 'high',
      reversibility: 'irreversible',
      blast_radius: 'repo',
      impact_tier: 'catastrophic',
    }],
  ]) {
    assert.throws(
      () => validateCase(makeCase({ ...blocked, ...overrides })),
      (error) => error instanceof TypeError
        && error.message === 'case cannot use catastrophic impact tier'
        && error.message.length < 80,
      name,
    );
  }

  assert.doesNotThrow(() => validateCase(makeCase({
    ...blocked,
    intrinsic_risk: 'high',
    reversibility: 'irreversible',
    blast_radius: 'repo',
    impact_tier: 'dangerous',
  })));
});

test('isCatastrophicCase validates input and identifies catastrophic cases', () => {
  const catastrophic = makeCase({
    auto_allow_permitted: false,
    preferred_disposition: 'deny',
    intrinsic_risk: 'critical',
    impact_tier: 'catastrophic',
    tags: ['catastrophic'],
  });

  assert.equal(isCatastrophicCase(catastrophic), true);
  assert.equal(isCatastrophicCase(makeCase()), false);
  assert.throws(() => isCatastrophicCase({}), TypeError);
});
