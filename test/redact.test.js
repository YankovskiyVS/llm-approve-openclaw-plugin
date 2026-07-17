import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isSecretBearingKey,
  redactForJudge,
  redactForJudgeWithProvenance,
} from '../src/redact.js';

const REDACTED = '[REDACTED]';

test('returns frozen boolean-only provenance without changing redacted bytes', () => {
  const secret = 'api_token=provenance-fixture-never-send-1b2';
  const input = {
    nested: { payload: secret },
    long: 'x'.repeat(5_000),
  };
  const result = redactForJudgeWithProvenance(input);

  assert.deepEqual(result.value, redactForJudge(input));
  assert.deepEqual(Object.keys(result), ['value', 'secret_redacted', 'truncated', 'opaque']);
  assert.equal(result.secret_redacted, true);
  assert.equal(result.truncated, true);
  assert.equal(result.opaque, true);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(JSON.stringify(result).includes(secret), false);
});

test('distinguishes a pre-existing marker from newly detected secret provenance', () => {
  for (const message of [
    '[REDACTED]',
    'api_token=[REDACTED]',
    'Bearer [REDACTED]',
    'Bearer [TRUNCATED]',
    'Bearer [REDACTED PRIVATE KEY]',
    '[TRUNCATED]',
  ]) {
    const literal = redactForJudgeWithProvenance({ message });
    assert.equal(literal.secret_redacted, false, message);
    assert.equal(literal.truncated, false, message);
    assert.equal(literal.opaque, true, message);
  }

  const secret = redactForJudgeWithProvenance({ message: 'Bearer actual-fixture-token-3d4' });
  assert.equal(secret.secret_redacted, true);
  assert.equal(secret.truncated, false);
  assert.equal(secret.opaque, true);

  const secretBeforeMarker = redactForJudgeWithProvenance({
    message: 'Bearer actual-fixture-token-3d4 [TRUNCATED]',
  });
  assert.equal(secretBeforeMarker.secret_redacted, true);
  assert.equal(secretBeforeMarker.opaque, true);
});

test('tracks nested secret and truncation provenance idempotently without values or paths', () => {
  const first = redactForJudgeWithProvenance({
    items: [{ password: 'nested-provenance-fixture-4e5' }],
    note: 'z'.repeat(4_097),
  });
  const second = redactForJudgeWithProvenance(first.value);

  assert.equal(first.secret_redacted, true);
  assert.equal(first.truncated, true);
  assert.equal(first.opaque, true);
  assert.equal(second.secret_redacted, false);
  assert.equal(second.truncated, false);
  assert.equal(second.opaque, true);
  assert.deepEqual(second.value, first.value);
  assert.deepEqual(Object.keys(first), ['value', 'secret_redacted', 'truncated', 'opaque']);
});

test('provenance preserves generic redaction errors for proxy, accessor and cycle inputs', () => {
  let getterCalls = 0;
  const accessor = {};
  Object.defineProperty(accessor, 'password', {
    enumerable: true,
    get() {
      getterCalls += 1;
      return 'accessor-secret-never-read';
    },
  });
  const proxy = new Proxy({}, {
    ownKeys() { throw new Error('proxy-secret-never-leak'); },
  });
  const cycle = {};
  cycle.self = cycle;

  for (const value of [accessor, proxy, cycle]) {
    assert.throws(
      () => redactForJudgeWithProvenance(value),
      (error) => error instanceof TypeError
        && /^cannot redact (?:unsupported|cyclic) value$/u.test(error.message)
        && !error.message.includes('secret-never'),
    );
  }
  assert.equal(getterCalls, 0);
});

test('provenance fails closed for inherited fields or runtime prototype mutation', () => {
  const inherited = Object.create({ api_token: 'prototype-secret-never-read' });
  inherited.visible = 'safe';
  assert.throws(
    () => redactForJudgeWithProvenance(inherited),
    (error) => error instanceof TypeError && error.message === 'cannot redact unsupported value',
  );

  const descriptor = Object.getOwnPropertyDescriptor(Object.prototype, 'pollutedSecret');
  Object.defineProperty(Object.prototype, 'pollutedSecret', {
    configurable: true,
    enumerable: true,
    value: 'prototype-secret-never-read',
  });
  try {
    assert.throws(
      () => redactForJudgeWithProvenance({ visible: 'safe' }),
      (error) => error instanceof TypeError && error.message === 'cannot redact unsupported value',
    );
  } finally {
    if (descriptor) Object.defineProperty(Object.prototype, 'pollutedSecret', descriptor);
    else delete Object.prototype.pollutedSecret;
  }
});

test('provenance fails closed when mutable collection or string intrinsics are replaced', () => {
  const cases = [
    [Set.prototype, 'has', () => false],
    [Array.prototype, 'some', () => false],
    [String.prototype, 'includes', () => false],
    [RegExp.prototype, 'test', () => false],
  ];

  for (const [owner, key, replacement] of cases) {
    const descriptor = Object.getOwnPropertyDescriptor(owner, key);
    Object.defineProperty(owner, key, { ...descriptor, value: replacement });
    try {
      assert.throws(
        () => redactForJudgeWithProvenance({ message: 'api_token=must-not-upgrade' }),
        (error) => error instanceof TypeError && error.message === 'cannot redact unsupported value',
        `${owner.constructor.name}.${key}`,
      );
    } finally {
      Object.defineProperty(owner, key, descriptor);
    }
  }
});

test('provenance fails closed when Boolean or symbol dispatch intrinsics are replaced', () => {
  const rawSecret = 'symbol-dispatch-secret-never-send-w74';
  const cases = [
    [globalThis, 'Boolean', () => true],
    [Set.prototype, Symbol.iterator, function* hostileIterator() {}],
    [RegExp.prototype, Symbol.replace, () => 'safe'],
    [RegExp.prototype, Symbol.split, () => ['safe']],
  ];

  for (const [owner, key, replacement] of cases) {
    const descriptor = Object.getOwnPropertyDescriptor(owner, key);
    Object.defineProperty(owner, key, { ...descriptor, value: replacement });
    try {
      assert.throws(
        () => redactForJudgeWithProvenance({ apiToken: rawSecret }),
        (error) => error instanceof TypeError
          && error.message === 'cannot redact unsupported value'
          && !String(error).includes(rawSecret),
        String(key),
      );
    } finally {
      Object.defineProperty(owner, key, descriptor);
    }
  }
});

test('classifies secret-bearing config keys without metadata false positives', () => {
  for (const key of [
    'appToken',
    'userToken',
    'signingSecret',
    'webhookSecret',
    'creds',
    'privateKeyPem',
    'authorizationRaw',
    'credentialsJson',
    'apiPassword',
    'appPassword',
    'appSecret',
    'encryptKey',
    'serviceAccount',
    'verificationToken',
    'webhookToken',
    'passphrase',
  ]) {
    assert.equal(isSecretBearingKey(key), true, key);
  }

  for (const key of [
    'maxToken',
    'maxTokens',
    'tokenBudget',
    'tokenCount',
    'tokenLimit',
    'tokenUsage',
    'apiKeyPath',
    'passwordFile',
    'secretPath',
    'baseUrl',
    'keyPath',
    'passphraseFile',
    'encryptKeyRef',
    'serviceAccountRef',
    'sessionKey',
    'sortKey',
    'keyboardLayout',
  ]) {
    assert.equal(isSecretBearingKey(key), false, key);
  }
});

test('redacts authoritative OpenClaw secret leaves and opaque value containers', () => {
  const secret = 'openclaw-matrix-secret-fixture-never-send-r41';
  const result = redactForJudge({
    encryptKey: secret,
    serviceAccount: { private_key: secret },
    headers: { 'X-Custom-Provider-Auth': secret },
    sessionKey: 'agent:main:main',
  });

  assert.equal(result.encryptKey, REDACTED);
  assert.equal(result.serviceAccount, REDACTED);
  assert.equal(result.headers['X-Custom-Provider-Auth'], REDACTED);
  assert.equal(result.sessionKey, 'agent:main:main');
  assert.equal(JSON.stringify(result).includes(secret), false);
});

test('redacts context-bound OpenClaw credentials without making generic keys secret', () => {
  const secret = 'context-matrix-fixture-never-send-u52';
  const input = {
    profiles: {
      default: {
        type: 'api_key',
        provider: 'cloudru',
        key: secret,
        displayName: 'Cloud.ru work',
      },
      oauth: {
        type: 'oauth',
        provider: 'openai',
        access: secret,
        refresh: secret,
        expires: 4_102_444_800_000,
      },
    },
    models: {
      providers: {
        cloudru: {
          request: {
            tls: {
              ca: secret,
              cert: secret,
              key: secret,
              passphrase: secret,
              serverName: 'fm.example.invalid',
            },
            proxy: {
              tls: {
                ca: secret,
                cert: secret,
                key: secret,
                passphrase: secret,
                insecureSkipVerify: false,
              },
            },
          },
        },
      },
    },
    hooks: {
      mappings: [{ id: 'status-hook', sessionKey: secret, action: 'agent' }],
    },
    'auth-profiles': {
      oauth: { access: secret, refresh: secret, expires: 4_102_444_800_000 },
    },
    sessionKey: 'agent:main:main',
    metadata: { key: 'ordinary-sort-label', sortKey: 'created_at' },
  };

  const result = redactForJudge(input);
  assert.equal(JSON.stringify(result).includes(secret), false, 'context secret remained');
  assert.equal(result.profiles.default.key, REDACTED);
  assert.equal(result.profiles.default.displayName, 'Cloud.ru work');
  assert.equal(result.profiles.oauth, REDACTED);
  for (const key of ['ca', 'cert', 'key', 'passphrase']) {
    assert.equal(result.models.providers.cloudru.request.tls[key], REDACTED, key);
    assert.equal(result.models.providers.cloudru.request.proxy.tls[key], REDACTED, `proxy.${key}`);
  }
  assert.equal(result.models.providers.cloudru.request.tls.serverName, 'fm.example.invalid');
  assert.equal(result.models.providers.cloudru.request.proxy.tls.insecureSkipVerify, false);
  assert.equal(result.hooks.mappings[0].sessionKey, REDACTED);
  assert.equal(result['auth-profiles'].oauth, REDACTED);
  assert.equal(result.sessionKey, 'agent:main:main');
  assert.deepEqual(result.metadata, { key: 'ordinary-sort-label', sortKey: 'created_at' });
});

test('fails closed for serialized context-bound credentials but preserves safe JSON metadata', () => {
  const secret = 'serialized-context-fixture-never-send-v63';
  const credentialJson = JSON.stringify({
    profiles: { default: { key: secret } },
    models: {
      providers: {
        cloudru: { request: { proxy: { tls: { ca: secret, cert: secret, key: secret } } } },
      },
    },
    hooks: { mappings: [{ sessionKey: secret }] },
  });
  const oauthJson = JSON.stringify({
    'auth-profiles': { oauth: { access: secret, refresh: secret } },
  });

  for (const value of [credentialJson, oauthJson]) {
    const result = redactForJudge(value);
    assert.equal(result.includes(secret), false, 'serialized credential remained');
    assert.equal(result, REDACTED);
  }

  const safeJson = JSON.stringify({
    sessionKey: 'agent:main:main',
    metadata: { key: 'ordinary-sort-label', sortKey: 'created_at' },
    tls: { serverName: 'public.example.invalid' },
    profiles: { default: { displayName: 'Public label' } },
  });
  assert.equal(redactForJudge(safeJson), safeJson);
});

test('fails closed before truncating a JSON-looking credential payload', () => {
  const secret = 'truncated-json-fixture-never-send-w74';
  const value = JSON.stringify({
    profiles: { default: { key: secret } },
    padding: 'x'.repeat(5_000),
  });

  const result = redactForJudge(value);
  assert.equal(result.includes(secret), false, 'truncated JSON leaked a credential');
  assert.equal(result, REDACTED);
});

test('redacts raw payloads only for exact OpenClaw config write actions', () => {
  const secret = 'json5-config-raw-fixture-never-send-x85';
  const json5 = `{ profiles: { default: { key: '${secret}' } } }`;

  for (const action of ['config.set', 'config.apply', 'config.patch']) {
    const result = redactForJudge({ action, raw: json5, path: 'models.providers' });
    assert.equal(JSON.stringify(result).includes(secret), false, action);
    assert.equal(result.action, action);
    assert.equal(result.raw, REDACTED);
    assert.equal(result.path, 'models.providers');
  }

  const configSet = redactForJudge({
    action: 'config.set',
    path: 'models.providers.cloudru.apiKey',
    value: secret,
  });
  assert.equal(JSON.stringify(configSet).includes(secret), false, 'config.set value remained');
  assert.equal(configSet.value, REDACTED);

  assert.deepEqual(redactForJudge({ action: 'config.get', raw: 'public', value: 'ordinary' }), {
    action: 'config.get',
    raw: 'public',
    value: 'ordinary',
  });
  assert.deepEqual(redactForJudge({ action: 'status', raw: 'public' }), {
    action: 'status',
    raw: 'public',
  });
});

test('recursively redacts secret-bearing keys without mutating input', () => {
  const secrets = [
    'token-fixture-7f31',
    'password-fixture-4a22',
    'api-key-fixture-9c10',
    'authorization-fixture-1d08',
    'cookie-fixture-3e76',
    'secret-fixture-5b44',
  ];
  const input = {
    Token: secrets[0],
    nested: {
      PASSWORD: secrets[1],
      api_key: secrets[2],
      Authorization: secrets[3],
      sessionCookie: secrets[4],
      clientSecret: secrets[5],
      visible: 'keep me',
    },
    array: [{ refreshToken: secrets[0] }, true, null, 42],
  };
  const before = JSON.stringify(input);

  const result = redactForJudge(input);

  assert.equal(result.Token, REDACTED);
  assert.equal(result.nested.PASSWORD, REDACTED);
  assert.equal(result.nested.api_key, REDACTED);
  assert.equal(result.nested.Authorization, REDACTED);
  assert.equal(result.nested.sessionCookie, REDACTED);
  assert.equal(result.nested.clientSecret, REDACTED);
  assert.equal(result.array[0].refreshToken, REDACTED);
  assert.equal(result.nested.visible, 'keep me');
  assert.deepEqual(result.array.slice(1), [true, null, 42]);
  assert.equal(JSON.stringify(input) === before, true, 'redaction mutated its input');
  assert.equal(
    secrets.some((secret) => JSON.stringify(result).includes(secret)),
    false,
    'redacted output retained a credential fixture',
  );
});

test('preserves env names while redacting every env value', () => {
  const secrets = ['env-token-fixture-a12', 'env-path-fixture-b34', 'env-nested-fixture-c56'];
  const input = {
    env: {
      API_TOKEN: secrets[0],
      PATH: secrets[1],
      NESTED: { value: secrets[2] },
    },
    child: {
      ENV: {
        HOME: '/private/home/fixture',
      },
    },
  };

  const result = redactForJudge(input);

  assert.deepEqual(Object.keys(result.env), ['API_TOKEN', 'PATH', 'NESTED']);
  assert.equal(Object.values(result.env).every((value) => value === REDACTED), true);
  assert.deepEqual(Object.keys(result.child.ENV), ['HOME']);
  assert.equal(result.child.ENV.HOME, REDACTED);
  assert.equal(
    secrets.some((secret) => JSON.stringify(result).includes(secret)),
    false,
    'redacted env retained a credential fixture',
  );
});

test('redacts PEM private keys and bearer-token material inside strings', () => {
  const privateMaterial = 'pem-private-fixture-QWxhZGRpbjpvcGVuIHNlc2FtZQ==';
  const bearerMaterial = 'bearer-fixture.eyJzdWIiOiJzZWNyZXQifQ.signature';
  const pem = [
    'prefix',
    '-----BEGIN PRIVATE KEY-----',
    privateMaterial,
    '-----END PRIVATE KEY-----',
    'suffix',
  ].join('\n');
  const bearer = `curl -H "Authorization: Bearer ${bearerMaterial}" https://example.invalid`;

  const result = redactForJudge({ pem, bearer });
  const serialized = JSON.stringify(result);

  assert.equal(serialized.includes(privateMaterial), false, 'PEM material was not redacted');
  assert.equal(serialized.includes(bearerMaterial), false, 'bearer material was not redacted');
  assert.equal(result.pem.includes('[REDACTED PRIVATE KEY]'), true);
  assert.equal(result.bearer, REDACTED);
});

test('redacts credentials embedded in shell commands, headers, flags, and URLs', () => {
  const secrets = {
    apiHeader: 'shell-api-header-fixture-never-send-a11',
    aws: 'shell-aws-secret-fixture-never-send-b22',
    basic: 'shell-basic-auth-fixture-never-send-c33',
    password: 'shell-user-password-fixture-never-send-d44',
    cookie: 'shell-cookie-fixture-never-send-e55',
    query: 'shell-query-key-fixture-never-send-f66',
    flag: 'shell-password-flag-fixture-never-send-g77',
  };
  const input = {
    apiHeader: `curl -H "X-API-Key: ${secrets.apiHeader}" https://example.invalid`,
    aws: `AWS_SECRET_ACCESS_KEY=${secrets.aws} command --safe`,
    basic: `curl -H 'Authorization: Basic ${secrets.basic}' https://example.invalid`,
    userPassword: `curl -u user:${secrets.password} https://example.invalid`,
    cookie: `curl -H "Cookie: session=${secrets.cookie}; theme=dark" https://example.invalid`,
    query: `curl 'https://example.invalid/data?api_key=${secrets.query}&safe=1'`,
    passwordFlag: `tool --password '${secrets.flag}' --mode safe`,
  };

  const result = redactForJudge(input);
  const serialized = JSON.stringify(result);

  for (const [name, secret] of Object.entries(secrets)) {
    assert.equal(serialized.includes(secret), false, `${name} credential remained in output`);
  }
  for (const value of Object.values(result)) {
    assert.equal(value.includes(REDACTED), true, 'credential marker was not preserved');
  }
  assert.deepEqual(redactForJudge(result), result, 'credential redaction was not idempotent');
});

test('does not treat ordinary token-count and password-policy prose as credentials', () => {
  const text = 'Run tokenizer with max-tokens 256 and print the password policy name.';

  assert.equal(redactForJudge(text), text);
});

test('redacts JSON, CLI, URI, concatenated, and unterminated credential forms idempotently', () => {
  const secrets = [
    'json-secret-fixture-never-send-h88',
    'cli-equals-fixture-never-send-i99',
    'cli-spaces-fixture-never-send-j00 with spaces',
    'uri-password-fixture-never-send-k11',
    'concatenated-fixture-never-send-l22 with suffix',
    'unterminated-fixture-never-send-m33',
  ];
  const input = {
    json: `payload='{"api_key":"${secrets[0]}","safe":1}'`,
    cli: `tool --api-key=${secrets[1]} --client-secret '${secrets[2]}' --mode safe`,
    uri: `postgres://dbuser:${secrets[3]}@db.example.invalid/app`,
    concatenated: `API_KEY=prefix'${secrets[4]}' command`,
    unterminated: `TOKEN='${secrets[5]}`,
  };

  const once = redactForJudge(input);
  const twice = redactForJudge(once);
  const serialized = JSON.stringify(once);

  for (const secret of secrets) {
    assert.equal(serialized.includes(secret), false, 'credential form remained in output');
  }
  assert.deepEqual(twice, once, 'redaction was not idempotent');
});

test('preserves non-secret user flags, metadata options, regions, hashes, and IDs', () => {
  const safe = [
    'sudo -u deploy curl https://example.invalid',
    'tool --password-stdin --secret-file /tmp/secret-name.txt',
    'AWS_REGION=ru-central-1 MAX_TOKENS=256',
    'echo authorization required',
    'sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    '123e4567-e89b-12d3-a456-426614174000',
  ].join(' && ');

  assert.equal(redactForJudge(safe), safe);
});

test('fails closed for adversarial credential syntax without leaking suffixes', () => {
  const secret = 'adversarial-secret-fixture-never-send-n44';
  const inputs = [
    `API_KEY=[REDACTED]${secret}`,
    `X-API-Key: [REDACTED]${secret}`,
    `AUTHORIZATION=${secret} rm -rf /tmp/fixture`,
    `COOKIE=${secret} curl -X POST https://example.invalid`,
    `API_KEY=first,${secret}`,
    `API_KEY=first]${secret}`,
    `API_KEY=$(printf '${secret}')`,
    `curl -H "Cookie: theme=dark; session=${secret}" https://example.invalid`,
    `curl 'https://example.invalid/?a=1&b=2' -u user:${secret}`,
    `/usr/bin/curl -uuser:${secret} https://example.invalid`,
    `REFRESH_TOKENS=${secret}`,
    `tool --refresh-token ${secret}`,
    `tool --api_key ${secret}`,
    `redis://:${secret}@redis.example.invalid/0`,
    `curl.exe -u user:${secret} https://example.invalid`,
    `powershell -Credential ${secret} -Command Get-Item`,
    `ПАРОЛЬ=${secret} команда`,
    `INPUT_AUTH_TOKEN=${secret}`,
    `OUTPUT_ACCESS_TOKEN=${secret}`,
    `PROMPT_API_TOKEN=${secret}`,
    `TOKEN_USAGE_SECRET=${secret}`,
    `TOKEN_BUDGET_PASSWORD=${secret}`,
    `tool '--api-key' '${secret}'`,
    `tool "--password" "${secret}"`,
    `curl '-u' 'user:${secret}' https://example.invalid`,
    `curl \\-u user:${secret} https://example.invalid`,
    `INPUT_TOKEN=${secret}`,
    `OUTPUT_TOKEN=${secret}`,
    `PROMPT_TOKEN=${secret}`,
    `CONTEXT_TOKEN=${secret}`,
    `powershell '-Credential' '${secret}'`,
    `powershell "-Password" "${secret}"`,
    `'curl' '-u' 'user:${secret}' https://example.invalid`,
    `"curl.exe" '-u' 'user:${secret}' https://example.invalid`,
    `apikeyvalue=${secret}`,
    `clientsecretvalue=${secret}`,
    `passwordvalue=${secret}`,
    `APIKEYValue=${secret}`,
    String.raw`C:\curl.exe -u user:${secret} https://example.invalid`,
    String.raw`C:\Windows\System32\curl.exe -u user:${secret} https://example.invalid`,
    String.raw`& 'C:\Windows\System32\curl.exe' '-u' 'user:${secret}' https://example.invalid`,
  ];

  for (const input of inputs) {
    const result = redactForJudge(input);
    assert.equal(result, REDACTED, 'credential-bearing string was not made opaque');
    assert.equal(result.includes(secret), false, 'credential suffix remained in output');
  }
});

test('does not classify related non-secret identifiers as credential bindings', () => {
  const safe = [
    'secretary=Alice',
    'authorizationServer=https://idp.example.invalid echo retain',
    'PASSWORD_POLICY=strict',
    'SECRET_FILE=/tmp/secret.txt',
    'MAX_OUTPUT_TOKENS=256',
  ].join(' && ');

  assert.equal(redactForJudge(safe), safe);
});

test('redacts common camelCase credential fields and bindings', () => {
  const secret = 'camel-case-secret-fixture-never-send-q77';
  const input = {
    apiKeyValue: secret,
    tokenValue: secret,
    passwordValue: secret,
    clientSecretValue: secret,
    credentialsJson: secret,
    privateKeyData: secret,
  };

  const result = redactForJudge(input);

  assert.equal(Object.values(result).every((value) => value === REDACTED), true);
  assert.equal(redactForJudge(`apiKeyValue=${secret} command`), REDACTED);
  assert.equal(redactForJudge(`clientSecretValue=${secret} command`), REDACTED);
});

test('never preserves credential material embedded in an object property name', () => {
  const secret = 'property-name-secret-fixture-never-send-s99';
  const key = `api_key=${secret}`;

  const result = redactForJudge({ [key]: 'ordinary value' });

  assert.equal(result, REDACTED);
  assert.equal(JSON.stringify(result).includes(secret), false);
});

test('fails closed for incomplete PEM blocks and non-standard bearer material', () => {
  const privateMaterial = 'incomplete-pem-fixture-never-print-d9b';
  const bearerTail = 'bearer-colon-tail-fixture-never-print-e0c';
  const incompletePem = `-----BEGIN RSA PRIVATE KEY-----\n${privateMaterial}`;
  const bearer = `Bearer prefix:${bearerTail}`;

  const result = redactForJudge({ incompletePem, bearer });
  const serialized = JSON.stringify(result);

  assert.equal(serialized.includes(privateMaterial), false, 'incomplete PEM material remained');
  assert.equal(serialized.includes(bearerTail), false, 'bearer tail remained');
});

test('redacts complete and incomplete PGP private-key blocks', () => {
  const secret = 'pgp-private-key-fixture-never-send-t00';
  const complete = [
    '-----BEGIN PGP PRIVATE KEY BLOCK-----',
    secret,
    '-----END PGP PRIVATE KEY BLOCK-----',
  ].join('\n');
  const incomplete = `-----BEGIN PGP PRIVATE KEY BLOCK-----\n${secret}`;

  const result = redactForJudge({ complete, incomplete });
  const serialized = JSON.stringify(result);

  assert.equal(serialized.includes(secret), false);
  assert.equal(result.complete.includes('[REDACTED PRIVATE KEY]'), true);
  assert.equal(result.incomplete.includes('[REDACTED PRIVATE KEY]'), true);
});

test('truncates long strings at the configured limit with an explicit marker', () => {
  assert.equal(redactForJudge('abcdef', { maxStringLength: 5 }), 'abcde[TRUNCATED]');

  const atDefaultLimit = 'x'.repeat(4096);
  assert.equal(redactForJudge(atDefaultLimit), atDefaultLimit);
  assert.equal(redactForJudge(`${atDefaultLimit}x`), `${atDefaultLimit}[TRUNCATED]`);
});

test('rejects cyclic and unsupported values with secret-free errors', () => {
  const secret = 'unsupported-fixture-never-print-51f';
  const cyclic = { visible: secret };
  cyclic.self = cyclic;

  assert.throws(
    () => redactForJudge(cyclic),
    (error) => error instanceof TypeError
      && error.message === 'cannot redact cyclic value'
      && !error.message.includes(secret),
  );

  const unsupported = [undefined, 1n, Symbol(secret), () => secret, new Date(), Number.NaN];
  for (const value of unsupported) {
    assert.throws(
      () => redactForJudge(value),
      (error) => error instanceof TypeError
        && error.message === 'cannot redact unsupported value'
        && !error.message.includes(secret),
    );
  }
});

test('normalizes exceptions thrown by unsupported objects without exposing their text', () => {
  const secret = 'proxy-redaction-fixture-never-print-b7f';
  const hostile = new Proxy({}, {
    getPrototypeOf() {
      throw new Error(secret);
    },
  });
  let caught;

  try {
    redactForJudge(hostile);
  } catch (error) {
    caught = error;
  }

  assert.equal(caught instanceof TypeError, true, 'unsupported object did not fail safely');
  assert.equal(caught?.message === 'cannot redact unsupported value', true, 'error was not normalized');
  assert.equal(caught?.message.includes(secret), false, 'error exposed unsupported object text');
});

test('validates maxStringLength without echoing input', () => {
  const secret = 'invalid-limit-fixture-never-print-62a';

  for (const maxStringLength of [-1, 1.5, Number.NaN, '10']) {
    assert.throws(
      () => redactForJudge(secret, { maxStringLength }),
      (error) => error instanceof TypeError
        && error.message === 'maxStringLength must be a non-negative integer'
        && !error.message.includes(secret),
    );
  }
});
