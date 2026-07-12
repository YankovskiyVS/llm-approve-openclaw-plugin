import test from 'node:test';
import assert from 'node:assert/strict';
import { redactForJudge } from '../src/redact.js';

const REDACTED = '[REDACTED]';

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
