import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createOAuth } from '../lib/oauth.js';
import { createNative } from '../lib/native.js';

function fixture() {
  const saved = {}, requests = [];
  let clock = 1000000, refreshes = 0;
  const storeFactory = server => ({ read: async () => structuredClone(saved[server] || {}), save: async value => { saved[server] = structuredClone(value); } });
  const fetchImpl = async (input, options = {}) => {
    const url = new URL(input), base = url.origin;
    requests.push({ url, options });
    assert.equal(options.redirect, 'error');
    const json = value => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
    if (url.pathname.includes('oauth-protected-resource')) return json({ resource: base + '/mcp', authorization_servers: [base] });
    if (url.pathname.includes('oauth-authorization-server')) return json({ issuer: base, authorization_endpoint: base + '/authorize', token_endpoint: base + '/token', registration_endpoint: base + '/register', response_types_supported: ['code'], grant_types_supported: ['authorization_code', 'refresh_token'], token_endpoint_auth_methods_supported: ['none'], code_challenge_methods_supported: ['S256'] });
    if (url.pathname === '/register') return json({ ...JSON.parse(options.body), client_id: 'fixture-client' });
    if (url.pathname === '/token') {
      const body = new URLSearchParams(options.body);
      if (body.get('grant_type') === 'refresh_token') {
        refreshes++;
        assert.equal(body.get('refresh_token'), 'private-refresh');
        return json({ access_token: 'refreshed-access', token_type: 'Bearer', expires_in: 3600 });
      }
      assert.ok(body.get('code_verifier'));
      return json({ access_token: 'private-access', refresh_token: 'private-refresh', token_type: 'Bearer', expires_in: 3600 });
    }
    throw new Error('Unexpected URL');
  };
  const oauth = createOAuth({ storeFactory, fetchImpl, now: () => clock });
  const start = (server = 'api') => oauth.start({ server, origin: 'https://runtime.test', owner: 'admin1' });
  const complete = async (server = 'api') => {
    const { authorizationUrl } = await start(server);
    const state = new URL(authorizationUrl).searchParams.get('state');
    await oauth.finish({ state, code: 'authorization-code', owner: 'admin1' });
    return state;
  };
  return { oauth, saved, requests, start, complete, advance: ms => { clock += ms; }, refreshes: () => refreshes };
}

test('real SDK registers callback and creates PKCE; owner binding and single-use state', async () => {
  const { oauth, start, requests, saved } = fixture();
  const url = new URL((await start()).authorizationUrl);
  assert.equal(url.origin, 'https://mcp.cloudflare.com');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(url.searchParams.get('redirect_uri'), 'https://runtime.test/cloudflare/oauth/callback');
  const state = url.searchParams.get('state');
  await assert.rejects(oauth.finish({ state, code: 'x', owner: 'another-admin' }), /inválido/);
  await oauth.finish({ state, code: 'x', owner: 'admin1' });
  const exchange = requests.find(r => r.url.pathname === '/token');
  const verifier = new URLSearchParams(exchange.options.body).get('code_verifier');
  assert.equal(createHash('sha256').update(verifier).digest('base64url'), url.searchParams.get('code_challenge'));
  await assert.rejects(oauth.finish({ state, code: 'x', owner: 'admin1' }), /inválido/);
  assert.equal(saved.api.tokens.access_token, 'private-access');
  assert.equal(saved.api.verifier, undefined);
  assert.equal(saved.api.authorizationUrl, undefined);
  assert.doesNotMatch(JSON.stringify(await oauth.status()), /private-access|private-refresh|fixture-client/);
});

test('cancelled, expired and incorrect-issuer flows preserve existing connection', async () => {
  const { oauth, start, complete, advance, saved } = fixture();
  await complete();
  for (const mode of ['cancel', 'expire', 'issuer']) {
    const state = new URL((await start()).authorizationUrl).searchParams.get('state');
    if (mode === 'expire') advance(600001);
    await assert.rejects(oauth.finish({ state, owner: 'admin1', code: 'x', ...(mode === 'cancel' ? { error: 'access_denied' } : {}), ...(mode === 'issuer' ? { issuer: 'https://evil.test' } : {}) }));
    assert.equal(saved.api.tokens.access_token, 'private-access');
  }
});

test('refresh is serialized, preserves refresh token and stays scoped to its server', async () => {
  const { oauth, complete, advance, saved, refreshes } = fixture();
  await complete(); advance(3600000);
  assert.deepEqual(await Promise.all([oauth.accessToken('api'), oauth.accessToken('api')]), ['refreshed-access', 'refreshed-access']);
  assert.equal(refreshes(), 1);
  assert.equal(saved.api.tokens.refresh_token, 'private-refresh');
  assert.equal(await oauth.accessToken('bindings'), '');
  await oauth.disconnect({ server: 'api' });
  assert.equal(await oauth.accessToken('api'), '');
});

test('disconnect cancels pending login and invalid origins/servers never register', async () => {
  const { oauth, start, requests } = fixture();
  for (const server of ['docs', 'constructor', 'https://evil.test']) await assert.rejects(start(server));
  await assert.rejects(oauth.start({ origin: 'http://runtime.test', owner: 'admin1' }));
  await assert.rejects(oauth.start({ origin: 'https://runtime.test' }));
  assert.equal(requests.length, 0);
  const state = new URL((await start()).authorizationUrl).searchParams.get('state');
  await oauth.disconnect();
  await assert.rejects(oauth.finish({ state, code: 'x', owner: 'admin1' }));
});

test('OAuth discovery cannot redirect token exchange or leak upstream error details', async () => {
  let leaked = false;
  const oauth = createOAuth({ authImpl: async (_, { fetchFn }) => { await fetchFn('https://evil.test/token', { body: 'secret' }); }, fetchImpl: async () => { leaked = true; } });
  await assert.rejects(oauth.start({ origin: 'https://runtime.test', owner: 'admin1' }), /Não foi possível/);
  assert.equal(leaked, false);
});

test('native MCP uses only scoped OAuth, redacts it, and rejects missing server login', async () => {
  const { oauth, complete } = fixture(); await complete();
  const seen = [];
  const native = createNative({ oauth, clientFactory: () => ({
    connect: async transport => { seen.push(new Headers(transport._requestInit.headers).get('Authorization')); },
    close: async () => {}, listTools: async () => ({ tools: [{ name: 'echo', description: 'private-access' }] }),
  }) });
  assert.doesNotMatch(JSON.stringify(await native.discover()), /private-access/);
  await assert.rejects(native.discover({ server: 'bindings' }), /Entre com Cloudflare/);
  await native.discover({ server: 'docs' });
  assert.deepEqual(seen, ['Bearer private-access', null]);
});

