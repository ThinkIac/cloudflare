import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { auth } from '@modelcontextprotocol/sdk/client/auth.js';
import { createStore } from './store.js';
import { nativeServers } from './native.js';

const privateDir = () => process.env.CLOUDFLARE_PRIVATE_DIR || fileURLToPath(new URL('../../../.private/cloudflare/', import.meta.url));
export function createOAuth({ storeFactory = server => createStore(join(privateDir(), 'oauth', server)), fetchImpl = fetch, authImpl = auth, now = Date.now } = {}) {
  const pending = new Map(), locks = new Map();
  function validate(server) {
    if (!Object.hasOwn(nativeServers, server) || server === 'docs') throw new Error('Servidor OAuth inválido.');
  }
  function locked(server, action) {
    const next = (locks.get(server) || Promise.resolve()).catch(() => {}).then(action);
    locks.set(server, next);
    return next.finally(() => { if (locks.get(server) === next) locks.delete(server); });
  }
  function safeFetch(server) {
    return (input, options = {}) => {
      const url = new URL(input instanceof Request ? input.url : input);
      if (url.origin !== new URL(nativeServers[server]).origin || url.username || url.password) throw new Error('Destino OAuth não permitido.');
      return fetchImpl(input, { ...options, redirect: 'error', signal: AbortSignal.any([AbortSignal.timeout(20000), ...(options.signal ? [options.signal] : [])]) });
    };
  }
  function provider(data, state, interactive) {
    return {
      redirectUrl: data.redirectUrl,
      clientMetadata: { client_name: 'ThinkIac', redirect_uris: [data.redirectUrl], grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: 'none' },
      state: () => state, clientInformation: () => data.client, saveClientInformation: value => { data.client = value; },
      tokens: () => data.tokens,
      saveTokens: value => { data.tokens = { ...value, ...(value.refresh_token ? {} : { refresh_token: data.tokens?.refresh_token }) }; data.expiresAt = now() + (value.expires_in || 3600) * 1000; },
      saveCodeVerifier: value => { data.verifier = value; }, codeVerifier: () => data.verifier,
      redirectToAuthorization: url => { if (!interactive || url.origin !== new URL(nativeServers[data.server]).origin) throw new Error('Conecte novamente pela View.'); data.authorizationUrl = url.href; },
    };
  }
  async function start({ server = 'api', origin, owner }) {
    validate(server);
    const base = new URL(origin);
    if (!owner || (base.protocol !== 'https:' && !(base.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(base.hostname)))) throw new Error('Login exige administrador identificado e HTTPS (ou localhost).');
    for (const [key, flow] of pending) if (flow.deadline <= now() || (flow.owner === owner && flow.server === server)) pending.delete(key);
    if (pending.size >= 100) throw new Error('Muitos logins pendentes. Aguarde alguns minutos.');
    const state = randomBytes(32).toString('base64url');
    const data = { server, owner, redirectUrl: base.origin + '/cloudflare/oauth/callback', deadline: now() + 600000 };
    try {
      const result = await authImpl(provider(data, state, true), { serverUrl: nativeServers[server], fetchFn: safeFetch(server) });
      if (result !== 'REDIRECT' || !data.authorizationUrl || !data.verifier) throw new Error();
      pending.set(state, data);
      return { authorizationUrl: data.authorizationUrl };
    } catch { throw new Error('Não foi possível iniciar o login Cloudflare. Tente novamente.'); }
  }
  async function finish({ state, code, error, owner, issuer }) {
    const data = typeof state === 'string' && pending.get(state);
    if (!data || !owner || data.owner !== owner || data.deadline <= now()) throw new Error('Login inválido ou expirado. Inicie novamente pela View.');
    pending.delete(state);
    if (error) throw new Error('Autorização cancelada no Cloudflare.');
    if (typeof code !== 'string' || !code || code.length > 8192 || (issuer && issuer !== new URL(nativeServers[data.server]).origin)) throw new Error('Resposta OAuth inválida.');
    return locked(data.server, async () => {
      try {
        const result = await authImpl(provider(data, state, false), { serverUrl: nativeServers[data.server], authorizationCode: code, fetchFn: safeFetch(data.server) });
        if (result !== 'AUTHORIZED' || !data.tokens?.access_token) throw new Error();
        const store = storeFactory(data.server);
        await store.save({ server: data.server, redirectUrl: data.redirectUrl, client: data.client, tokens: data.tokens, expiresAt: data.expiresAt });
        return { success: true };
      } catch { throw new Error('Não foi possível concluir o login Cloudflare. Inicie novamente pela View.'); }
    });
  }
  async function status() {
    return Object.fromEntries(await Promise.all(Object.keys(nativeServers).filter(s => s !== 'docs').map(async server => {
      const data = await storeFactory(server).read();
      return [server, { connected: Boolean(data.tokens?.access_token), expiresAt: data.expiresAt || null }];
    })));
  }
  async function accessToken(server) {
    validate(server);
    return locked(server, async () => {
      const store = storeFactory(server), data = await store.read();
      if (!data.tokens?.access_token) return '';
      if (data.expiresAt > now() + 60000) return data.tokens.access_token;
      if (!data.tokens.refresh_token) throw new Error('Login Cloudflare expirado. Conecte novamente pela View.');
      try {
        if (await authImpl(provider(data, '', false), { serverUrl: nativeServers[server], fetchFn: safeFetch(server) }) !== 'AUTHORIZED') throw new Error();
        await store.save(data);
        return data.tokens.access_token;
      } catch { throw new Error('Login Cloudflare expirado. Conecte novamente pela View.'); }
    });
  }
  async function disconnect({ server = 'api' } = {}) {
    validate(server);
    for (const [key, flow] of pending) if (flow.server === server) pending.delete(key);
    return locked(server, async () => { await storeFactory(server).save({}); return { success: true }; });
  }
  return { start, finish, status, accessToken, disconnect };
}
