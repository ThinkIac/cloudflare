import { adminRoute } from './lib/http.js';
import { createNative } from './lib/native.js';
import { createOAuth } from './lib/oauth.js';
import { assertSurface } from '../ui-schema/index.js';
const oauth = createOAuth();
const native = createNative({ oauth });
const owner = req => req.principal?.subject || req.user?.id;
const CLOUDFLARE_SURFACE = Object.freeze({ version: 1, kind: 'cloudflare-integration', eyebrow: 'Cloudflare integration', title: 'Cloudflare', description: 'Connect the official Cloudflare MCP servers for DNS, Workers, Tunnels, SSL, cache, builds, and observability.', forms: { connection: { fields: [{ name: 'server', component: 'select' }] } }, actions: { 'cloudflare.refresh': { intent: 'read' }, 'cloudflare.connect': { intent: 'write' }, 'cloudflare.disconnect': { intent: 'destructive' }, 'cloudflare.catalog': { intent: 'read' }, 'cloudflare.audit': { intent: 'read' } } });
async function integrationState() { return { connections: await oauth.status(), servers: native.servers() }; }
export async function cloudflareSystemView(req, res) {
  /** @register_router system/view @method GET */
  return adminRoute(req, res, async () => { if (req.query?.tab && req.query.tab !== 'integrations:cloudflare') return { status: 404, message: 'Cloudflare integration was not found.' }; return { status: 200, surface: assertSurface(CLOUDFLARE_SURFACE), state: await integrationState() }; });
}
export async function cloudflareSystemAction(req, res) {
  /** @register_router system/action @method POST */
  return adminRoute(req, res, async () => {
    if (req.query?.tab && req.query.tab !== 'integrations:cloudflare') return { status: 404, message: 'Cloudflare integration was not found.' };
    const action = String(req.body?.action || ''), values = req.body?.values && typeof req.body.values === 'object' ? req.body.values : {};
    if (action === 'cloudflare.refresh') return { status: 200, state: await integrationState() };
    if (action === 'cloudflare.connect') return { status: 200, state: await integrationState(), authorizationUrl: (await oauth.start({ server: values.server, origin: req.headers.origin, owner: owner(req) })).authorizationUrl };
    if (action === 'cloudflare.disconnect') { await oauth.disconnect({ server: values.server }); return { status: 200, state: await integrationState(), notice: 'Cloudflare connection removed from this Runtime.' }; }
    if (action === 'cloudflare.catalog') return { status: 200, state: await integrationState(), catalog: await native.discover({ server: values.server, cursor: values.cursor }) };
    if (action === 'cloudflare.audit') return { status: 200, state: await integrationState(), audit: await (await import('./lib/store.js')).createStore().history() };
    return { status: 404, message: 'Integration action is not allowed.' };
  });
}
export async function oauthStart(req, res) { /** @register_router oauth/start @method POST */ return adminRoute(req, res, () => oauth.start({ server: req.body?.server, origin: req.headers.origin, owner: owner(req) })); }
export async function oauthStatus(req, res) { /** @register_router oauth/status @method GET */ return adminRoute(req, res, () => oauth.status()); }
export async function oauthDisconnect(req, res) { /** @register_router oauth/disconnect @method POST */ return adminRoute(req, res, () => oauth.disconnect(req.body || {})); }
export async function oauthCallback(req, res) {
  /** @register_router oauth/callback @method GET */
  res.setHeader('Referrer-Policy', 'no-referrer');
  return adminRoute(req, res, async () => { try { await oauth.finish({ state: req.query?.state, code: req.query?.code, error: req.query?.error, issuer: req.query?.iss, owner: owner(req) }); return res.redirect('/view/settings/Index?integration=integrations%3Acloudflare&integration_status=success'); } catch { return res.redirect('/view/settings/Index?integration=integrations%3Acloudflare&integration_status=failed'); } });
}
export async function nativeCatalogRoute(req, res) { /** @register_router native/catalog @method POST */ return adminRoute(req, res, () => native.discover(req.body || {})); }
export async function cloudflareNativeCatalog(input = {}) {
  /** @register_tool cloudflare_native_catalog
   * @description Discovers tools and schemas from the official Cloudflare MCP servers.
   * @param {string?} server - api, docs, bindings, builds, or observability.
   * @param {string?} cursor - Server pagination cursor.
   */
  return native.discover(input);
}
export async function cloudflareNativeCall(input) {
  /** @register_tool cloudflare_native_call
   * @reach manual
   * @description Runs an official Cloudflare tool previously returned by cloudflare_native_catalog. It can mutate resources and requires task authorization.
   * @param {string} server - api, docs, bindings, builds, or observability.
   * @param {string} tool - Exact tool name from the official catalog.
   * @param {object?} args - Arguments from the discovered schema; never credentials.
   */
  return native.call(input);
}
export async function historyRoute(req, res) { /** @register_router audit @method GET */ return adminRoute(req, res, async () => ({ entries: await (await import('./lib/store.js')).createStore().history() })); }
export async function cloudflareStatus() { /** @register_tool cloudflare_status @description Shows official OAuth connection state without revealing credentials. */ return { oauth: await oauth.status() }; }
export async function cloudflareAudit() { /** @register_tool cloudflare_audit @description Reads the last 100 local audit entries, excluding payloads and credentials. */ return { entries: await (await import('./lib/store.js')).createStore().history() }; }
