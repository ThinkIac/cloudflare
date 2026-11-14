import { randomUUID } from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { createStore } from './store.js';
function sanitize(value, token = '') {
  if (typeof value === 'string') { if (/^[\s]*[{[]/.test(value)) { try { return JSON.stringify(sanitize(JSON.parse(value), token)); } catch { /* ordinary text */ } } return token ? value.split(token).join('[oculto]') : value; }
  if (Array.isArray(value)) return value.map(item => sanitize(item, token));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, /token|secret|password|authorization|api.?key|private.?key/i.test(key) ? '[oculto]' : sanitize(item, token)]));
  return value;
}
export const nativeServers = Object.freeze({ api: 'https://mcp.cloudflare.com/mcp', docs: 'https://docs.mcp.cloudflare.com/mcp', bindings: 'https://bindings.mcp.cloudflare.com/mcp', builds: 'https://builds.mcp.cloudflare.com/mcp', observability: 'https://observability.mcp.cloudflare.com/mcp' });
export function createNative({ store = createStore(), fetchImpl = fetch, oauth, clientFactory = () => new Client({ name: 'thinkiac-cloudflare', version: '0.4.0' }) } = {}) {
  async function session(server, action, schema = false) {
    if (!Object.hasOwn(nativeServers, server)) throw new Error('Servidor inválido: api, docs, bindings, builds ou observability.');
    const token = server === 'docs' ? '' : await oauth?.accessToken(server);
    if (server !== 'docs' && !token) throw new Error('Entre com Cloudflare na View.');
    const endpoint = nativeServers[server], client = clientFactory();
    const transport = new StreamableHTTPClientTransport(new URL(endpoint), { requestInit: { headers: token ? { Authorization: `Bearer ${token}` } : {} }, reconnectionOptions: { maxRetries: 0, initialReconnectionDelay: 1000, maxReconnectionDelay: 1000, reconnectionDelayGrowFactor: 1 }, fetch: (url, options) => { if (new URL(url instanceof Request ? url.url : url).href !== endpoint) throw new Error('Destino MCP não permitido.'); return fetchImpl(url, { ...options, redirect: 'error', signal: AbortSignal.any([AbortSignal.timeout(45000), ...(options?.signal ? [options.signal] : [])]) }); } });
    try { await client.connect(transport, { timeout: 20000 }); const result = await action(client); return schema ? (token ? JSON.parse(JSON.stringify(result).split(token).join('[oculto]')) : result) : sanitize(result, token); }
    catch { throw new Error(`Falha no MCP Cloudflare (${server}). Verifique credencial, permissões e disponibilidade. Se houve execução, o resultado pode ser desconhecido; não repita automaticamente.`); }
    finally { try { await client.close(); } catch { /* preserve original result */ } }
  }
  async function discover({ server = 'api', cursor } = {}) { if (cursor !== undefined && (typeof cursor !== 'string' || cursor.length > 4096)) throw new Error('Cursor inválido.'); return session(server, client => client.listTools(cursor ? { cursor } : {}, { timeout: 20000 }), true); }
  async function call({ server = 'api', tool, args = {} } = {}) {
    if (typeof tool !== 'string' || !/^[\w.-]{1,200}$/.test(tool)) throw new Error('Nome de ferramenta inválido.');
    if (!args || typeof args !== 'object' || Array.isArray(args) || JSON.stringify(args).length > 2_000_000) throw new Error('Argumentos devem ser um objeto JSON de até 2 MB.');
    return session(server, async client => {
      let cursor, found; const seen = new Set();
      for (let page = 0; page < 100; page++) { const result = await client.listTools(cursor ? { cursor } : {}, { timeout: 20000 }); found = result.tools.find(item => item.name === tool); if (found || !result.nextCursor || seen.has(result.nextCursor)) break; cursor = result.nextCursor; seen.add(cursor); }
      if (!found) throw new Error('Ferramenta não encontrada no MCP oficial.');
      const event = { id: randomUUID(), operation: 'native_call', server, tool }; await store.audit({ ...event, outcome: 'attempt' });
      let result; try { result = await client.callTool({ name: tool, arguments: args }, undefined, { timeout: 45000 }); } catch (error) { await store.audit({ ...event, outcome: 'failed_or_unknown' }); throw error; }
      try { await store.audit({ ...event, outcome: result.isError ? 'failed_or_unknown' : 'success' }); } catch { return { ...result, warning: 'Chamada retornou, mas falhou o registro local. Não repita automaticamente.' }; }
      return result;
    });
  }
  return { discover, call, servers: () => Object.entries(nativeServers).map(([server, url]) => ({ server, url, authentication: server === 'docs' ? 'public' : 'bearer' })) };
}
