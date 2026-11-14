import { mkdir, readFile, writeFile, rename, appendFile } from 'node:fs/promises';
import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

export function createStore(dir = process.env.CLOUDFLARE_PRIVATE_DIR || fileURLToPath(new URL('../../../.private/cloudflare/', import.meta.url))) {
  const file = join(dir, 'credentials.json');
  async function prepare() { await mkdir(dir, { recursive: true, mode: 0o700 }); }
  async function key(create = false) {
    if (create) {
      await prepare();
      try { await writeFile(join(dir, 'key'), randomBytes(32), { mode: 0o600, flag: 'wx' }); }
      catch (e) { if (e.code !== 'EEXIST') throw e; }
    }
    return readFile(join(dir, 'key'));
  }
  async function read() {
    let data;
    try { data = JSON.parse(await readFile(file, 'utf8')); }
    catch (e) { if (e.code === 'ENOENT') return {}; throw new Error('Não foi possível ler a configuração privada.'); }
    try {
      const decipher = createDecipheriv('aes-256-gcm', await key(), Buffer.from(data.iv, 'base64'));
      decipher.setAuthTag(Buffer.from(data.tag, 'base64'));
      return JSON.parse(Buffer.concat([decipher.update(Buffer.from(data.cipher, 'base64')), decipher.final()]).toString());
    } catch { throw new Error('Não foi possível abrir a configuração privada. Preserve a chave local.'); }
  }
  async function save(config) {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', await key(true), iv);
    const encrypted = Buffer.concat([cipher.update(JSON.stringify(config)), cipher.final()]);
    const tmp = join(dir, `credentials-${randomBytes(8).toString('hex')}.tmp`);
    await writeFile(tmp, JSON.stringify({ iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), cipher: encrypted.toString('base64') }), { mode: 0o600, flag: 'wx' });
    await rename(tmp, file);
  }
  async function audit(entry) {
    await prepare();
    await appendFile(join(dir, 'audit.jsonl'), JSON.stringify({ at: new Date().toISOString(), ...entry }) + '\n', { mode: 0o600 });
  }
  async function history() {
    try { return (await readFile(join(dir, 'audit.jsonl'), 'utf8')).trim().split('\n').filter(Boolean).slice(-100).map(JSON.parse); }
    catch (e) { if (e.code === 'ENOENT') return []; throw e; }
  }
  return { read, save, audit, history };
}
