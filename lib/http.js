export async function adminRoute(req, res, action) {
  res?.setHeader?.('Cache-Control', 'no-store');
  const principal = req?.principal;
  const isAdmin = principal ? principal.roles?.includes('admin') : req?.user?.role === 'admin';
  if (!isAdmin || req?.user?.delegatedSubject || principal?.claims?.delegatedSubject) {
    if (res) res.statusCode = 403;
    return { success: false, error: 'Acesso restrito a administrador sem delegação.' };
  }
  if (req.method !== 'GET') {
    const headers = req.headers || {};
    let sameOrigin = false;
    try { sameOrigin = new URL(headers.origin).host === headers.host; } catch { /* fail closed */ }
    if (!sameOrigin || !/^application\/json(?:;|$)/i.test(headers['content-type'] || '')) {
      if (res) res.statusCode = 403;
      return { success: false, error: 'Envie a operação pela View autenticada, na mesma origem.' };
    }
  }
  try { return await action(); }
  catch (e) { if (res) res.statusCode = 400; return { success: false, error: e.message }; }
}
