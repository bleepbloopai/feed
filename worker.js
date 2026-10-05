import page from './index.html';
const enc = new TextEncoder();
const J = (d, s = 200, h = {}) => new Response(JSON.stringify(d), { status: s, headers: { 'content-type': 'application/json', ...h } });
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b)));
const unb = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const eq = (a, b) => { a = String(a); b = String(b); let r = a.length ^ b.length; for (let i = 0; i < Math.max(a.length, b.length); i++) r |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0); return r === 0; };
const hmac = async (env, d) => { const k = await crypto.subtle.importKey('raw', enc.encode(env.SESSION_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']); return b64(await crypto.subtle.sign('HMAC', k, enc.encode(d))); };
const hashPw = async (pw, salt) => { const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']); return b64(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100000 }, k, 256)); };

async function me(req, env) {
  const m = /(?:^|; )s=([^;]+)/.exec(req.headers.get('cookie') || '');
  if (!m) return null;
  const [p, sig] = m[1].split('.');
  if (!p || !sig || !eq(sig, await hmac(env, p))) return null;
  let d; try { d = JSON.parse(atob(p)); } catch { return null; }
  if (d.e < Date.now()) return null;
  const owner = d.u.toLowerCase() === env.OWNER_USERNAME.toLowerCase();
  if (owner) return { name: env.OWNER_USERNAME, owner: true, id: 0 };
  const r = await env.DB.prepare('SELECT id,username FROM users WHERE username_lc=?').bind(d.u.toLowerCase()).first();
  return r ? { name: r.username, owner: false, id: r.id } : null;
}
async function session(env, u) {
  const p = btoa(JSON.stringify({ u, e: Date.now() + 30 * 864e5 }));
  return J({ ok: true }, 200, { 'set-cookie': `s=${p}.${await hmac(env, p)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=2592000` });
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url), path = url.pathname, M = req.method;
    if (!path.startsWith('/api/')) return new Response(page, { headers: { 'content-type': 'text/html;charset=utf-8' } });
    const DB = env.DB, now = Date.now();
    try {
      if (path.startsWith('/api/media/')) {
        const o = await env.MEDIA.get(path.slice(11), { range: req.headers });
        if (!o) return new Response('Not found', { status: 404 });
        const h = new Headers(); o.writeHttpMetadata(h);
        h.set('accept-ranges', 'bytes'); h.set('cache-control', 'public, max-age=31536000');
        if (o.range) { const { offset = 0, length = o.size - offset } = o.range; h.set('content-range', `bytes ${offset}-${offset + length - 1}/${o.size}`); return new Response(o.body, { status: 206, headers: h }); }
        return new Response(o.body, { headers: h });
      }
      const u = await me(req, env);
      if (path === '/api/me') return J(u ? { name: u.name, owner: u.owner } : null);
      if (path === '/api/logout') return J({ ok: true }, 200, { 'set-cookie': 's=; Max-Age=0; Path=/' });

      if (path === '/api/register' && M === 'POST') {
        const { username, password } = await req.json();
        if (!/^[A-Za-z0-9_]{3,20}$/.test(username || '')) return J({ error: 'Username must be 3-20 letters, numbers or _' }, 400);
        if ((password || '').length < 8) return J({ error: 'Password must be at least 8 characters' }, 400);
        const lc = username.toLowerCase();
        if (lc === env.OWNER_USERNAME.toLowerCase()) return J({ error: 'Username taken' }, 409);
        const salt = crypto.getRandomValues(new Uint8Array(16));
        try { await DB.prepare('INSERT INTO users(username,username_lc,salt,hash,created) VALUES(?,?,?,?,?)').bind(username, lc, b64(salt), await hashPw(password, salt), now).run(); }
        catch { return J({ error: 'Username taken' }, 409); }
        return session(env, username);
      }
      if (path === '/api/login' && M === 'POST') {
        const { username = '', password = '' } = await req.json();
        if (username.toLowerCase() === env.OWNER_USERNAME.toLowerCase())
          return eq(password, env.OWNER_PASSWORD) ? session(env, env.OWNER_USERNAME) : J({ error: 'Wrong username or password' }, 401);
        const r = await DB.prepare('SELECT * FROM users WHERE username_lc=?').bind(username.toLowerCase()).first();
        if (!r || !eq(r.hash, await hashPw(password, unb(r.salt)))) return J({ error: 'Wrong username or password' }, 401);
        return session(env, r.username);
      }

      if (path === '/api/posts' && M === 'GET') {
        const uid = u ? u.id : -1;
        const posts = (await DB.prepare('SELECT p.*,(SELECT COUNT(*) FROM likes WHERE post_id=p.id) likes,(SELECT COUNT(*) FROM likes WHERE post_id=p.id AND user_id=?) liked FROM posts p ORDER BY id DESC LIMIT 50').bind(uid).all()).results;
        const vc = (await DB.prepare('SELECT post_id,opt,COUNT(*) n FROM votes GROUP BY post_id,opt').all()).results;
        const mv = u && !u.owner ? (await DB.prepare('SELECT post_id,opt FROM votes WHERE user_id=?').bind(uid).all()).results : [];
        return J(posts.map(p => {
          const poll = p.poll ? JSON.parse(p.poll).map((t, i) => ({ text: t, votes: (vc.find(v => v.post_id === p.id && v.opt === i) || {}).n || 0 })) : null;
          const my = mv.find(v => v.post_id === p.id);
          return { id: p.id, body: p.body, link: p.link, media: p.media_key ? { url: '/api/media/' + p.media_key, type: p.media_type } : null, poll, myVote: my ? my.opt : null, likes: p.likes, liked: !!p.liked, created: p.created };
        }));
      }
      if (path === '/api/posts' && M === 'POST') {
        if (!u || !u.owner) return J({ error: 'Only the owner can post' }, 403);
        const f = await req.formData();
        const body = (f.get('body') || '').toString().trim().slice(0, 1000);
        const link = (f.get('link') || '').toString().trim();
        if (link && !/^https?:\/\//i.test(link)) return J({ error: 'Link must start with http:// or https://' }, 400);
        let poll = null; const opts = JSON.parse(f.get('poll') || '[]').map(s => String(s).trim().slice(0, 80)).filter(Boolean);
        if (opts.length) { if (opts.length < 2 || opts.length > 4) return J({ error: 'A poll needs 2-4 options' }, 400); poll = JSON.stringify(opts); }
        const file = f.get('file'); let key = null, type = null;
        if (file && file.size) {
          type = file.type.startsWith('video/') ? 'video' : file.type.startsWith('image/') ? 'image' : null;
          if (!type) return J({ error: 'Only photos and videos can be uploaded' }, 400);
          key = crypto.randomUUID();
          await env.MEDIA.put(key, file.stream(), { httpMetadata: { contentType: file.type } });
        }
        if (!body && !link && !poll && !key) return J({ error: 'Post is empty' }, 400);
        await DB.prepare('INSERT INTO posts(body,link,media_key,media_type,poll,created) VALUES(?,?,?,?,?,?)').bind(body, link || null, key, type, poll, now).run();
        return J({ ok: true });
      }

      if (!u) return J({ error: 'Log in first' }, 401);
      let m;
      if ((m = /^\/api\/like\/(\d+)$/.exec(path)) && M === 'POST') {
        if (u.owner) return J({ error: 'Owner cannot like own posts' }, 400);
        const del = await DB.prepare('DELETE FROM likes WHERE post_id=? AND user_id=?').bind(m[1], u.id).run();
        if (!del.meta.changes) await DB.prepare('INSERT OR IGNORE INTO likes VALUES(?,?)').bind(m[1], u.id).run();
        return J({ ok: true });
      }
      if ((m = /^\/api\/vote\/(\d+)$/.exec(path)) && M === 'POST') {
        if (u.owner) return J({ error: 'Owner cannot vote' }, 400);
        const { opt } = await req.json();
        await DB.prepare('INSERT OR IGNORE INTO votes VALUES(?,?,?)').bind(m[1], u.id, opt).run();
        return J({ ok: true });
      }
      if (path === '/api/dm/threads' && u.owner)
        return J((await DB.prepare('SELECT u.username name,MAX(m.id) last FROM messages m JOIN users u ON u.id=m.user_id GROUP BY u.id ORDER BY last DESC').all()).results);
      if (path === '/api/dm' && M === 'GET') {
        let uid = u.id;
        if (u.owner) { const t = await DB.prepare('SELECT id FROM users WHERE username_lc=?').bind((url.searchParams.get('with') || '').toLowerCase()).first(); if (!t) return J([]); uid = t.id; }
        return J((await DB.prepare('SELECT from_owner,body,created FROM messages WHERE user_id=? ORDER BY id').bind(uid).all()).results);
      }
      if (path === '/api/dm' && M === 'POST') {
        const { body = '', to } = await req.json();
        const text = body.trim().slice(0, 1000); if (!text) return J({ error: 'Message is empty' }, 400);
        let uid = u.id;
        if (u.owner) { const t = await DB.prepare('SELECT id FROM users WHERE username_lc=?').bind((to || '').toLowerCase()).first(); if (!t) return J({ error: 'No such user' }, 404); uid = t.id; }
        await DB.prepare('INSERT INTO messages(user_id,from_owner,body,created) VALUES(?,?,?,?)').bind(uid, u.owner ? 1 : 0, text, now).run();
        return J({ ok: true });
      }
      return J({ error: 'Not found' }, 404);
    } catch (e) { return J({ error: 'Server error' }, 500); }
  }
};
