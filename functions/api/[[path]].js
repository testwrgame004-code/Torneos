// API de torneos TCG Pocket (Cloudflare Pages Function + Upstash Redis).
// Contraseñas: NO están en el código. Se definen como variables en Cloudflare:
//   ADMIN_PASSWORD  → contraseña general del "Modo admin"
//   SUPER_PASSWORD  → contraseña de control total (se escribe en el mismo cuadro)
// Si una variable no existe, esa contraseña queda desactivada.
const P = 'tcgt:'; // prefijo de claves en Redis (no choca con tus bots)
const sha = async s => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))].map(b => b.toString(16).padStart(2, '0')).join('');
const eq = (a, b) => { a = String(a); b = String(b); if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0 };

export async function onRequest({ request, env }) {
  const url = new URL(request.url), path = url.pathname.replace(/^\/api\/?/, ''), method = request.method;
  const J = (o, s = 200, h = {}) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...h } });
  if (!env.UPSTASH_REDIS_REST_URL || !env.UPSTASH_REDIS_REST_TOKEN) return J({ error: 'Falta configurar Upstash en Cloudflare' }, 500);
  const R = async (...cmd) => { const r = await fetch(env.UPSTASH_REDIS_REST_URL, { method: 'POST', headers: { Authorization: 'Bearer ' + env.UPSTASH_REDIS_REST_TOKEN }, body: JSON.stringify(cmd) }); const j = await r.json(); if (j.error) throw new Error(j.error); return j.result };
  const listKey = new Request(url.origin + '/api/torneos');
  const isSuper = p => !!(env.SUPER_PASSWORD && p && eq(p, env.SUPER_PASSWORD));
  const isGen = p => !!(env.ADMIN_PASSWORD && p && eq(p, env.ADMIN_PASSWORD));
  const imgUrl = d => d.iv ? '/api/img/' + d.id + '?v=' + d.iv : '';
  try {
    if (method === 'GET' && path === 'torneos') {
      const hit = await caches.default.match(listKey); if (hit) return hit;
      const h = (await R('HGETALL', P + 't')) || [], out = [];
      for (let i = 0; i < h.length; i += 2) { const d = JSON.parse(h[i + 1]); d.img = imgUrl(d); delete d.ph; delete d.salt; delete d.iv; delete d.gi; out.push(d) }
      const res = J(out, 200, { 'cache-control': 'public, max-age=8' });
      await caches.default.put(listKey, res.clone()); return res;
    }
    if (method === 'GET' && path.startsWith('img/')) {
      const v = await R('GET', P + 'i:' + path.slice(4)), m = v && v.match(/^data:(image\/[a-z+]+);base64,(.*)$/);
      if (!m) return new Response('', { status: 404 });
      return new Response(Uint8Array.from(atob(m[2]), c => c.charCodeAt(0)), { headers: { 'content-type': m[1], 'cache-control': 'public, max-age=31536000, immutable' } });
    }
    if (method !== 'POST') return J({ error: 'No encontrado' }, 404);
    const body = await request.json().catch(() => ({}));
    const ip = request.headers.get('CF-Connecting-IP') || 'x', fk = P + 'f:' + ip;
    if (+(await R('GET', fk)) >= 10) return J({ error: 'Demasiados intentos. Espera unos minutos.' }, 429);
    const bad = async () => { await R('INCR', fk); await R('EXPIRE', fk, 600); return J({ error: 'Contraseña incorrecta' }, 401) };
    const load = async id => { const r = typeof id === 'string' && await R('HGET', P + 't', id); return r ? JSON.parse(r) : null };
    const check = async (d, pw) => !!(pw && d.ph && d.ph === await sha(d.salt + ':' + pw));

    if (path === 'login') return isSuper(body.pass) ? J({ r: 2 }) : isGen(body.pass) ? J({ r: 1 }) : bad();
    if (path === 'auth') { const d = await load(body.id); if (!d) return J({ error: 'No existe' }, 404); return (await check(d, body.tp)) ? J({ ok: 1 }) : bad() }
    if (path === 'delete') {
      const d = await load(body.id); if (!d) return J({ error: 'No existe' }, 404);
      if (!isSuper(body.sp) && !(await check(d, body.tp))) return bad();
      await R('HDEL', P + 't', d.id); await R('DEL', P + 'i:' + d.id); for (const k of d.gi || []) await R('DEL', P + 'i:' + d.id + ':' + k); await caches.default.delete(listKey); return J({ ok: 1 });
    }
    if (path === 'save') {
      const doc = body.doc, sup = isSuper(body.sp);
      if (!doc || !/^t[a-z0-9]{3,20}$/.test(doc.id || '')) return J({ error: 'Datos inválidos' }, 400);
      if (JSON.stringify(doc).length > 300000) return J({ error: 'Torneo demasiado grande' }, 413);
      const old = await load(doc.id);
      if (body.create) {
        if (old) return J({ error: 'Ya existe' }, 409);
        if (!sup && !isGen(body.gp)) return bad();
        if (!body.pw || String(body.pw).length < 3) return J({ error: 'Contraseña de torneo inválida' }, 400);
      } else {
        if (!old) return J({ error: 'No existe' }, 404);
        if (!sup && !(await check(old, body.tp))) return bad();
      }
      const d = {
        id: doc.id, name: String(doc.name || '').slice(0, 60), fmt: ['bo3', 'sd', 'mix', 'duo'].includes(doc.fmt) ? doc.fmt : 'sd',
        parts: (Array.isArray(doc.parts) ? doc.parts : []).slice(0, 128).map(s => String(s).slice(0, 60)),
        ms: (Array.isArray(doc.ms) ? doc.ms : []).slice(0, 300), start: doc.start === undefined ? (old ? old.start || 0 : 0) : (Number.isFinite(+doc.start) && +doc.start > 0 ? Math.floor(+doc.start) : 0), info: typeof doc.info === 'string' ? doc.info.slice(0, 6000) : (old ? old.info || '' : ''), rules: typeof doc.rules === 'string' ? doc.rules.slice(0, 6000) : (old ? old.rules || '' : ''),
        created: old ? old.created : Date.now(), upd: Number(doc.upd) || Date.now(),
        by: (body.create || sup) ? String(doc.by || '').slice(0, 24) : old.by, ph: old ? old.ph : '', salt: old ? old.salt : '', iv: old ? old.iv : 0
      };
      // Imágenes insertadas en info/reglas: se referencian como img:TOKEN y se guardan en Redis (máx. 10 por torneo).
      const used = new Set([...(d.info + ' ' + d.rules).matchAll(/img:([a-z0-9]{4,12})/g)].map(m => m[1]));
      const imgs = body.imgs && typeof body.imgs === 'object' ? body.imgs : {};
      const add = Object.keys(imgs).filter(k => /^[a-z0-9]{4,12}$/.test(k) && used.has(k)).slice(0, 10);
      for (const k of add) if (typeof imgs[k] !== 'string' || !/^data:image\/(png|jpeg|webp|gif);base64,[A-Za-z0-9+\/=]+$/.test(imgs[k]) || imgs[k].length > 200000) return J({ error: 'Imagen inválida o demasiado grande' }, 413);
      const oldGi = old && Array.isArray(old.gi) ? old.gi : [];
      d.gi = [...new Set([...oldGi.filter(k => used.has(k)), ...add])];
      if (d.gi.length > 10) return J({ error: 'Máximo 10 imágenes por torneo' }, 400);
      if (body.create || (sup && body.newpw)) { d.salt = crypto.randomUUID(); d.ph = await sha(d.salt + ':' + (body.create ? body.pw : body.newpw)) }
      if (typeof doc.img === 'string' && doc.img.startsWith('data:image/')) {
        if (doc.img.length > 200000) return J({ error: 'Imagen demasiado grande' }, 413);
        await R('SET', P + 'i:' + d.id, doc.img); d.iv = Date.now();
      } else if (doc.img === '' && d.iv) { await R('DEL', P + 'i:' + d.id); d.iv = 0 }
      for (const k of add) await R('SET', P + 'i:' + d.id + ':' + k, imgs[k]);
      for (const k of oldGi) if (!used.has(k)) await R('DEL', P + 'i:' + d.id + ':' + k);
      await R('HSET', P + 't', d.id, JSON.stringify(d)); await caches.default.delete(listKey);
      return J({ ok: 1, img: imgUrl(d) });
    }
    return J({ error: 'No encontrado' }, 404);
  } catch (e) { return J({ error: 'Error del servidor' }, 500) }
}
