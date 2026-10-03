// Horizon Render — funzione del server (Netlify Edge Function)
//
// Fa una cosa sola: "Cerca online", cioè cerca foto e video gratuiti su
// Pixabay, Pexels e Unsplash. Le chiavi restano qui sul server, mai dentro il sito.
// Il sito in sé è pubblico: chi ha il link lo apre, senza nome utente né password.
//
// Impostazioni su Netlify (Project configuration > Environment variables):
//   PIXABAY_KEY    la chiave API di Pixabay     (foto e video)
//   PEXELS_KEY     la chiave API di Pexels      (foto e video)   facoltativa
//   UNSPLASH_KEY   la "Access Key" di Unsplash  (solo foto)      facoltativa
// Dopo ogni modifica alle variabili: Deploys > Trigger deploy > Deploy project.

const env = (k) => (globalThis.Netlify && Netlify.env.get(k)) || '';

// Le ricerche si accettano solo dalle pagine del sito stesso (non da altri siti).
function sameSite(req){
  const f = req.headers.get('sec-fetch-site'); if (f) return f === 'same-origin';
  const o = req.headers.get('origin') || req.headers.get('referer'); if (!o) return true;
  try { return new URL(o).host === new URL(req.url).host; } catch (e){ return false; }
}
function json(obj, status){ return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type':'application/json', 'Cache-Control':'no-store' } }); }

/* ---------- librerie gratuite ---------- */
const PER = 12;
const MEDIA_HOSTS = /(^|\.)(pixabay\.com|pexels\.com|unsplash\.com|vimeo\.com|vimeocdn\.com)$/;
async function getJSON(u, headers){
  const ac = new AbortController(); const t = setTimeout(() => ac.abort(), 8000);
  try { const r = await fetch(u, { headers: headers || {}, signal: ac.signal }); if (!r.ok) return { err: r.status }; return { data: await r.json() }; }
  catch (e){ return { err: 'net' }; } finally { clearTimeout(t); }
}
async function searchPixabay(q, page, kind, orient){
  const key = env('PIXABAY_KEY'); if (!key) return null;
  const isV = kind === 'video'; const u = new URL('https://pixabay.com/api/' + (isV ? 'videos/' : ''));
  const p = { key, q, lang:'it', safesearch:'true', per_page:String(PER), page:String(page) };
  if (isV) p.video_type = 'film'; else { p.image_type = 'photo'; if (orient) p.orientation = orient === 'v' ? 'vertical' : 'horizontal'; }
  for (const k in p) u.searchParams.set(k, p[k]);
  const r = await getJSON(u.toString()); if (!r.data) return { err: r.err, hits: [], more: false };
  const hits = (r.data.hits || []).map(h => {
    if (!isV) return { src:'pixabay', id:'pb' + h.id, prev:h.webformatURL, large:h.largeImageURL || h.webformatURL, alt:h.webformatURL, user:h.user, page:h.pageURL };
    const v = h.videos || {}; const pick = v.tiny && v.tiny.url ? v.tiny : (v.small && v.small.url ? v.small : v.medium || {});
    const thumb = (v.tiny && v.tiny.thumbnail) || (v.small && v.small.thumbnail) || (v.medium && v.medium.thumbnail) || (h.picture_id ? 'https://i.vimeocdn.com/video/' + h.picture_id + '_295x166.jpg' : '');
    return { src:'pixabay', id:'pb' + h.id, prev:thumb, large:pick.url, alt:(v.small && v.small.url) || '', dur:h.duration || 0, user:h.user, page:h.pageURL };
  }).filter(h => h.large);
  return { hits, more: page*PER < (r.data.totalHits || 0) };
}
async function searchPexels(q, page, kind, orient){
  const key = env('PEXELS_KEY'); if (!key) return null;
  const isV = kind === 'video';
  const build = base => { const u = new URL(base); u.searchParams.set('query', q); u.searchParams.set('per_page', String(PER)); u.searchParams.set('page', String(page)); u.searchParams.set('locale', 'it-IT'); if (orient) u.searchParams.set('orientation', orient === 'v' ? 'portrait' : 'landscape'); return u.toString(); };
  let r = await getJSON(build(isV ? 'https://api.pexels.com/v1/videos/search' : 'https://api.pexels.com/v1/search'), { Authorization: key });
  if (isV && r.err === 404) r = await getJSON(build('https://api.pexels.com/videos/search'), { Authorization: key });
  if (!r.data) return { err: r.err, hits: [], more: false };
  const d = r.data;
  const hits = isV
    ? (d.videos || []).map(v => {
        const files = (v.video_files || []).filter(f => f.link && String(f.file_type || '').indexOf('mp4') > -1).sort((a, b) => (a.width || 0) - (b.width || 0));
        const ok = files.filter(f => Math.min(f.width || 0, f.height || 0) >= 360);
        const good = ok[0] || files[files.length - 1]; if (!good) return null;
        return { src:'pexels', id:'pv' + v.id, prev:v.image, large:good.link, alt:(ok[1] && ok[1].link) || '', dur:v.duration || 0, user:(v.user || {}).name || 'Pexels', page:v.url };
      }).filter(Boolean)
    : (d.photos || []).map(p => ({ src:'pexels', id:'pp' + p.id, prev:(p.src || {}).medium, large:(p.src || {}).large2x || (p.src || {}).large, alt:(p.src || {}).large, user:p.photographer, page:p.url })).filter(h => h.large);
  return { hits, more: !!d.next_page };
}
async function searchUnsplash(q, page, kind, orient){
  if (kind === 'video') return null;
  const key = env('UNSPLASH_KEY'); if (!key) return null;
  const u = new URL('https://api.unsplash.com/search/photos');
  u.searchParams.set('query', q); u.searchParams.set('page', String(page)); u.searchParams.set('per_page', String(PER)); u.searchParams.set('content_filter', 'high');
  if (orient) u.searchParams.set('orientation', orient === 'v' ? 'portrait' : 'landscape');
  const r = await getJSON(u.toString(), { Authorization: 'Client-ID ' + key, 'Accept-Version':'v1' });
  if (!r.data) return { err: r.err, hits: [], more: false };
  const utm = '?utm_source=horizon_render&utm_medium=referral';
  const hits = (r.data.results || []).map(p => ({
    src:'unsplash', id:'us' + p.id, prev:(p.urls || {}).small, large:(p.urls || {}).regular, alt:(p.urls || {}).small,
    user:(p.user || {}).name || 'Unsplash', page:(((p.user || {}).links || {}).html || 'https://unsplash.com') + utm, dl:(p.links || {}).download_location
  })).filter(h => h.large);
  return { hits, more: page < (r.data.total_pages || 0) };
}
// Interroga le librerie in parallelo e alterna i risultati (uno per libreria).
async function searchAll(q, page, kind, orient){
  const all = (await Promise.all([searchPixabay, searchPexels, searchUnsplash].map(fn => fn(q, page, kind, orient)))).filter(Boolean);
  const lists = all.map(r => r.hits); const hits = [];
  for (let i = 0; lists.some(l => i < l.length); i++) lists.forEach(l => { if (i < l.length) hits.push(l[i]); });
  return { hits, more: all.some(r => r.more), tried: all.length, failed: all.filter(r => r.err).length, rate: all.some(r => r.err === 429 || r.err === 403) };
}

export default async (request, context) => {
  const url = new URL(request.url);
  const path = url.pathname;

  /* ---------- ricerca online ---------- */
  if (path.indexOf('/api/') === 0){
    if (!sameSite(request)) return json({ error:'origin' }, 403);

    // "Cerca online": una ricerca su tutte le librerie configurate. Le chiavi restano sul server.
    if (path === '/api/search'){
      if (!env('PIXABAY_KEY') && !env('PEXELS_KEY') && !env('UNSPLASH_KEY')) return json({ error:'nokey' }, 503);
      const q = (url.searchParams.get('q') || '').trim().slice(0, 100);
      if (!q) return json({ hits:[], more:false }, 200);
      const kind = url.searchParams.get('kind') === 'video' ? 'video' : 'photo';
      const page = Math.min(50, Math.max(1, parseInt(url.searchParams.get('page') || '1', 10) || 1));
      const o = url.searchParams.get('orient'); const orient = o === 'h' || o === 'v' ? o : '';
      let res = await searchAll(q, page, kind, orient);
      if (orient && page === 1 && !res.hits.length) res = await searchAll(q, page, kind, ''); // riprova senza orientamento
      if (!res.hits.length && res.tried && res.failed === res.tried) return json({ error:'upstream' }, res.rate ? 429 : 502);
      return new Response(JSON.stringify({ hits: res.hits, more: res.more }), { status: 200, headers: { 'Content-Type':'application/json', 'Cache-Control':'private, max-age=86400' } });
    }
    // Unsplash chiede di segnalare ogni foto effettivamente usata.
    if (path === '/api/track'){
      let t; try { t = new URL(url.searchParams.get('u') || ''); } catch (e){ return json({ error:'bad' }, 400); }
      if (t.protocol !== 'https:' || t.hostname !== 'api.unsplash.com' || !/^\/photos\/[^/]+\/download/.test(t.pathname) || !env('UNSPLASH_KEY')) return json({ error:'bad' }, 400);
      try { await fetch(t.toString(), { headers: { Authorization: 'Client-ID ' + env('UNSPLASH_KEY'), 'Accept-Version':'v1' } }); } catch (e){}
      return new Response(null, { status: 204 });
    }
    // Scarico foto e video delle librerie per conto del browser (solo i loro indirizzi).
    if (path === '/api/px-media'){
      let target; try { target = new URL(url.searchParams.get('u') || ''); } catch (e){ return json({ error:'bad' }, 400); }
      if (target.protocol !== 'https:' || !MEDIA_HOSTS.test(target.hostname)) return json({ error:'host' }, 403);
      let r; try { r = await fetch(target.toString()); } catch (e){ return json({ error:'upstream' }, 502); }
      if (!r.ok) return json({ error:'upstream', status:r.status }, 502);
      return new Response(r.body, { status: 200, headers: { 'Content-Type': r.headers.get('content-type') || 'application/octet-stream', 'Cache-Control':'private, max-age=3600' } });
    }
    return json({ error:'not_found' }, 404);
  }

  return context.next();   // qualsiasi altro indirizzo: lo gestisce Netlify
};

export const config = {
  path: '/api/*'
};
