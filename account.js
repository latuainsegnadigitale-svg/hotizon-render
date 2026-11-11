// Horizon Render — account (amministratore → venditori) e registro degli accessi, su database Cloudflare D1.
//
// Regole:
//  · il sito si apre solo dopo l'accesso: senza account si vede soltanto la pagina "Accedi" (vedi worker.js);
//  · l'amministratore (master) apre, modifica, disattiva i venditori, cambia le loro password,
//    li scollega da tutti i dispositivi e legge il registro degli accessi;
//  · il venditore entra con nome utente + password e usa Horizon Render; può cambiare solo il suo profilo;
//  · ogni accesso, tentativo sbagliato e visita senza account finisce nel registro con indirizzo IP,
//    città/paese, rete e dispositivo.
//
// Impostazioni su Cloudflare:
//  · collegamento al database D1 con nome "DB" (in wrangler.jsonc);
//  · Secret MASTER_PASSWORD: la password dell'amministratore. Al primo avvio crea l'account
//    (nome utente "paolo", oppure MASTER_USER). Funziona sempre anche come password di riserva.
//
// Sicurezza: password salvate solo come impronta (PBKDF2), sessione in un cookie HttpOnly,
// tentativi di accesso limitati, al massimo MAX_DEVICES dispositivi collegati per venditore.

const SESSION_DAYS = { seller: 30, master: 30 };
const MAX_DEVICES = 3;                     // un venditore collegato da più dispositivi: il più vecchio esce
const MAX_FAILS_USER = 8, MAX_FAILS_IP = 30, FAIL_WINDOW = 15 * 60 * 1000;
const LOG_DAYS = 180;                      // il registro tiene gli ultimi 6 mesi
const SEEN_GAP = 30 * 60 * 1000;           // "apertura" e "visita" si registrano al massimo ogni 30 minuti
const COOKIE = 'hr_session';
let schemaReady = false;

/* ---------- utilità ---------- */
const now = () => Date.now();
export function json(obj, status, headers){ return new Response(JSON.stringify(obj), { status: status || 200, headers: Object.assign({ 'Content-Type':'application/json', 'Cache-Control':'no-store' }, headers || {}) }); }
const fail = (msg, code, status) => json({ error: msg, code: code || 'bad' }, status || 400);
const b64u = bytes => btoa(String.fromCharCode.apply(null, Array.from(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), c => c.charCodeAt(0));
async function sha256(s){ const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)); return Array.from(new Uint8Array(d), b => b.toString(16).padStart(2, '0')).join(''); }
function sameText(a, b){ a = String(a); b = String(b); let r = a.length ^ b.length; for (let i = 0; i < Math.max(a.length, b.length); i++) r |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0); return r === 0; }
async function hashPass(pw, saltB64){
  const salt = saltB64 ? unb64u(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name:'PBKDF2', hash:'SHA-256', salt, iterations:100000 }, key, 256);
  return 'pbkdf2$100000$' + b64u(salt) + '$' + b64u(new Uint8Array(bits));
}
async function checkPass(pw, stored){ if (!stored || !pw) return false; const p = stored.split('$'); if (p.length !== 4) return false; return sameText(await hashPass(pw, p[2]), stored); }
const cleanPhone = v => String(v || '').replace(/\D/g, '');
const phoneOk = d => /^\d{11,15}$/.test(d);
const str = (v, max) => String(v == null ? '' : v).trim().slice(0, max || 120);
function cookieOf(req, name){ const c = req.headers.get('cookie') || ''; const m = c.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]+)')); return m ? m[1] : ''; }
const setCookie = (tok, days) => COOKIE + '=' + tok + '; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=' + Math.round(days * 86400);
const clearCookie = () => COOKIE + '=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0';
// Da dove arriva la richiesta: IP, città, paese, rete (Cloudflare lo sa già, non serve chiedere a nessuno).
function whereOf(req){
  const cf = req.cf || {};
  return {
    ip: req.headers.get('cf-connecting-ip') || req.headers.get('x-real-ip') || '',
    country: str(cf.country, 4), city: str(cf.city, 60), region: str(cf.region, 60),
    org: str(cf.asOrganization, 80), ua: str(req.headers.get('user-agent'), 300)
  };
}

/* ---------- database ---------- */
export async function ensureSchema(db){
  if (schemaReady) return;
  const steps = [
    `CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY, role TEXT NOT NULL, name TEXT NOT NULL, username TEXT NOT NULL, username_lc TEXT NOT NULL UNIQUE,
      pass_hash TEXT, phone TEXT NOT NULL DEFAULT '', active INTEGER NOT NULL DEFAULT 1,
      created_at INTEGER NOT NULL, created_by TEXT, updated_at INTEGER NOT NULL, last_login INTEGER)`,
    `CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL,
      last_seen INTEGER NOT NULL DEFAULT 0, ip TEXT NOT NULL DEFAULT '', country TEXT NOT NULL DEFAULT '', city TEXT NOT NULL DEFAULT '', ua TEXT NOT NULL DEFAULT '')`,
    'CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id)',
    'CREATE TABLE IF NOT EXISTS login_fails (k TEXT PRIMARY KEY, n INTEGER NOT NULL, until INTEGER NOT NULL)',
    `CREATE TABLE IF NOT EXISTS access_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, event TEXT NOT NULL, user_id TEXT, tried TEXT,
      ip TEXT NOT NULL DEFAULT '', country TEXT NOT NULL DEFAULT '', city TEXT NOT NULL DEFAULT '', region TEXT NOT NULL DEFAULT '',
      org TEXT NOT NULL DEFAULT '', ua TEXT NOT NULL DEFAULT '', info TEXT NOT NULL DEFAULT '')`,
    'CREATE INDEX IF NOT EXISTS log_ts ON access_log(ts)',
    'CREATE INDEX IF NOT EXISTS log_user ON access_log(user_id, ts)',
    'CREATE INDEX IF NOT EXISTS log_ip ON access_log(ip, event, ts)'
  ];
  for (const sql of steps) await db.prepare(sql).run();   // una alla volta: le tabelle si creano da sole al primo avvio
  schemaReady = true;
}
const getUser = (db, id) => id ? db.prepare('SELECT * FROM users WHERE id = ?').bind(id).first() : null;
const getMaster = db => db.prepare("SELECT * FROM users WHERE role = 'master' ORDER BY created_at LIMIT 1").first();
// Primo avvio: crea l'amministratore con la password scritta nei Secret di Cloudflare.
async function ensureMaster(db, env){
  const m = await getMaster(db); if (m) return m;
  if (!env.MASTER_PASSWORD) return null;
  const t = now(), uname = str(env.MASTER_USER || 'paolo', 30);
  await db.prepare('INSERT OR IGNORE INTO users (id, role, name, username, username_lc, pass_hash, phone, active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)')
    .bind(crypto.randomUUID(), 'master', str(env.MASTER_NAME || 'Paolo Tolve', 80), uname, uname.toLowerCase(), await hashPass(env.MASTER_PASSWORD), cleanPhone(env.MASTER_PHONE || ''), t, t).run();
  return getMaster(db);
}
async function addLog(db, event, where, userId, tried, info){
  try {
    await db.prepare('INSERT INTO access_log (ts, event, user_id, tried, ip, country, city, region, org, ua, info) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .bind(now(), event, userId || null, tried ? str(tried, 60) : null, where.ip, where.country, where.city, where.region, where.org, where.ua, str(info, 200)).run();
  } catch (e){}
}

/* ---------- sessione ---------- */
async function loadSession(req, db){
  const tok = cookieOf(req, COOKIE); if (!tok) return {};
  const th = await sha256(tok);
  const s = await db.prepare('SELECT * FROM sessions WHERE token_hash = ? AND expires_at > ?').bind(th, now()).first();
  if (!s) return {};
  const user = await getUser(db, s.user_id);
  if (!user || !user.active){ await db.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(th).run(); return {}; }
  return { th, s, user };
}
// Usata dal worker per ogni pagina: chi è collegato (null = nessuno). Registra anche le aperture del sito.
export async function gateCheck(req, env, isPage){
  const db = env.DB; if (!db) return { nodb: true };
  await ensureSchema(db);
  const ses = await loadSession(req, db), t = now(), where = whereOf(req);
  if (!ses.user){
    if (isPage){   // qualcuno senza account ha aperto il sito: lo segniamo (una volta ogni 30 minuti per IP)
      const last = await db.prepare("SELECT ts FROM access_log WHERE ip = ? AND event = 'visit' ORDER BY ts DESC LIMIT 1").bind(where.ip).first();
      if (!last || t - last.ts > SEEN_GAP) await addLog(db, 'visit', where, null, null, new URL(req.url).pathname);
    }
    return { user: null };
  }
  if (isPage && t - (ses.s.last_seen || 0) > SEEN_GAP){
    await db.prepare('UPDATE sessions SET last_seen = ?, ip = ?, country = ?, city = ?, ua = ? WHERE token_hash = ?').bind(t, where.ip, where.country, where.city, where.ua, ses.th).run();
    const changed = ses.s.ip && ses.s.ip !== where.ip;
    await addLog(db, 'open', where, ses.user.id, null, changed ? 'IP diverso da quello dell\'accesso (' + ses.s.ip + ')' : '');
  }
  return { user: ses.user };
}
function view(u){ return { id:u.id, role:u.role, name:u.name, username:u.username, phone:u.phone || '', active: !!u.active, lastLogin: u.last_login || null, createdAt: u.created_at }; }

/* ---------- tentativi di accesso ---------- */
async function blocked(db, k, max){ const r = await db.prepare('SELECT n, until FROM login_fails WHERE k = ?').bind(k).first(); return !!(r && r.until > now() && r.n >= max); }
async function addFail(db, k){
  const t = now(), r = await db.prepare('SELECT n, until FROM login_fails WHERE k = ?').bind(k).first();
  if (!r || r.until <= t) await db.prepare('INSERT OR REPLACE INTO login_fails (k, n, until) VALUES (?, 1, ?)').bind(k, t + FAIL_WINDOW).run();
  else await db.prepare('UPDATE login_fails SET n = n + 1 WHERE k = ?').bind(k).run();
}

/* ---------- statistiche per l'amministratore ---------- */
async function statsOf(db){
  const t = now(), d7 = t - 7*86400000, d30 = t - 30*86400000;
  const [ses, ips, foreign, fails] = await Promise.all([
    db.prepare('SELECT user_id, COUNT(*) AS n FROM sessions WHERE expires_at > ? GROUP BY user_id').bind(t).all(),
    db.prepare("SELECT user_id, COUNT(DISTINCT ip) AS n FROM access_log WHERE ts > ? AND user_id IS NOT NULL AND event IN ('login','open') GROUP BY user_id").bind(d7).all(),
    db.prepare("SELECT user_id, GROUP_CONCAT(DISTINCT country) AS c FROM access_log WHERE ts > ? AND user_id IS NOT NULL AND country != '' AND country != 'IT' GROUP BY user_id").bind(d30).all(),
    db.prepare("SELECT tried, COUNT(*) AS n FROM access_log WHERE ts > ? AND event = 'fail' GROUP BY tried").bind(d7).all()
  ]);
  const m = {}; const at = id => (m[id] = m[id] || { devices:0, ips7:0, abroad:'', fails7:0 });
  (ses.results || []).forEach(r => { at(r.user_id).devices = r.n; });
  (ips.results || []).forEach(r => { at(r.user_id).ips7 = r.n; });
  (foreign.results || []).forEach(r => { at(r.user_id).abroad = r.c || ''; });
  return { byUser: m, failsByName: Object.fromEntries((fails.results || []).map(r => [String(r.tried || '').toLowerCase(), r.n])) };
}

/* ---------- richieste ---------- */
export async function handleAcc(request, env){
  if (request.method !== 'POST') return fail('Richiesta non valida.', 'method', 405);
  const db = env.DB;
  if (!db) return fail('Il database degli account non è ancora collegato.', 'nodb', 503);
  await ensureSchema(db);
  let d; try { d = await request.json(); } catch (e){ return fail('Richiesta non valida.'); }
  const ses = await loadSession(request, db), me = ses.user, where = whereOf(request);
  const needMaster = () => !me ? fail('Devi accedere di nuovo.', 'auth', 401) : me.role !== 'master' ? fail('Solo l\'amministratore può farlo.', 'perm', 403) : null;

  switch (d.action){
    case 'me':
      return json({ user: me ? view(me) : null });

    case 'login': {
      const master = await ensureMaster(db, env);
      if (!master) return fail('Il sito non è ancora configurato: manca la password dell\'amministratore su Cloudflare.', 'setup', 503);
      const uname = str(d.username, 60).toLowerCase(), pw = str(d.password, 200);
      if (!uname || !pw) return fail('Scrivi nome utente e password.');
      if (await blocked(db, 'u:' + uname, MAX_FAILS_USER) || await blocked(db, 'ip:' + where.ip, MAX_FAILS_IP)){
        await addLog(db, 'blocked', where, null, uname, 'troppi tentativi');
        return fail('Troppi tentativi sbagliati. Riprova tra 15 minuti.', 'slow', 429);
      }
      const u = await db.prepare('SELECT * FROM users WHERE username_lc = ?').bind(uname).first();
      let good = false;
      if (u){ good = await checkPass(pw, u.pass_hash); if (!good && u.role === 'master' && env.MASTER_PASSWORD) good = sameText(pw, env.MASTER_PASSWORD); }
      if (!good){
        await addFail(db, 'u:' + uname); await addFail(db, 'ip:' + where.ip);
        await addLog(db, 'fail', where, u ? u.id : null, uname, u ? 'password sbagliata' : 'nome utente inesistente');
        return fail('Nome utente o password non corretti.', 'auth', 401);
      }
      if (!u.active){ await addLog(db, 'off', where, u.id, uname, 'account disattivato'); return fail('Questo account è disattivato. Chiedi all\'amministratore.', 'off', 403); }
      await db.prepare('DELETE FROM login_fails WHERE k = ?').bind('u:' + uname).run();
      const tok = b64u(crypto.getRandomValues(new Uint8Array(32))), days = SESSION_DAYS[u.role] || 30, t = now();
      await db.batch([
        db.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(t),
        db.prepare('DELETE FROM access_log WHERE ts < ?').bind(t - LOG_DAYS*86400000),
        db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at, created_at, last_seen, ip, country, city, ua) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
          .bind(await sha256(tok), u.id, t + days*86400000, t, t, where.ip, where.country, where.city, where.ua),
        db.prepare('UPDATE users SET last_login = ? WHERE id = ?').bind(t, u.id)
      ]);
      await addLog(db, 'login', where, u.id, null, '');
      // troppi dispositivi collegati (credenziali passate ad altri?): esce il più vecchio
      if (u.role !== 'master'){
        const old = await db.prepare('SELECT token_hash, ip, city FROM sessions WHERE user_id = ? ORDER BY last_seen DESC LIMIT -1 OFFSET ?').bind(u.id, MAX_DEVICES).all();
        for (const o of (old.results || [])){
          await db.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(o.token_hash).run();
          await addLog(db, 'kicked', where, u.id, null, 'scollegato il dispositivo più vecchio (' + (o.ip || '?') + (o.city ? ', ' + o.city : '') + '): più di ' + MAX_DEVICES + ' dispositivi');
        }
      }
      return json({ user: view(Object.assign({}, u, { last_login: t })) }, 200, { 'Set-Cookie': setCookie(tok, days) });
    }

    case 'logout':
      if (ses.th){ await db.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(ses.th).run(); if (me) await addLog(db, 'logout', where, me.id); }
      return json({ ok:true }, 200, { 'Set-Cookie': clearCookie() });

    // Eventi dell'app (es. render scaricato): così il registro dice anche chi usa davvero lo strumento.
    case 'event': {
      if (!me) return fail('Devi accedere di nuovo.', 'auth', 401);
      const type = d.type === 'export' ? 'export' : d.type === 'export-spot' ? 'export-spot' : null;
      if (type) await addLog(db, type, where, me.id, null, str(d.info, 120));
      return json({ ok:true });
    }

    case 'list': {
      const no = needMaster(); if (no) return no;
      const r = await db.prepare("SELECT * FROM users ORDER BY CASE role WHEN 'master' THEN 0 ELSE 1 END, active DESC, name COLLATE NOCASE").all();
      const st = await statsOf(db);
      return json({ users: (r.results || []).map(u => Object.assign(view(u), st.byUser[u.id] || { devices:0, ips7:0, abroad:'' }, { fails7: st.failsByName[u.username_lc] || 0 })) });
    }

    case 'save': {
      const no = needMaster(); if (no) return no;
      const x = d.user || {}, t = now();
      const cur = x.id ? await getUser(db, str(x.id, 60)) : null;
      if (x.id && !cur) return fail('Account non trovato.', 'missing', 404);
      if (cur && cur.role === 'master') return fail('Il tuo account si modifica da "Il mio profilo".', 'perm', 403);
      const name = str(x.name, 80), username = str(x.username, 30), phone = cleanPhone(x.phone), pw = str(x.password, 200);
      if (!name) return fail('Scrivi nome e cognome.');
      if (!/^[a-z0-9._-]{3,30}$/i.test(username)) return fail('Il nome utente: almeno 3 caratteri, senza spazi.');
      if (phone && !phoneOk(phone)) return fail('Il numero WhatsApp non è valido.');
      if (!cur && pw.length < 6) return fail('La password deve avere almeno 6 caratteri.');
      if (pw && pw.length < 6) return fail('La nuova password deve avere almeno 6 caratteri.');
      const dup = await db.prepare('SELECT id FROM users WHERE username_lc = ?').bind(username.toLowerCase()).first();
      if (dup && (!cur || dup.id !== cur.id)) return fail('Questo nome utente esiste già.', 'dup', 409);
      const active = x.active === false ? 0 : 1;
      if (cur){
        await db.prepare('UPDATE users SET name = ?, username = ?, username_lc = ?, phone = ?, pass_hash = ?, active = ?, updated_at = ? WHERE id = ?')
          .bind(name, username, username.toLowerCase(), phone, pw ? await hashPass(pw) : cur.pass_hash, active, t, cur.id).run();
        // disattivato o password cambiata: esce da tutti i dispositivi
        if (!active || pw) await db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(cur.id).run();
        if (!active && cur.active) await addLog(db, 'disabled', where, cur.id, null, 'disattivato da ' + me.name);
        if (active && !cur.active) await addLog(db, 'enabled', where, cur.id, null, 'riattivato da ' + me.name);
        if (pw) await addLog(db, 'password', where, cur.id, null, 'password cambiata da ' + me.name);
      } else {
        const id = crypto.randomUUID();
        await db.prepare('INSERT INTO users (id, role, name, username, username_lc, pass_hash, phone, active, created_at, created_by, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)')
          .bind(id, 'seller', name, username, username.toLowerCase(), await hashPass(pw), phone, t, me.id, t).run();
        await addLog(db, 'created', where, id, null, 'aperto da ' + me.name);
      }
      const saved = await db.prepare('SELECT * FROM users WHERE username_lc = ?').bind(username.toLowerCase()).first();
      return json({ user: view(saved) });
    }

    case 'saveMe': {
      if (!me) return fail('Devi accedere di nuovo.', 'auth', 401);
      const name = str(d.name, 80), phone = cleanPhone(d.phone), pw = str(d.password, 200);
      if (!name) return fail('Scrivi nome e cognome.');
      if (phone && !phoneOk(phone)) return fail('Il numero WhatsApp non è valido.');
      if (pw && pw.length < 6) return fail('La password deve avere almeno 6 caratteri.');
      await db.prepare('UPDATE users SET name = ?, phone = ?, pass_hash = ?, updated_at = ? WHERE id = ?').bind(name, phone, pw ? await hashPass(pw) : me.pass_hash, now(), me.id).run();
      if (pw){   // password cambiata: restano collegati solo questo dispositivo
        await db.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?').bind(me.id, ses.th).run();
        await addLog(db, 'password', where, me.id, null, 'password cambiata da sé');
      }
      return json({ ok:true });
    }

    // Scollega un venditore da tutti i dispositivi (dovrà rientrare con la password).
    case 'kick': {
      const no = needMaster(); if (no) return no;
      const u = await getUser(db, str(d.id, 60));
      if (!u || u.role === 'master') return fail('Account non trovato.');
      await db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(u.id).run();
      await addLog(db, 'kicked', where, u.id, null, 'scollegato da tutti i dispositivi da ' + me.name);
      return json({ ok:true });
    }

    // Dispositivi collegati adesso a un account.
    case 'devices': {
      const no = needMaster(); if (no) return no;
      const r = await db.prepare('SELECT created_at, last_seen, ip, country, city, ua FROM sessions WHERE user_id = ? AND expires_at > ? ORDER BY last_seen DESC').bind(str(d.id, 60), now()).all();
      return json({ devices: r.results || [] });
    }

    // Registro degli accessi: filtro per account, solo problemi o solo visitatori senza account.
    case 'log': {
      const no = needMaster(); if (no) return no;
      const f = d.filter || 'all', lim = Math.min(300, Math.max(20, parseInt(d.limit, 10) || 150)), before = parseInt(d.before, 10) || 0;
      const conds = ['1 = 1'], args = [];
      if (before){ conds.push('l.id < ?'); args.push(before); }
      if (d.userId){ conds.push('l.user_id = ?'); args.push(str(d.userId, 60)); }
      if (d.ip){ conds.push('l.ip = ?'); args.push(str(d.ip, 60)); }
      if (f === 'problems') conds.push("(l.event IN ('fail','blocked','off') OR (l.event = 'kicked' AND l.info LIKE '%più di%') OR (l.event = 'visit' AND l.ip NOT IN (SELECT ip FROM access_log WHERE event = 'login')))");
      else if (f === 'visits') conds.push("l.event = 'visit' AND l.ip NOT IN (SELECT ip FROM access_log WHERE event = 'login')");
      else if (f === 'logins') conds.push("l.event IN ('login','open')");
      const r = await db.prepare('SELECT l.*, u.name AS user_name, u.username AS user_username FROM access_log l LEFT JOIN users u ON u.id = l.user_id WHERE ' + conds.join(' AND ') + ' ORDER BY l.id DESC LIMIT ?').bind(...args, lim).all();
      const t = now(), d7 = t - 7*86400000, rows = r.results || [];
      // una "visita senza account" da un IP che poi è entrato con un account è normale (era la pagina "Accedi")
      const vips = Array.from(new Set(rows.filter(x => x.event === 'visit' && x.ip).map(x => x.ip)));
      const known = new Set();
      for (let i = 0; i < vips.length; i += 50){
        const part = vips.slice(i, i + 50);
        const k = await db.prepare("SELECT DISTINCT ip FROM access_log WHERE event = 'login' AND ip IN (" + part.map(() => '?').join(',') + ')').bind(...part).all();
        (k.results || []).forEach(x => known.add(x.ip));
      }
      rows.forEach(x => { if (x.event === 'visit') x.known = known.has(x.ip) ? 1 : 0; });
      const sum = await db.prepare("SELECT SUM(event = 'login') AS logins, SUM(event = 'fail') AS fails, SUM(event IN ('export','export-spot')) AS exports FROM access_log WHERE ts > ?").bind(d7).first();
      const unk = await db.prepare("SELECT COUNT(DISTINCT ip) AS n FROM access_log WHERE ts > ? AND event = 'visit' AND ip NOT IN (SELECT ip FROM access_log WHERE event = 'login')").bind(d7).first();
      return json({ rows, summary: Object.assign(sum || {}, { visitIps: unk ? unk.n : 0 }), more: rows.length === lim });
    }
  }
  return fail('Richiesta non valida.', 'action', 400);
}

/* ---------- pagina "Accedi" (l'unica che vede chi non ha un account) ---------- */
export function loginPage(setupMissing){
  return `<!DOCTYPE html>
<html lang="it"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow"><meta name="theme-color" content="#FFFFFF">
<title>Horizon Render · Accedi</title>
<link rel="manifest" href="manifest.json"><link rel="apple-touch-icon" href="icon-192.png">
<style>
:root{--bg:#fff;--fg:#1D1D1F;--muted:#6E6E73;--fill:#F5F5F7;--field:#D2D2D7;--warn-bg:#FFF4E5;--warn-fg:#8A4B00;color-scheme:light;}
@media (prefers-color-scheme:dark){:root{--bg:#000;--fg:#F5F5F7;--muted:#A1A1A6;--fill:#1C1C1E;--field:#3A3A3C;--warn-bg:#3A2A12;--warn-fg:#FFD08A;color-scheme:dark;}}
*{box-sizing:border-box;}html,body{margin:0;background:var(--bg);color:var(--fg);font:17px/1.4 -apple-system,BlinkMacSystemFont,"SF Pro Text","Helvetica Neue",Arial,sans-serif;-webkit-font-smoothing:antialiased;}
main{max-width:420px;margin:0 auto;padding:calc(8vh + env(safe-area-inset-top)) 22px 40px;display:flex;flex-direction:column;gap:22px;}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:19px;letter-spacing:-.01em;}
.brand img{width:34px;height:34px;border-radius:9px;background:#000;padding:5px;}
h1{font-size:34px;line-height:1.1;letter-spacing:-.02em;margin:0;}
.sub{color:var(--muted);margin:8px 0 0;}
form{display:flex;flex-direction:column;gap:16px;}
label{font-weight:600;font-size:16px;display:block;margin-bottom:6px;}
.input{width:100%;min-height:54px;border:1px solid var(--field);border-radius:14px;padding:0 16px;font-size:17px;background:var(--bg);color:var(--fg);}
.input:focus{outline:2px solid var(--fg);outline-offset:1px;}
.pw{position:relative;}.pw .input{padding-right:96px;}
.pw button{position:absolute;right:8px;top:50%;transform:translateY(-50%);border:0;background:transparent;color:var(--fg);font-weight:600;font-size:15px;padding:10px 6px;}
.go{min-height:56px;border:0;border-radius:16px;background:var(--fg);color:var(--bg);font-size:17px;font-weight:600;}
.go:disabled{opacity:.5;}
.warn{background:var(--warn-bg);color:var(--warn-fg);border-radius:12px;padding:12px 14px;font-size:15px;margin:0;}
.note{color:var(--muted);font-size:14px;text-align:center;margin:0;}
</style></head><body><main>
<div class="brand"><img src="brand/mark-horizon.png" alt="">Horizon Render</div>
<div><h1>Accedi.</h1><p class="sub">Strumento riservato ai venditori del Team Horizon.</p></div>
${setupMissing ? '<p class="warn">Il sito non è ancora configurato: su Cloudflare manca la password dell\'amministratore (MASTER_PASSWORD).</p>' : ''}
<form id="f" novalidate>
<div><label for="u">Nome utente</label><input class="input" id="u" autocomplete="username" autocapitalize="off" spellcheck="false"></div>
<div><label for="p">Password</label><div class="pw"><input class="input" id="p" type="password" autocomplete="current-password" autocapitalize="off" spellcheck="false"><button type="button" id="s">Mostra</button></div></div>
<p class="warn" id="e" hidden></p>
<button class="go" id="g" type="submit">Entra</button>
</form>
<p class="note">Non hai le credenziali? Chiedile al tuo responsabile.<br>Gli accessi vengono registrati.</p>
</main><script>
(function(){
var $=function(i){return document.getElementById(i);};
$('s').onclick=function(){var i=$('p'),v=i.type==='password';i.type=v?'text':'password';this.textContent=v?'Nascondi':'Mostra';};
$('f').onsubmit=function(ev){ev.preventDefault();var u=$('u').value.trim(),p=$('p').value.trim(),e=$('e'),g=$('g');
if(!u||!p){e.textContent='Scrivi nome utente e password.';e.hidden=false;return;}
g.disabled=true;fetch('/api/acc',{method:'POST',headers:{'content-type':'application/json'},credentials:'same-origin',body:JSON.stringify({action:'login',username:u,password:p})})
.then(function(r){return r.json().catch(function(){return{};}).then(function(j){if(!r.ok||j.error)throw new Error(j.error||'Qualcosa non ha funzionato. Riprova.');location.replace('/');});})
.catch(function(x){e.textContent=x.message==='Failed to fetch'?'Connessione non riuscita. Controlla internet e riprova.':x.message;e.hidden=false;g.disabled=false;});};
})();
</script></body></html>`;
}
