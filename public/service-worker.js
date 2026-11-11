// Horizon Render — service worker (v11)
// Salva solo le pagine del sito, e solo dopo l'accesso. Non tocca le richieste al server (/api/).
// La pagina "Accedi" (riconoscibile dall'intestazione X-Horizon-Gate) non viene mai salvata.
const CACHE = 'horizon-render-v11';
const ASSETS = ['./manifest.json', './icon-192.png', './icon-512.png', './brand/mark-horizon.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)).catch(() => {}));
  self.skipWaiting();
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))));
  self.clients.claim();
});
self.addEventListener('message', e => { if (e.data === 'logout') e.waitUntil(caches.delete(CACHE)); });
self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;
  const url = new URL(e.request.url);
  if (url.origin !== self.location.origin) return;
  if (/^\/api\//.test(url.pathname)) return;
  e.respondWith(
    fetch(e.request)
      .then(resp => {
        const gate = resp.headers.get('X-Horizon-Gate');
        if (gate) caches.delete(CACHE).catch(() => {});   // sessione scaduta o uscito: via le copie salvate
        else if (resp.ok && resp.type === 'basic'){ const copy = resp.clone(); caches.open(CACHE).then(c => c.put(e.request, copy)).catch(() => {}); }
        return resp;
      })
      .catch(() => caches.match(e.request))
  );
});
