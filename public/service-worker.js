// Horizon Render — service worker (v1)
// Salva solo le pagine del sito. Non tocca le ricerche online (/api/).
const CACHE = 'horizon-render-v1';
const ASSETS = ['./', './index.html', './manifest.json', './icon-192.png', './icon-512.png', './brand/logo-render.png', './brand/mark-horizon.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)).catch(() => {}));
  self.skipWaiting();
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))));
  self.clients.claim();
});
self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;
  const url = new URL(e.request.url);
  if (url.origin !== self.location.origin) return;
  if (/^\/api\//.test(url.pathname)) return;
  e.respondWith(
    fetch(e.request)
      .then(resp => {
        if (resp.ok && resp.type === 'basic'){ const copy = resp.clone(); caches.open(CACHE).then(c => c.put(e.request, copy)).catch(() => {}); }
        return resp;
      })
      .catch(() => caches.match(e.request))
  );
});
