/* VPS Dashboard service worker — offline shell + stale-while-revalidate.
   Caches the app shell (page, manifest, icons). API calls always go to the
   network; when offline they fail fast and the page shows its own
   "can't reach the server" banner. */
const SHELL = ['/', '/manifest.json', '/icon-192.png', '/icon-512.png'];
const CACHE = 'vpsdash-v1';

self.addEventListener('install', function (e) {
  e.waitUntil(caches.open(CACHE).then(function (c) { return c.addAll(SHELL); }));
  self.skipWaiting();
});

self.addEventListener('activate', function (e) {
  e.waitUntil(caches.keys().then(function (keys) {
    return Promise.all(keys.filter(function (k) { return k !== CACHE; })
      .map(function (k) { return caches.delete(k); }));
  }));
  self.clients.claim();
});

self.addEventListener('fetch', function (e) {
  var url = new URL(e.request.url);
  if (url.origin !== location.origin) return;
  // never intercept API calls — always fresh from the network
  if (url.pathname.startsWith('/api/')) return;

  if (e.request.mode === 'navigate') {
    // network-first for the page; fall back to the cached shell offline
    e.respondWith(
      fetch(e.request)
        .then(function (r) {
          var copy = r.clone();
          caches.open(CACHE).then(function (c) { c.put('/', copy); });
          return r;
        })
        .catch(function () {
          return caches.match('/').then(function (r) { return r || caches.match(e.request); });
        })
    );
    return;
  }
  // static assets: cache-first, update in the background
  e.respondWith(
    caches.match(e.request).then(function (hit) {
      var net = fetch(e.request).then(function (r) {
        if (r.ok) {
          var copy = r.clone();
          caches.open(CACHE).then(function (c) { c.put(e.request, copy); });
        }
        return r;
      }).catch(function () { return hit; });
      return hit || net;
    })
  );
});
