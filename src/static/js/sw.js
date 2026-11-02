const V = 'selfcloud-v1';
const SHELL = ['/', '/manifest.webmanifest', '/icons/icon-192.png', '/icons/icon-512.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(V).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== V).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const r = e.request, u = new URL(r.url);
  // API i pobieranie plików zawsze idą do sieci (nigdy z cache)
  if (r.method !== 'GET' || u.origin !== location.origin || u.pathname.startsWith('/api/')) return;

  // Strona: najpierw sieć, w razie braku połączenia – wersja z cache
  if (r.mode === 'navigate') {
    e.respondWith(
      fetch(r)
        .then(res => { const cp = res.clone(); caches.open(V).then(c => c.put('/', cp)); return res; })
        .catch(() => caches.match('/'))
    );
    return;
  }

  // Statyczne zasoby: cache, potem sieć
  e.respondWith(
    caches.match(r).then(hit => hit || fetch(r).then(res => {
      if (res.ok) { const cp = res.clone(); caches.open(V).then(c => c.put(r, cp)); }
      return res;
    }))
  );
});