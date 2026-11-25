const CACHE = "rock-notes-v16";
const SHELL = ["/", "/index.html", "/manifest.webmanifest", "/icon-192.png", "/icon-512.png", "/icon-180.png"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim()),
  );
});
self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== "GET" || url.pathname.startsWith("/api/") || url.origin !== location.origin) return;
  // Network first so updates show up; fall back to cache when offline.
  e.respondWith(
    fetch(e.request)
      .then((res) => {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(e.request, copy));
        return res;
      })
      .catch(() => caches.match(e.request).then((r) => r || caches.match("/index.html"))),
  );
});

// Join alerts: the server sends an empty push; we look up who joined.
self.addEventListener("push", (e) => {
  e.waitUntil((async () => {
    let title = "Someone new joined Scout Notes";
    let body = "Tap to see who.";
    try {
      const c = await caches.open("rock-auth");
      const r = await c.match("/__auth");
      const tok = r ? await r.text() : "";
      if (tok) {
        const me = await fetch("/api/me", { headers: { authorization: "Bearer " + tok } }).then((x) => x.json());
        const j = (me.joins || [])[0];
        if (j) { title = `${j.name} joined Scout Notes`; body = "Tap to see your accounts."; }
      }
    } catch (err) {}
    await self.registration.showNotification(title, { body, icon: "/icon-192.png", badge: "/icon-192.png", tag: "join", renotify: true });
  })());
});
self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  e.waitUntil((async () => {
    const all = await clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const c of all) { if ("focus" in c) { await c.navigate("/#accounts").catch(() => {}); return c.focus(); } }
    return clients.openWindow("/#accounts");
  })());
});
