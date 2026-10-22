// Minimal service worker. It exists so browsers offer "Install app".
// It deliberately caches nothing: a chat app must always load fresh code.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', () => {});
