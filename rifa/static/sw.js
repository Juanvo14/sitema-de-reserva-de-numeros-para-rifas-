// NeoRifa Service Worker — Push Notification Handler
const CACHE = 'neorifa-v1';

self.addEventListener('install', e => {
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(clients.claim());
});

// ── Push event: show notification ──────────────────────────────────────────
self.addEventListener('push', e => {
  let data = { title: '🎟️ NeoRifa', body: 'Nueva actividad en la rifa' };
  try {
    if (e.data) data = e.data.json();
  } catch(_) {
    if (e.data) data.body = e.data.text();
  }

  const options = {
    body:      data.body,
    icon:      '/static/icon.png',
    badge:     '/static/icon.png',
    vibrate:   [200, 100, 200],
    timestamp: data.timestamp || Date.now(),
    requireInteraction: true,
    data:      { url: '/admin' },
    actions: [
      { action: 'open',    title: '📋 Ver panel' },
      { action: 'dismiss', title: '✕ Cerrar' }
    ],
    tag:   'neorifa-reserva',
    renotify: true,
  };

  e.waitUntil(
    self.registration.showNotification(data.title, options)
  );
});

// ── Notification click: open admin panel ───────────────────────────────────
self.addEventListener('notificationclick', e => {
  e.notification.close();
  if (e.action === 'dismiss') return;

  const target = e.notification.data?.url || '/admin';

  e.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      for (const client of list) {
        if (client.url.includes('/admin') && 'focus' in client) {
          return client.focus();
        }
      }
      if (clients.openWindow) return clients.openWindow(target);
    })
  );
});
