self.addEventListener('install', e => { self.skipWaiting(); });
self.addEventListener('activate', e => { e.waitUntil(clients.claim()); });

self.addEventListener('push', e => {
  let data = { title: '🎟️ RifOs', body: 'Nueva actividad en tu rifa' };
  try { if (e.data) data = e.data.json(); } catch(_) {}
  e.waitUntil(self.registration.showNotification(data.title, {
    body: data.body, icon: '/static/icon.png',
    vibrate: [200, 100, 200], requireInteraction: true,
    data: { url: '/dashboard' },
    actions: [{ action: 'open', title: '📋 Ver panel' }, { action: 'dismiss', title: '✕ Cerrar' }],
    tag: 'rifos-reserva', renotify: true,
  }));
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  if (e.action === 'dismiss') return;
  e.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      for (const c of list) { if ('focus' in c) return c.focus(); }
      if (clients.openWindow) return clients.openWindow('/dashboard');
    })
  );
});
