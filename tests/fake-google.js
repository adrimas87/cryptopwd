// Finto Google Identity Services + Drive API, per i test end-to-end.
// Lo "storage" del Drive vive nella pagina padre così sopravvive al ricaricamento dell'app.
(function () {
  const P = window.parent;
  P.fakeDrive = P.fakeDrive || { files: {}, seq: 0, failNetwork: false, calls: [] };
  const FD = P.fakeDrive;

  window.google = {
    accounts: {
      oauth2: {
        initTokenClient(cfg) {
          return {
            requestAccessToken() {
              setTimeout(() => cfg.callback({ access_token: 'fake-token', expires_in: 3600, scope: cfg.scope }), 10);
            },
          };
        },
        hasGrantedAllScopes: () => true,
        revoke: (_t, cb) => cb && cb(),
      },
    },
  };

  const realFetch = window.fetch.bind(window);
  const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'Content-Type': 'application/json' } });

  window.fetch = async (input, opts = {}) => {
    const url = new URL(typeof input === 'string' ? input : input.url);
    if (url.hostname !== 'www.googleapis.com') return realFetch(input, opts);
    const method = (opts.method || 'GET').toUpperCase();
    FD.calls.push(`${method} ${url.pathname}`);
    if (FD.failNetwork) throw new TypeError('Failed to fetch');
    if (opts.headers?.Authorization !== 'Bearer fake-token') return json({ error: 'unauth' }, 401);

    let m;
    if (method === 'GET' && url.pathname === '/drive/v3/files') {
      const name = /name='([^']+)'/.exec(url.searchParams.get('q'))[1];
      const files = Object.values(FD.files).filter((f) => f.name === name && !f.trashed).map((f) => ({ id: f.id, modifiedTime: f.modifiedTime }));
      return json({ files });
    }
    if (method === 'GET' && (m = /^\/drive\/v3\/files\/([^/]+)$/.exec(url.pathname))) {
      const f = FD.files[m[1]];
      if (!f) return json({ error: 'not found' }, 404);
      if (url.searchParams.get('alt') === 'media') return new Response(f.content, { status: 200 });
      return json({ id: f.id, modifiedTime: f.modifiedTime, trashed: !!f.trashed });
    }
    if (method === 'PATCH' && (m = /^\/upload\/drive\/v3\/files\/([^/]+)$/.exec(url.pathname))) {
      const f = FD.files[m[1]];
      if (!f) return json({ error: 'not found' }, 404);
      f.content = opts.body;
      f.modifiedTime = new Date().toISOString();
      return json({ id: f.id, modifiedTime: f.modifiedTime });
    }
    if (method === 'POST' && url.pathname === '/upload/drive/v3/files') {
      const boundary = /boundary=(.+)$/.exec(opts.headers['Content-Type'])[1];
      const parts = opts.body.split(`--${boundary}`).slice(1, -1).map((p) => p.split('\r\n\r\n').slice(1).join('\r\n\r\n').replace(/\r\n$/, ''));
      const meta = JSON.parse(parts[0]);
      const id = 'file' + ++FD.seq;
      FD.files[id] = { id, name: meta.name, content: parts[1], modifiedTime: new Date().toISOString() };
      return json({ id, modifiedTime: FD.files[id].modifiedTime });
    }
    return json({ error: `fake: ${method} ${url.pathname} non gestito` }, 400);
  };
})();
