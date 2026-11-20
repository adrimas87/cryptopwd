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
      const q = url.searchParams.get('q');
      const eq = /name='([^']+)'/.exec(q);
      const contains = /name contains '([^']+)'/.exec(q);
      const files = Object.values(FD.files)
        .filter((f) => !f.trashed && (eq ? f.name === eq[1] : f.name.includes(contains[1])))
        .map((f) => ({ id: f.id, name: f.name, modifiedTime: f.modifiedTime }));
      return json({ files });
    }
    if (method === 'POST' && url.pathname === '/drive/v3/files') {
      const meta = JSON.parse(opts.body);
      const id = 'file' + ++FD.seq;
      FD.files[id] = { id, name: meta.name, content: new Uint8Array(0), modifiedTime: new Date().toISOString() };
      return json({ id });
    }
    if (method === 'DELETE' && (m = /^\/drive\/v3\/files\/([^/]+)$/.exec(url.pathname))) {
      delete FD.files[m[1]];
      return new Response(null, { status: 204 });
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
