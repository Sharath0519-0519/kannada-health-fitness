// Kannada Health and Fitness: chat server
// Express + Socket.IO + Postgres (messages, users, settings) + Cloudflare R2 (files) + Google sign-in
require('dotenv').config();
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const express = require('express');
const multer = require('multer');
const { Server } = require('socket.io');
const { Pool } = require('pg');
const { OAuth2Client } = require('google-auth-library');
const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

const env = process.env;
const REQUIRED = ['DATABASE_URL', 'GOOGLE_CLIENT_ID', 'R2_ACCOUNT_ID', 'R2_ACCESS_KEY_ID', 'R2_SECRET_ACCESS_KEY', 'R2_BUCKET'];
const missing = REQUIRED.filter((k) => !env[k]);
if (missing.length) { console.error('Missing environment variables: ' + missing.join(', ')); process.exit(1); }

const db = new Pool({
  connectionString: env.DATABASE_URL,
  ssl: /localhost|127\.0\.0\.1/.test(env.DATABASE_URL) ? false : { rejectUnauthorized: false },
});
const gclient = new OAuth2Client(env.GOOGLE_CLIENT_ID);
const s3 = new S3Client({
  region: 'auto',
  endpoint: `https://${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: { accessKeyId: env.R2_ACCESS_KEY_ID, secretAccessKey: env.R2_SECRET_ACCESS_KEY },
});
const BUCKET = env.R2_BUCKET;

const SESSION_MS = 90 * 24 * 3600 * 1000;
const KEY_RE = /^u\/[0-9a-f-]{36}$/;
const KV_RE = /^(blk|stars|hid|hl|rem|c:[\w-]+)$/;
const SAFE = /^(image\/(jpeg|png|webp|gif)|video\/(mp4|webm|quicktime)|audio\/(webm|mp4|mpeg|ogg|wav|x-m4a|aac))$/;

const dm = (a, b) => 'dm:' + [a, b].sort().join('|');
const peerId = (to) => String(to || '').replace(/^user:/, '');
const pub = (u) => ({ id: u.id, name: u.name, email: u.email, picture: u.picture || undefined });
const rowToMsg = (r) => ({
  id: r.id, convo: r.convo, from: r.from_id, name: r.name, ts: Number(r.ts),
  text: r.deleted ? '' : r.text, file: r.deleted ? undefined : r.file || undefined,
  replyTo: r.reply_to || undefined, status: r.status, deleted: r.deleted || undefined,
});

/* ---------- database ---------- */
async function initDb() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT UNIQUE, name TEXT, picture TEXT, created_at BIGINT);
    CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at BIGINT NOT NULL);
    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY, convo TEXT NOT NULL, from_id TEXT NOT NULL, to_id TEXT NOT NULL, name TEXT,
      ts BIGINT NOT NULL, text TEXT NOT NULL DEFAULT '', file JSONB, reply_to JSONB,
      status TEXT NOT NULL DEFAULT 'sent', deleted BOOLEAN NOT NULL DEFAULT FALSE);
    CREATE INDEX IF NOT EXISTS messages_convo_ts ON messages (convo, ts);
    CREATE INDEX IF NOT EXISTS messages_to_status ON messages (to_id, status);
    CREATE INDEX IF NOT EXISTS messages_file_key ON messages ((file->>'key'));
    CREATE TABLE IF NOT EXISTS kv (user_id TEXT NOT NULL, k TEXT NOT NULL, v JSONB NOT NULL, PRIMARY KEY (user_id, k));
    CREATE TABLE IF NOT EXISTS files (key TEXT PRIMARY KEY, owner TEXT NOT NULL, ctype TEXT NOT NULL, created_at BIGINT NOT NULL);
  `);
}

async function userFromSession(token) {
  if (!token || typeof token !== 'string' || token.length > 100) return null;
  const { rows } = await db.query(
    'SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = $1 AND s.created_at > $2',
    [token, Date.now() - SESSION_MS]);
  return rows[0] || null;
}
async function userFromGoogle(credential) {
  const t = await gclient.verifyIdToken({ idToken: credential, audience: env.GOOGLE_CLIENT_ID });
  const p = t.getPayload();
  if (!p || !p.sub || !p.email || p.email_verified === false) return null;
  const { rows } = await db.query(
    `INSERT INTO users (id, email, name, picture, created_at) VALUES ($1,$2,$3,$4,$5)
     ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email, name = EXCLUDED.name, picture = EXCLUDED.picture
     RETURNING *`,
    [p.sub, p.email.toLowerCase(), p.name || p.email, p.picture || null, Date.now()]);
  return rows[0];
}

/* ---------- files (R2) ---------- */
// A user may use a file if they uploaded it, or it is in a message they sent or received.
async function mayUseFile(uid, key) {
  const { rows } = await db.query(
    `SELECT 1 FROM files WHERE key = $1 AND owner = $2
     UNION ALL
     SELECT 1 FROM messages WHERE file->>'key' = $1 AND (from_id = $2 OR to_id = $2) AND deleted = FALSE
     LIMIT 1`, [key, uid]);
  return rows.length > 0;
}
async function dropFileIfUnused(key) {
  const { rows } = await db.query(`SELECT 1 FROM messages WHERE file->>'key' = $1 LIMIT 1`, [key]); // forwarded copies share the key
  if (rows.length) return;
  await s3.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: key }));
  await db.query('DELETE FROM files WHERE key = $1', [key]);
}

/* ---------- http ---------- */
const app = express();
const server = http.createServer(app);
app.disable('x-powered-by');
app.use((req, res, next) => { res.set({ 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin' }); next(); });
app.get('/config.json', (req, res) => res.json({ clientId: env.GOOGLE_CLIENT_ID }));
app.get('/healthz', (req, res) => res.send('ok'));
app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 15 * 1024 * 1024 } });
async function auth(req, res, next) {
  try {
    const u = await userFromSession(req.get('x-session'));
    if (!u) return res.status(401).json({ error: 'auth' });
    req.uid = u.id; next();
  } catch (e) { res.status(500).json({ error: 'fail' }); }
}

app.post('/upload', auth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'no file' });
    const type = SAFE.test(req.file.mimetype) ? req.file.mimetype : 'application/octet-stream';
    const key = 'u/' + crypto.randomUUID();                // random key; the original filename is never used as a path
    await s3.send(new PutObjectCommand({ Bucket: BUCKET, Key: key, Body: req.file.buffer, ContentType: type }));
    await db.query('INSERT INTO files (key, owner, ctype, created_at) VALUES ($1,$2,$3,$4)', [key, req.uid, type, Date.now()]);
    res.json({ key });
  } catch (e) { console.error('upload', e.message); res.status(500).json({ error: 'fail' }); }
});

app.get('/file-url', auth, async (req, res) => {
  try {
    const key = String(req.query.key || '');
    if (!KEY_RE.test(key) || !(await mayUseFile(req.uid, key))) return res.status(403).json({ error: 'denied' });
    const f = (await db.query('SELECT ctype FROM files WHERE key = $1', [key])).rows[0];
    if (!f) return res.status(404).json({ error: 'gone' });
    const name = String(req.query.name || 'file').replace(/[^\w.\- ]/g, '_').slice(0, 100);
    const url = await getSignedUrl(s3, new GetObjectCommand({
      Bucket: BUCKET, Key: key,
      ResponseContentDisposition: `${SAFE.test(f.ctype) ? 'inline' : 'attachment'}; filename="${name}"`,
    }), { expiresIn: 3600 });                              // link works for 1 hour
    res.json({ url });
  } catch (e) { console.error('file-url', e.message); res.status(500).json({ error: 'fail' }); }
});

app.use((err, req, res, next) => res.status(err && err.code === 'LIMIT_FILE_SIZE' ? 413 : 500).json({ error: 'fail' }));

/* ---------- realtime ---------- */
const io = new Server(server, { maxHttpBufferSize: 1e6 });
const online = new Map();                                  // userId -> { user, n }
const broadcastOnline = () => io.emit('online', [...online.values()].map((o) => ({ id: o.user.id, name: o.user.name, picture: o.user.picture || undefined })));

async function recentChats(uid) {
  const last = (await db.query(
    `SELECT * FROM (SELECT DISTINCT ON (convo) * FROM messages WHERE from_id = $1 OR to_id = $1 ORDER BY convo, ts DESC) t
     ORDER BY ts DESC LIMIT 200`, [uid])).rows;
  if (!last.length) return [];
  const unread = {};
  (await db.query(`SELECT from_id, COUNT(*)::int AS n FROM messages WHERE to_id = $1 AND status <> 'read' AND deleted = FALSE GROUP BY from_id`, [uid]))
    .rows.forEach((r) => (unread[r.from_id] = r.n));
  const peers = last.map((r) => (r.from_id === uid ? r.to_id : r.from_id));
  const users = {};
  (await db.query('SELECT * FROM users WHERE id = ANY($1::text[])', [peers])).rows.forEach((u) => (users[u.id] = u));
  return last.map((r, i) => users[peers[i]] && { user: pub(users[peers[i]]), last: rowToMsg(r), unread: unread[peers[i]] || 0 }).filter(Boolean);
}

io.on('connection', (socket) => {
  let uid = null, name = '', sendTimes = [];
  const on = (ev, fn) => socket.on(ev, async (...a) => {
    try { await fn(...a); } catch (e) {
      console.error(ev, e.message);
      const ack = a[a.length - 1];
      if (typeof ack === 'function') { try { ack(ev === 'history' ? [] : { error: 'server' }); } catch (_) {} }
    }
  });

  on('join', async (auth, ack) => {
    if (typeof ack !== 'function') return;
    let user = null, session = null;
    if (auth && auth.credential) {
      user = await userFromGoogle(auth.credential);
      if (user) {
        session = crypto.randomBytes(32).toString('hex');
        await db.query('INSERT INTO sessions (token, user_id, created_at) VALUES ($1,$2,$3)', [session, user.id, Date.now()]);
      }
    } else if (auth && auth.session) { user = await userFromSession(auth.session); session = auth.session; }
    if (!user) return ack({ error: 'auth' });

    uid = user.id; name = user.name || user.email;
    if (!socket.data.joined) {
      socket.data.joined = true; socket.join('u:' + uid);
      const o = online.get(uid) || { user, n: 0 }; o.user = user; o.n++; online.set(uid, o);
    }
    const kv = {};
    (await db.query('SELECT k, v FROM kv WHERE user_id = $1', [uid])).rows.forEach((r) => (kv[r.k] = r.v));
    const recent = await recentChats(uid);
    // messages that arrived while offline are now delivered: tell the senders (single ticks -> double ticks)
    const upd = await db.query(`UPDATE messages SET status = 'delivered' WHERE to_id = $1 AND status = 'sent' RETURNING convo, from_id`, [uid]);
    new Set(upd.rows.map((r) => r.convo + '\u0000' + r.from_id)).forEach((x) => {
      const [convo, from] = x.split('\u0000'); io.to('u:' + from).emit('status', { convo, status: 'delivered' });
    });
    ack({ id: uid, session, user: pub(user), name, kv, recent });
    broadcastOnline();
  });

  on('send', async (p, ack) => {
    if (!uid || !p || typeof p !== 'object') return;
    const now = Date.now(); sendTimes = sendTimes.filter((t) => now - t < 10000);
    if (sendTimes.length >= 20) return; sendTimes.push(now);                      // simple flood limit
    const peer = peerId(p.to);
    if (!peer || peer === uid) return;
    if (!(await db.query('SELECT 1 FROM users WHERE id = $1', [peer])).rows.length) return;

    const id = String(p.id || '').slice(0, 64) || crypto.randomUUID();
    const text = String(p.text || '').slice(0, 5000);
    let file = null;
    if (p.file && typeof p.file === 'object') {
      const key = String(p.file.key || '');
      if (!KEY_RE.test(key) || !(await mayUseFile(uid, key))) return;
      file = { name: String(p.file.name || 'file').slice(0, 150), type: String(p.file.type || 'application/octet-stream').slice(0, 100), size: Math.max(0, +p.file.size || 0), key };
    }
    if (!text && !file) return;
    let reply = null;
    if (p.replyTo && typeof p.replyTo === 'object') {
      reply = { id: String(p.replyTo.id || '').slice(0, 64), name: String(p.replyTo.name || '').slice(0, 100), text: String(p.replyTo.text || '').slice(0, 200) };
    }
    const convo = dm(uid, peer);
    const ins = await db.query(
      `INSERT INTO messages (id, convo, from_id, to_id, name, ts, text, file, reply_to, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'sent') ON CONFLICT (id) DO NOTHING RETURNING *`,
      [id, convo, uid, peer, name, Date.now(), text, file, reply]);
    if (!ins.rows.length) return;                                                  // duplicate resend from the offline queue
    io.to('u:' + uid).to('u:' + peer).emit('message', rowToMsg(ins.rows[0]));
    if (online.has(peer)) {
      await db.query(`UPDATE messages SET status = 'delivered' WHERE id = $1 AND status = 'sent'`, [id]);
      io.to('u:' + uid).emit('status', { convo, status: 'delivered' });
    }
    if (typeof ack === 'function') ack({ ok: true });
  });

  on('history', async (p, ack) => {
    if (typeof ack !== 'function') return;
    if (!uid) return ack([]);
    const before = Number(p && p.before) || null;
    const { rows } = await db.query(
      `SELECT * FROM messages WHERE convo = $1 AND ($2::bigint IS NULL OR ts < $2::bigint) ORDER BY ts DESC LIMIT 50`,
      [dm(uid, peerId(p && p.to)), before]);
    ack(rows.reverse().map(rowToMsg));
  });

  on('read', async (p) => {
    if (!uid) return;
    const peer = peerId(p && p.to), convo = dm(uid, peer);
    const r = await db.query(`UPDATE messages SET status = 'read' WHERE convo = $1 AND to_id = $2 AND status <> 'read'`, [convo, uid]);
    if (r.rowCount) io.to('u:' + peer).emit('status', { convo, status: 'read' });
  });

  on('delete', async (p) => {                                                      // "delete for everyone" (sender only)
    if (!uid || !p) return;
    const peer = peerId(p.to), convo = dm(uid, peer), id = String(p.id || '');
    const sel = (await db.query('SELECT file FROM messages WHERE id = $1 AND convo = $2 AND from_id = $3 AND deleted = FALSE', [id, convo, uid])).rows[0];
    if (!sel) return;
    await db.query(`UPDATE messages SET deleted = TRUE, text = '', file = NULL WHERE id = $1`, [id]);
    io.to('u:' + uid).to('u:' + peer).emit('deleted', { convo, id });
    if (sel.file && sel.file.key) await dropFileIfUnused(sel.file.key);
  });

  on('typing', (p) => { if (uid && p) io.to('u:' + peerId(p.to)).emit('typing', { from: uid }); });

  on('find', async (p, ack) => {
    if (typeof ack !== 'function') return;
    if (!uid) return ack({});
    const email = String((p && p.email) || '').trim().toLowerCase();
    const u = (await db.query('SELECT * FROM users WHERE email = $1', [email])).rows[0];
    ack(u ? { user: pub(u) } : {});
  });

  on('kv', async (p) => {                                                          // per-user settings saved in the cloud
    if (!uid || !p) return;
    const k = String(p.k || ''), s = JSON.stringify(p.v);
    if (!KV_RE.test(k) || s === undefined || s.length > 200000) return;
    await db.query('INSERT INTO kv (user_id, k, v) VALUES ($1,$2,$3::jsonb) ON CONFLICT (user_id, k) DO UPDATE SET v = EXCLUDED.v', [uid, k, s]);
  });

  on('call', (p) => {                                                              // WebRTC signalling relay
    if (!uid || !p || !p.data || JSON.stringify(p.data).length > 20000) return;
    const to = peerId(p.to);
    if (!online.has(to)) return socket.emit('call', { from: to, data: { type: 'end' } });
    io.to('u:' + to).emit('call', { from: uid, data: p.data });
  });

  socket.on('disconnect', () => {
    if (!socket.data.joined) return;
    const o = online.get(uid);
    if (o && --o.n <= 0) online.delete(uid);
    broadcastOnline();
  });
});

process.on('unhandledRejection', (e) => console.error('unhandled', e && e.message));
initDb().then(() => server.listen(env.PORT || 3000, () => console.log('Chat server running on port ' + (env.PORT || 3000))))
  .catch((e) => { console.error('Database setup failed:', e.message); process.exit(1); });
