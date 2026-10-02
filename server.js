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
const QRCode = require('qrcode');
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
  endpoint: env.R2_ENDPOINT || `https://${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,   // R2_ENDPOINT only needed for EU/FedRAMP buckets
  credentials: { accessKeyId: env.R2_ACCESS_KEY_ID, secretAccessKey: env.R2_SECRET_ACCESS_KEY },
  // Newer AWS SDK versions add checksum headers by default; Cloudflare R2 rejects them, which makes every upload fail.
  requestChecksumCalculation: 'WHEN_REQUIRED',
  responseChecksumValidation: 'WHEN_REQUIRED',
});
const BUCKET = env.R2_BUCKET;

const SESSION_MS = 90 * 24 * 3600 * 1000;
const KEY_RE = /^u\/[0-9a-f-]{36}$/;
const KV_RE = /^(blk|stars|hid|hl|rem|pin|mute|c:[\w-]+)$/;
const SAFE = /^(image\/(jpeg|png|webp|gif)|video\/(mp4|webm|quicktime)|audio\/(webm|mp4|mpeg|ogg|wav|x-m4a|aac))$/;

const dm = (a, b) => /^g:/.test(b) ? 'grp:' + b.slice(2) : 'dm:' + [a, b].sort().join('|');
const isG = (x) => /^g:/.test(x || '');
const peerId = (to) => String(to || '').replace(/^user:/, '');
const pub = (u) => ({ id: u.id, name: u.name, email: u.email, picture: u.picture || undefined, about: u.about || undefined });
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
    ALTER TABLE sessions ADD COLUMN IF NOT EXISTS device TEXT;
    ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_seen BIGINT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS about TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS custom BOOLEAN NOT NULL DEFAULT FALSE;
    CREATE TABLE IF NOT EXISTS statuses (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, ts BIGINT NOT NULL, exp BIGINT NOT NULL, text TEXT NOT NULL DEFAULT '', file JSONB);
    CREATE INDEX IF NOT EXISTS statuses_exp ON statuses (exp);
    CREATE INDEX IF NOT EXISTS statuses_user ON statuses (user_id, ts);
    CREATE TABLE IF NOT EXISTS chat_groups (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_by TEXT NOT NULL, created_at BIGINT NOT NULL);
    CREATE TABLE IF NOT EXISTS group_members (gid TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'member', joined_at BIGINT NOT NULL, PRIMARY KEY (gid, user_id));
    CREATE INDEX IF NOT EXISTS group_members_user ON group_members (user_id);
    ALTER TABLE group_members ADD COLUMN IF NOT EXISTS last_delivered BIGINT NOT NULL DEFAULT (extract(epoch from now()) * 1000)::bigint;
    ALTER TABLE chat_groups ADD COLUMN IF NOT EXISTS picture TEXT;
    CREATE TABLE IF NOT EXISTS status_views (sid TEXT NOT NULL, viewer TEXT NOT NULL, ts BIGINT NOT NULL, PRIMARY KEY (sid, viewer));
    CREATE TABLE IF NOT EXISTS challenges (id TEXT PRIMARY KEY, gid TEXT NOT NULL, title TEXT NOT NULL, metric TEXT NOT NULL, goal INT NOT NULL, d_start TEXT NOT NULL, d_end TEXT NOT NULL, created_by TEXT NOT NULL, created_at BIGINT NOT NULL);
    CREATE INDEX IF NOT EXISTS challenges_gid ON challenges (gid);
    CREATE TABLE IF NOT EXISTS challenge_members (cid TEXT NOT NULL, user_id TEXT NOT NULL, PRIMARY KEY (cid, user_id));
    ALTER TABLE group_members ADD COLUMN IF NOT EXISTS last_read BIGINT NOT NULL DEFAULT (extract(epoch from now()) * 1000)::bigint;
  `);
  await db.query('DELETE FROM sessions WHERE created_at < $1', [Date.now() - SESSION_MS]);
}

// Every sign-in (Google or QR) is one row in "sessions": there is no limit on how many devices a user can have.
async function newSession(userId, device) {
  const token = crypto.randomBytes(32).toString('hex');
  await db.query('INSERT INTO sessions (token, user_id, created_at, last_seen, device) VALUES ($1,$2,$3,$3,$4)', [token, userId, Date.now(), device]);
  return token;
}
const deviceName = (ua = '') => {
  const os = /Windows/i.test(ua) ? 'Windows' : /Android/i.test(ua) ? 'Android' : /iPhone|iPad|iPod/i.test(ua) ? 'iOS' : /Mac OS X|Macintosh/i.test(ua) ? 'macOS' : /CrOS/i.test(ua) ? 'ChromeOS' : /Linux/i.test(ua) ? 'Linux' : '';
  const br = /Edg(?:e|A|iOS)?\//i.test(ua) ? 'Edge' : /OPR\/|Opera/i.test(ua) ? 'Opera' : /Firefox\/|FxiOS/i.test(ua) ? 'Firefox' : /Chrome\/|CriOS/i.test(ua) ? 'Chrome' : /Safari\//i.test(ua) ? 'Safari' : 'Browser';
  return os ? br + ' on ' + os : br;
};
const QR_TTL = 120 * 1000;
const qrCodes = new Map();                                 // pairing code -> { sid: waiting socket id, device, exp }
setInterval(() => { const n = Date.now(); for (const [c, v] of qrCodes) if (v.exp < n) qrCodes.delete(c); }, 30000).unref();
setInterval(() => db.query('DELETE FROM sessions WHERE created_at < $1', [Date.now() - SESSION_MS]).catch(() => {}), 6 * 3600 * 1000).unref();

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
     ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email,
       name = CASE WHEN users.custom THEN users.name ELSE EXCLUDED.name END,
       picture = CASE WHEN users.custom THEN users.picture ELSE EXCLUDED.picture END
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
     UNION ALL
     SELECT 1 FROM messages WHERE file->>'key' = $1 AND deleted = FALSE AND to_id IN (SELECT 'g:' || gid FROM group_members WHERE user_id = $2)
     UNION ALL
     SELECT 1 FROM statuses WHERE file->>'key' = $1 AND exp > $3 AND (user_id = $2 OR user_id IN
       (SELECT CASE WHEN from_id = $2 THEN to_id ELSE from_id END FROM messages WHERE from_id = $2 OR to_id = $2)
       OR user_id IN (SELECT user_id FROM group_members WHERE gid IN (SELECT gid FROM group_members WHERE user_id = $2))))
     LIMIT 1`, [key, uid, Date.now()]);
  return rows.length > 0;
}
async function dropFileIfUnused(key) {
  const { rows } = await db.query(`SELECT 1 FROM messages WHERE file->>'key' = $1 LIMIT 1`, [key]); // forwarded copies share the key
  if (rows.length) return;
  if ((await db.query(`SELECT 1 FROM statuses WHERE file->>'key' = $1 LIMIT 1`, [key])).rows.length) return;
  await s3.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: key }));
  await db.query('DELETE FROM files WHERE key = $1', [key]);
}

/* ---------- http ---------- */
const app = express();
const server = http.createServer(app);
app.disable('x-powered-by');
app.use((req, res, next) => { res.set({
  'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin', 'X-Frame-Options': 'SAMEORIGIN', 'Strict-Transport-Security': 'max-age=15552000',
  'Permissions-Policy': 'camera=(self), microphone=(self), geolocation=(self)',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://accounts.google.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://accounts.google.com; font-src https://fonts.gstatic.com; img-src 'self' data: blob: https:; media-src 'self' blob: https:; connect-src 'self' ws: wss: https://accounts.google.com; frame-src https://accounts.google.com; object-src 'none'; base-uri 'none'; frame-ancestors 'self'" }); next(); });
app.get('/config.json', (req, res) => res.json({ clientId: env.GOOGLE_CLIENT_ID }));
app.get('/healthz', (req, res) => res.send('ok'));
app.get('/sw.js', (req, res) => res.set('Cache-Control', 'no-cache').type('js').sendFile(path.join(__dirname, 'public', 'sw.js')));   // service worker: must never be cached for long
app.get('/avatar-url', auth, async (req, res) => {          // profile / group photos: only signed-in users get a (15 minute) link
  try {
    const k = String(req.query.k || '');
    if (!/^[0-9a-f-]{36}$/.test(k) || !(await db.query(`SELECT 1 FROM users WHERE picture = $1 UNION ALL SELECT 1 FROM chat_groups WHERE picture = $1 LIMIT 1`, ['/avatar/' + k])).rows.length) return res.status(404).json({ error: 'no' });
    res.json({ url: await getSignedUrl(s3, new GetObjectCommand({ Bucket: BUCKET, Key: 'u/' + k }), { expiresIn: 900 }) });
  } catch (e) { res.status(500).json({ error: 'fail' }); }
});
app.get('/vendor/jsqr.js', (req, res) => res.sendFile(require.resolve('jsqr'), { maxAge: '30d' }));
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
  } catch (e) {
    console.error('upload failed:', e.name, e.message);
    res.status(500).json({ error: 'storage', code: String(e.Code || e.name || 'fail').slice(0, 40) });
  }
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

app.use((err, req, res, next) => { console.error('http error:', err && (err.code || err.name), err && err.message); res.status(err && err.code === 'LIMIT_FILE_SIZE' ? 413 : 500).json({ error: 'fail', code: String((err && (err.code || err.name)) || 'fail').slice(0, 40) }); });

/* ---------- realtime ---------- */
const io = new Server(server, { maxHttpBufferSize: 1e6 });
const peersOf = async (uid) => (await db.query(`SELECT DISTINCT p FROM (
    SELECT CASE WHEN from_id = $1 THEN to_id ELSE from_id END AS p FROM messages WHERE (from_id = $1 OR to_id = $1) AND convo LIKE 'dm:%'
    UNION SELECT user_id FROM group_members WHERE gid IN (SELECT gid FROM group_members WHERE user_id = $1) AND user_id <> $1) t`, [uid])).rows.map((r) => r.p);
const delAvatar = async (pic) => {
  const m = /^\/avatar\/([0-9a-f-]{36})$/.exec(pic || ''); if (!m) return;
  const key = 'u/' + m[1];
  await s3.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: key })).catch(() => {});
  await db.query('DELETE FROM files WHERE key = $1', [key]);
};
const sweepStatuses = async () => {                        // expired statuses disappear, along with their files
  const { rows } = await db.query('DELETE FROM statuses WHERE exp < $1 RETURNING file', [Date.now()]);
  await db.query('DELETE FROM status_views WHERE sid NOT IN (SELECT id FROM statuses)');
  for (const r of rows) if (r.file && r.file.key) await dropFileIfUnused(r.file.key).catch(() => {});
};
setInterval(() => sweepStatuses().catch(() => {}), 10 * 60 * 1000).unref();
const memberIds = async (g) => (await db.query('SELECT user_id FROM group_members WHERE gid = $1', [String(g).replace(/^g:/, '')])).rows.map((r) => r.user_id);
const isAdmin = async (gid, u) => (await db.query(`SELECT 1 FROM group_members WHERE gid = $1 AND user_id = $2 AND role = 'admin'`, [gid, u])).rows.length > 0;
async function groupObj(gid) {
  const g = (await db.query('SELECT * FROM chat_groups WHERE id = $1', [gid])).rows[0]; if (!g) return null;
  const m = (await db.query('SELECT u.id, u.name, u.email, u.picture, gm.role, gm.last_delivered AS d, gm.last_read AS r FROM group_members gm JOIN users u ON u.id = gm.user_id WHERE gm.gid = $1 ORDER BY gm.joined_at', [gid])).rows;
  return { id: 'g:' + gid, name: g.name, created_by: g.created_by, picture: g.picture || undefined, members: m.map((x) => ({ id: x.id, name: x.name || x.email, email: x.email, picture: x.picture || undefined, role: x.role, d: Number(x.d), r: Number(x.r) })) };
}
const pushMarks = async (gid) => {                          // delivered / read markers for the ticks on group messages
  const m = (await db.query('SELECT user_id, last_delivered, last_read FROM group_members WHERE gid = $1', [gid])).rows;
  const msg = { id: 'g:' + gid, marks: m.map((x) => ({ id: x.user_id, d: Number(x.last_delivered), r: Number(x.last_read) })) };
  m.forEach((x) => io.to('u:' + x.user_id).emit('gmarks', msg));
};
const pushGroup = async (gid) => { const G = await groupObj(gid); if (G) G.members.forEach((m) => io.to('u:' + m.id).emit('group', G)); };
const sweepFiles = async () => {                           // uploads never attached to a message, status or profile are removed after 24 h
  const { rows } = await db.query(`SELECT key FROM files f WHERE created_at < $1
    AND NOT EXISTS (SELECT 1 FROM messages WHERE file->>'key' = f.key) AND NOT EXISTS (SELECT 1 FROM statuses WHERE file->>'key' = f.key)
    AND NOT EXISTS (SELECT 1 FROM users WHERE picture = '/avatar/' || substr(f.key, 3)) AND NOT EXISTS (SELECT 1 FROM chat_groups WHERE picture = '/avatar/' || substr(f.key, 3)) LIMIT 200`, [Date.now() - 24 * 3600 * 1000]);
  for (const r of rows) { await s3.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: r.key })).catch(() => {}); await db.query('DELETE FROM files WHERE key = $1', [r.key]); }
};
setInterval(() => sweepFiles().catch(() => {}), 3600 * 1000).unref();
setTimeout(() => sweepFiles().catch(() => {}), 60 * 1000).unref();
const notice = async (gid, k, a, b) => {                     // "Ravi added Sita": stored as a system message, shown in each user's language
  const r = (await db.query(`INSERT INTO messages (id, convo, from_id, to_id, name, ts, text, status) VALUES ($1,$2,'system',$3,'',$4,$5,'read') RETURNING *`,
    [crypto.randomUUID(), 'grp:' + gid, 'g:' + gid, Date.now(), JSON.stringify({ k, a, b })])).rows[0];
  (await memberIds(gid)).forEach((m) => io.to('u:' + m).emit('message', rowToMsg(r)));
};
const addDays = (d, n) => { const x = new Date(d + 'T00:00:00Z'); x.setUTCDate(x.getUTCDate() + n); return x.toISOString().slice(0, 10); };
async function board(c) {                                  // leaderboard from the health numbers (kv "hl") of members who joined this challenge
  const mem = (await db.query('SELECT user_id FROM challenge_members WHERE cid = $1', [c.id])).rows.map((r) => r.user_id);
  if (!mem.length) return [];
  const kv = {}, us = {}, key = c.metric === 'water' ? 'w' : 's', n = Math.round((Date.parse(c.d_end) - Date.parse(c.d_start)) / 864e5) + 1;
  (await db.query(`SELECT user_id, v FROM kv WHERE k = 'hl' AND user_id = ANY($1::text[])`, [mem])).rows.forEach((r) => (kv[r.user_id] = r.v || {}));
  (await db.query('SELECT id, name, email, picture FROM users WHERE id = ANY($1::text[])', [mem])).rows.forEach((u) => (us[u.id] = u));
  const days = Array.from({ length: n }, (_, i) => addDays(c.d_start, i));
  return mem.map((id) => {
    let total = 0, hit = 0; days.forEach((d) => { const x = +((kv[id] || {})[d] || {})[key] || 0; total += x; if (x >= c.goal) hit++; });
    const u = us[id] || {}; return { id, name: u.name || u.email || '', picture: u.picture || undefined, total, days: hit };
  }).sort((a, b) => b.total - a.total);
}
const online = new Map();                                  // userId -> { user, n }
const broadcastOnline = () => io.emit('online', [...online.values()].map((o) => ({ id: o.user.id, name: o.user.name, picture: o.user.picture || undefined })));

async function recentChats(uid) {
  const last = (await db.query(
    `SELECT * FROM (SELECT DISTINCT ON (convo) * FROM messages WHERE (from_id = $1 OR to_id = $1) AND convo LIKE 'dm:%' ORDER BY convo, ts DESC) t
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
  let uid = null, name = '', sendTimes = [], curSession = null, qrCode = null, qrTimes = [];
  const hits = {}, limited = (k, max, ms) => { const n = Date.now(); hits[k] = (hits[k] || []).filter((x) => n - x < ms); if (hits[k].length >= max) return true; hits[k].push(n); return false; };
  const ua = () => String(socket.handshake.headers['user-agent'] || '');
  const dropQr = () => { if (qrCode) qrCodes.delete(qrCode); qrCode = null; };
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
        session = await newSession(user.id, deviceName(ua()));
      }
    } else if (auth && auth.session) {
      user = await userFromSession(auth.session); session = auth.session;
      if (user) await db.query('UPDATE sessions SET last_seen = $2, device = COALESCE(device, $3) WHERE token = $1', [session, Date.now(), deviceName(ua())]);
    }
    if (!user) return ack({ error: 'auth' });
    curSession = session; socket.data.session = session; dropQr();

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
    const gl = (await db.query('UPDATE group_members SET last_delivered = $2 WHERE user_id = $1 RETURNING gid', [uid, Date.now()])).rows.map((r) => r.gid), groups = [];
    gl.forEach((g) => pushMarks(g).catch(() => {}));
    if (gl.length) {
      const lastm = {}, unr = {};
      (await db.query(`SELECT m.convo, COUNT(*)::int AS n FROM messages m JOIN group_members gm ON m.convo = 'grp:' || gm.gid AND gm.user_id = $1
        WHERE m.ts > gm.last_read AND m.from_id NOT IN ($1, 'system') AND m.deleted = FALSE GROUP BY m.convo`, [uid])).rows.forEach((r) => (unr[r.convo] = r.n));
      (await db.query('SELECT DISTINCT ON (convo) * FROM messages WHERE convo = ANY($1::text[]) ORDER BY convo, ts DESC', [gl.map((x) => 'grp:' + x)])).rows.forEach((r) => (lastm[r.convo] = rowToMsg(r)));
      for (const g of gl) { const G = await groupObj(g); if (G) groups.push(Object.assign(G, { last: lastm['grp:' + g], unread: unr['grp:' + g] || 0 })); }
    }
    ack({ id: uid, session, user: pub(user), name, kv, recent, groups });
    broadcastOnline();
  });

  on('send', async (p, ack) => {
    if (!uid || !p || typeof p !== 'object') return;
    const now = Date.now(); sendTimes = sendTimes.filter((t) => now - t < 10000);
    if (sendTimes.length >= 20) return; sendTimes.push(now);                      // simple flood limit
    const peer = peerId(p.to), grp = isG(peer);
    if (!peer || peer === uid) return;
    let rooms = ['u:' + uid, 'u:' + peer];
    if (grp) { const mem = await memberIds(peer); if (!mem.includes(uid)) return; rooms = mem.map((x) => 'u:' + x); }
    else if (!(await db.query('SELECT 1 FROM users WHERE id = $1', [peer])).rows.length) return;

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
    io.to(rooms).emit('message', rowToMsg(ins.rows[0]));
    if (grp) {
      const ol = (await memberIds(peer)).filter((x) => x !== uid && online.has(x));
      if (ol.length) { await db.query('UPDATE group_members SET last_delivered = $3 WHERE gid = $1 AND user_id = ANY($2::text[])', [peer.slice(2), ol, Date.now()]); pushMarks(peer.slice(2)).catch(() => {}); }
    }
    if (!grp && online.has(peer)) {
      await db.query(`UPDATE messages SET status = 'delivered' WHERE id = $1 AND status = 'sent'`, [id]);
      io.to('u:' + uid).emit('status', { convo, status: 'delivered' });
    }
    if (typeof ack === 'function') ack({ ok: true });
  });

  on('history', async (p, ack) => {
    if (typeof ack !== 'function') return;
    if (!uid) return ack([]);
    const before = Number(p && p.before) || null, hp = peerId(p && p.to);
    if (isG(hp) && !(await memberIds(hp)).includes(uid)) return ack([]);
    const { rows } = await db.query(
      `SELECT * FROM messages WHERE convo = $1 AND ($2::bigint IS NULL OR ts < $2::bigint) ORDER BY ts DESC LIMIT 50`,
      [dm(uid, peerId(p && p.to)), before]);
    ack(rows.reverse().map(rowToMsg));
  });

  on('read', async (p) => {
    if (!uid) return;
    const peer = peerId(p && p.to), convo = dm(uid, peer);
    if (isG(peer)) { await db.query('UPDATE group_members SET last_read = $3 WHERE gid = $1 AND user_id = $2', [peer.slice(2), uid, Date.now()]); return pushMarks(peer.slice(2)); }
    const r = await db.query(`UPDATE messages SET status = 'read' WHERE convo = $1 AND to_id = $2 AND status <> 'read'`, [convo, uid]);
    if (r.rowCount) io.to('u:' + peer).emit('status', { convo, status: 'read' });
  });

  on('delete', async (p) => {                                                      // "delete for everyone" (sender only)
    if (!uid || !p) return;
    const peer = peerId(p.to), convo = dm(uid, peer), id = String(p.id || '');
    const sel = (await db.query('SELECT file FROM messages WHERE id = $1 AND convo = $2 AND from_id = $3 AND deleted = FALSE', [id, convo, uid])).rows[0];
    if (!sel) return;
    await db.query(`UPDATE messages SET deleted = TRUE, text = '', file = NULL WHERE id = $1`, [id]);
    io.to(isG(peer) ? (await memberIds(peer)).map((x) => 'u:' + x) : ['u:' + uid, 'u:' + peer]).emit('deleted', { convo, id });
    if (sel.file && sel.file.key) await dropFileIfUnused(sel.file.key);
  });

  /* ---- linked devices: sign in on a computer by scanning a QR code with the phone (like WhatsApp Web) ---- */
  on('qr:create', async (p, ack) => {                                              // computer, not signed in yet
    if (typeof ack !== 'function') return;
    const now = Date.now(); qrTimes = qrTimes.filter((x) => now - x < 60000);
    if (uid || qrTimes.length >= 12 || qrCodes.size > 5000) return ack({ error: 'limit' });
    qrTimes.push(now); dropQr();
    qrCode = crypto.randomBytes(18).toString('base64url');
    qrCodes.set(qrCode, { sid: socket.id, device: deviceName(ua()), exp: now + QR_TTL });
    const origin = /^https?:\/\/[^\s/]{1,200}$/.test(String(p && p.origin)) ? p.origin : '';
    ack({ code: qrCode, ttl: QR_TTL, svg: await QRCode.toString(origin + '/?link=' + qrCode, { type: 'svg', margin: 1, errorCorrectionLevel: 'M' }) });
  });
  on('qr:cancel', () => dropQr());
  on('qr:info', (p, ack) => {                                                      // phone: which device is asking?
    if (typeof ack !== 'function') return;
    const c = uid && qrCodes.get(String((p && p.code) || ''));
    ack(c && c.exp > Date.now() ? { device: c.device } : {});
  });
  on('qr:approve', async (p, ack) => {                                             // phone (signed in) says yes
    if (typeof ack !== 'function') return;
    if (!uid) return ack({ error: 'auth' });
    const code = String((p && p.code) || ''), c = qrCodes.get(code);
    const target = c && c.exp > Date.now() && io.sockets.sockets.get(c.sid);
    if (!target) return ack({ error: 'expired' });
    qrCodes.delete(code);
    target.emit('qr:done', { session: await newSession(uid, c.device) });
    ack({ ok: true, device: c.device });
  });
  on('devices', async (p, ack) => {
    if (typeof ack !== 'function') return;
    if (!uid) return ack([]);
    const { rows } = await db.query(
      'SELECT md5(token) AS id, token, device, created_at, last_seen FROM sessions WHERE user_id = $1 AND created_at > $2 ORDER BY COALESCE(last_seen, created_at) DESC',
      [uid, Date.now() - SESSION_MS]);
    ack(rows.map((r) => ({ id: r.id, device: r.device || 'Browser', created: Number(r.created_at), last: Number(r.last_seen || r.created_at), current: r.token === curSession })));
  });
  const kick = async (userId, gone) => {                                           // disconnect devices that were logged out
    for (const s of await io.in('u:' + userId).fetchSockets()) if (gone(s.data.session)) { s.emit('revoked'); s.disconnect(true); }
  };
  on('device:revoke', async (p, ack) => {
    if (!uid || !p) return;
    const r = await db.query('DELETE FROM sessions WHERE user_id = $1 AND md5(token) = $2 RETURNING token', [uid, String(p.id || '')]);
    const gone = new Set(r.rows.map((x) => x.token)); await kick(uid, (t) => gone.has(t));
    if (typeof ack === 'function') ack({ ok: true });
  });
  on('device:revoke_others', async (p, ack) => {
    if (!uid) return;
    await db.query('DELETE FROM sessions WHERE user_id = $1 AND token <> $2', [uid, curSession]);
    await kick(uid, (t) => t !== curSession);
    if (typeof ack === 'function') ack({ ok: true });
  });
  on('logout', async (p, ack) => {                                                 // this device only
    if (uid && curSession) await db.query('DELETE FROM sessions WHERE token = $1 AND user_id = $2', [curSession, uid]);
    if (typeof ack === 'function') ack({ ok: true });
  });

  /* ---- profile (name, about, photo) ---- */
  on('profile:update', async (p, ack) => {
    if (!uid || !p || typeof p !== 'object') return;
    if (limited('pu', 10, 60000)) return ack && ack({ error: 'slow' });
    const cur = (await db.query('SELECT * FROM users WHERE id = $1', [uid])).rows[0];
    if (!cur) return;
    let nm = cur.name, about = cur.about, pic = cur.picture;
    if (typeof p.name === 'string') { nm = p.name.trim().slice(0, 60); if (!nm) return ack && ack({ error: 'name' }); }
    if (typeof p.about === 'string') about = p.about.trim().slice(0, 140);
    if (p.picture === null) pic = null;
    else if (typeof p.picture === 'string') {
      const key = p.picture;
      if (!KEY_RE.test(key)) return ack && ack({ error: 'photo' });
      const f = (await db.query('SELECT ctype FROM files WHERE key = $1 AND owner = $2', [key, uid])).rows[0];
      if (!f || !/^image\//.test(f.ctype)) return ack && ack({ error: 'photo' });
      pic = '/avatar/' + key.slice(2);
    }
    const u = (await db.query('UPDATE users SET name = $2, about = $3, picture = $4, custom = TRUE WHERE id = $1 RETURNING *', [uid, nm, about || null, pic])).rows[0];
    if (cur.picture && cur.picture !== pic) await delAvatar(cur.picture);
    name = u.name || u.email;
    const o = online.get(uid); if (o) o.user = u;
    io.to([uid, ...(await peersOf(uid))].map((x) => 'u:' + x)).emit('profile', Object.assign(pub(u), { picture: u.picture || null }));
    for (const r of (await db.query('SELECT gid FROM group_members WHERE user_id = $1', [uid])).rows) await pushGroup(r.gid);
    broadcastOnline();
    if (typeof ack === 'function') ack({ ok: true });
  });

  /* ---- status (disappears after 24 h, 48 h or any custom number of hours) ---- */
  on('status:post', async (p, ack) => {
    if (!uid || !p || typeof p !== 'object' || typeof ack !== 'function') return;
    if (limited('sp', 10, 60000)) return ack({ error: 'slow' });
    const hours = Math.min(168, Math.max(1, Math.round(Number(p.hours) || 24)));
    const text = String(p.text || '').trim().slice(0, 700);
    let file = null;
    if (p.file && typeof p.file === 'object') {
      const key = String(p.file.key || '');
      if (!KEY_RE.test(key) || !(await mayUseFile(uid, key))) return ack({ error: 'file' });
      file = { name: String(p.file.name || 'file').slice(0, 150), type: String(p.file.type || 'application/octet-stream').slice(0, 100), size: Math.max(0, +p.file.size || 0), key };
    }
    if (!text && !file) return ack({ error: 'empty' });
    const now = Date.now();
    if ((await db.query('SELECT COUNT(*)::int AS n FROM statuses WHERE user_id = $1 AND exp > $2', [uid, now])).rows[0].n >= 30) return ack({ error: 'limit' });
    await db.query('INSERT INTO statuses (id, user_id, ts, exp, text, file) VALUES ($1,$2,$3,$4,$5,$6)', [crypto.randomUUID(), uid, now, now + hours * 3600000, text, file]);
    (await peersOf(uid)).forEach((x) => io.to('u:' + x).emit('status:new', { from: uid }));
    ack({ ok: true, hours });
  });
  on('status:list', async (p, ack) => {
    if (typeof ack !== 'function') return;
    if (!uid) return ack([]);
    const ids = [uid, ...(await peersOf(uid))];
    const { rows } = await db.query(
      `SELECT s.*, u.name, u.email, u.picture, (SELECT COUNT(*)::int FROM status_views v WHERE v.sid = s.id) AS views, EXISTS (SELECT 1 FROM status_views v2 WHERE v2.sid = s.id AND v2.viewer = $3) AS seen FROM statuses s JOIN users u ON u.id = s.user_id
       WHERE s.exp > $1 AND s.user_id = ANY($2::text[]) ORDER BY s.ts ASC LIMIT 300`, [Date.now(), ids, uid]);
    ack(rows.map((r) => ({ id: r.id, ts: Number(r.ts), exp: Number(r.exp), text: r.text, views: r.views, seen: r.seen, file: r.file || undefined, user: { id: r.user_id, name: r.name || r.email, picture: r.picture || undefined } })));
  });
  on('status:seen', async (p) => {
    if (!uid || !p || limited('ss', 120, 60000)) return;
    await db.query(`INSERT INTO status_views (sid, viewer, ts) SELECT s.id, $2, $3 FROM statuses s WHERE s.id = $1 AND s.exp > $3 AND s.user_id <> $2 AND s.user_id = ANY($4::text[]) ON CONFLICT DO NOTHING`, [String(p.id || ''), uid, Date.now(), await peersOf(uid)]);
  });
  on('status:viewers', async (p, ack) => {                                          // only the owner can see who viewed
    if (typeof ack !== 'function') return; if (!uid || !p) return ack([]);
    const r = await db.query(`SELECT u.id, u.name, u.email, u.picture, v.ts FROM status_views v JOIN users u ON u.id = v.viewer JOIN statuses s ON s.id = v.sid WHERE v.sid = $1 AND s.user_id = $2 ORDER BY v.ts DESC`, [String(p.id || ''), uid]);
    ack(r.rows.map((x) => ({ id: x.id, name: x.name || x.email, picture: x.picture || undefined, ts: Number(x.ts) })));
  });
  on('status:delete', async (p, ack) => {
    if (!uid || !p) return;
    const r = await db.query('DELETE FROM statuses WHERE id = $1 AND user_id = $2 RETURNING file', [String(p.id || ''), uid]);
    await db.query('DELETE FROM status_views WHERE sid = $1', [String(p.id || '')]);
    if (r.rows[0] && r.rows[0].file && r.rows[0].file.key) await dropFileIfUnused(r.rows[0].file.key);
    if (typeof ack === 'function') ack({ ok: true });
  });

  /* ---- groups: any signed-in user can create one; the creator is its admin ---- */
  on('group:create', async (p, ack) => {
    if (!uid || !p || typeof ack !== 'function') return;
    if (limited('gc', 5, 60000)) return ack({ error: 'slow' });
    const nm = String(p.name || '').trim().slice(0, 60); if (!nm) return ack({ error: 'name' });
    if ((await db.query('SELECT COUNT(*)::int AS n FROM chat_groups WHERE created_by = $1', [uid])).rows[0].n >= 50) return ack({ error: 'limit' });
    const ids = [...new Set((Array.isArray(p.members) ? p.members : []).map(String))].filter((x) => x !== uid).slice(0, 255);
    const ok = ids.length ? (await db.query('SELECT id FROM users WHERE id = ANY($1::text[])', [ids])).rows.map((r) => r.id) : [];
    const gid = crypto.randomUUID(), now = Date.now();
    await db.query('INSERT INTO chat_groups (id, name, created_by, created_at) VALUES ($1,$2,$3,$4)', [gid, nm, uid, now]);
    await db.query(`INSERT INTO group_members (gid, user_id, role, joined_at) SELECT $1, x, CASE WHEN x = $2 THEN 'admin' ELSE 'member' END, $3 FROM unnest($4::text[]) x`, [gid, uid, now, [uid, ...ok]]);
    await pushGroup(gid); await notice(gid, 'create', name); ack({ ok: true, id: 'g:' + gid });
  });
  on('group:add', async (p, ack) => {
    const gid = String((p && p.id) || '').replace(/^g:/, '');
    if (!uid || !(await isAdmin(gid, uid))) return;
    if (limited('ga', 10, 60000)) return;
    const have = await memberIds(gid), ids = [...new Set((Array.isArray(p.members) ? p.members : []).map(String))].filter((x) => !have.includes(x)).slice(0, Math.max(0, 256 - have.length));
    let added = [];
    if (ids.length) added = (await db.query(`INSERT INTO group_members (gid, user_id, joined_at) SELECT $1, id, $2 FROM users WHERE id = ANY($3::text[]) ON CONFLICT DO NOTHING RETURNING user_id`, [gid, Date.now(), ids])).rows.map((r) => r.user_id);
    await pushGroup(gid);
    if (added.length) await notice(gid, 'add', name, (await db.query('SELECT COALESCE(name, email) AS n FROM users WHERE id = ANY($1::text[])', [added])).rows.map((r) => r.n).join(', '));
    if (typeof ack === 'function') ack({ ok: true });
  });
  on('group:rename', async (p, ack) => {
    const gid = String((p && p.id) || '').replace(/^g:/, ''), nm = String((p && p.name) || '').trim().slice(0, 60);
    if (!uid || !nm || !(await isAdmin(gid, uid))) return;
    await db.query('UPDATE chat_groups SET name = $2 WHERE id = $1', [gid, nm]); await pushGroup(gid); await notice(gid, 'rename', name, nm); if (typeof ack === 'function') ack({ ok: true });
  });
  const leaveGroup = async (gid, who, by) => {
    const wn = (await db.query('SELECT COALESCE(name, email) AS n FROM users WHERE id = $1', [who])).rows[0];
    const r = await db.query('DELETE FROM group_members WHERE gid = $1 AND user_id = $2', [gid, who]); if (!r.rowCount) return;
    await db.query('DELETE FROM challenge_members WHERE user_id = $2 AND cid IN (SELECT id FROM challenges WHERE gid = $1)', [gid, who]);
    io.to('u:' + who).emit('group:gone', { id: 'g:' + gid });
    if (!(await memberIds(gid)).length) {                                              // last person left: remove the group and its files
      await db.query('DELETE FROM chat_groups WHERE id = $1', [gid]);
      await db.query('DELETE FROM challenge_members WHERE cid IN (SELECT id FROM challenges WHERE gid = $1)', [gid]); await db.query('DELETE FROM challenges WHERE gid = $1', [gid]);
      for (const m of (await db.query('DELETE FROM messages WHERE convo = $1 RETURNING file', ['grp:' + gid])).rows) if (m.file && m.file.key) await dropFileIfUnused(m.file.key).catch(() => {});
      return;
    }
    if (!(await db.query(`SELECT 1 FROM group_members WHERE gid = $1 AND role = 'admin' LIMIT 1`, [gid])).rows.length)
      await db.query(`UPDATE group_members SET role = 'admin' WHERE gid = $1 AND user_id = (SELECT user_id FROM group_members WHERE gid = $1 ORDER BY joined_at LIMIT 1)`, [gid]);
    await pushGroup(gid); await notice(gid, by ? 'remove' : 'left', by || (wn && wn.n), by ? wn && wn.n : undefined);
  };
  on('group:photo', async (p, ack) => {
    const gid = String((p && p.id) || '').replace(/^g:/, '');
    if (!uid || !(await isAdmin(gid, uid)) || limited('gp', 10, 60000)) return;
    const cur = (await db.query('SELECT picture FROM chat_groups WHERE id = $1', [gid])).rows[0]; if (!cur) return;
    let pic = null;
    if (typeof p.picture === 'string') {
      if (!KEY_RE.test(p.picture)) return;
      const f = (await db.query('SELECT ctype FROM files WHERE key = $1 AND owner = $2', [p.picture, uid])).rows[0]; if (!f || !/^image\//.test(f.ctype)) return;
      pic = '/avatar/' + p.picture.slice(2);
    }
    await db.query('UPDATE chat_groups SET picture = $2 WHERE id = $1', [gid, pic]);
    if (cur.picture && cur.picture !== pic) await delAvatar(cur.picture);
    await pushGroup(gid); if (typeof ack === 'function') ack({ ok: true });
  });
  /* ---- group fitness challenges: members opt in, only their total for the challenge is shared ---- */
  on('challenge:create', async (p, ack) => {
    if (typeof ack !== 'function') return;
    const gid = String((p && p.id) || '').replace(/^g:/, '');
    if (!uid || !(await isAdmin(gid, uid)) || limited('ch', 5, 60000)) return ack({ error: 'denied' });
    const title = String(p.title || '').trim().slice(0, 60), metric = p.metric === 'water' ? 'water' : 'steps', goal = Math.round(+p.goal), n = Math.round(+p.days), start = String(p.start || '');
    if (!title || !(goal >= 1 && goal <= 1000000) || !(n >= 1 && n <= 90) || !/^\d{4}-\d\d-\d\d$/.test(start) || !(Math.abs(Date.parse(start) - Date.now()) < 3 * 864e5)) return ack({ error: 'bad' });
    if ((await db.query('SELECT COUNT(*)::int AS c FROM challenges WHERE gid = $1 AND d_end >= $2', [gid, start])).rows[0].c >= 5) return ack({ error: 'limit' });
    const cid = crypto.randomUUID();
    await db.query('INSERT INTO challenges (id, gid, title, metric, goal, d_start, d_end, created_by, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)', [cid, gid, title, metric, goal, start, addDays(start, n - 1), uid, Date.now()]);
    await db.query('INSERT INTO challenge_members (cid, user_id) VALUES ($1,$2)', [cid, uid]);
    await notice(gid, 'challenge', name, title); ack({ ok: true });
  });
  on('challenge:list', async (p, ack) => {
    if (typeof ack !== 'function') return;
    const gid = String((p && p.id) || '').replace(/^g:/, '');
    if (!uid || limited('cl', 30, 60000) || !(await memberIds(gid)).includes(uid)) return ack([]);
    const out = [];
    for (const c of (await db.query('SELECT * FROM challenges WHERE gid = $1 ORDER BY d_end DESC, created_at DESC LIMIT 20', [gid])).rows) {
      const b = await board(c); out.push({ id: c.id, title: c.title, metric: c.metric, goal: c.goal, start: c.d_start, end: c.d_end, joined: b.some((x) => x.id === uid), board: b });
    }
    ack(out);
  });
  on('challenge:join', async (p, ack) => {
    if (!uid || !p) return;
    const c = (await db.query('SELECT c.id FROM challenges c JOIN group_members gm ON gm.gid = c.gid AND gm.user_id = $2 WHERE c.id = $1', [String(p.cid || ''), uid])).rows[0]; if (!c) return;
    if (p.join) await db.query('INSERT INTO challenge_members (cid, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [c.id, uid]);
    else await db.query('DELETE FROM challenge_members WHERE cid = $1 AND user_id = $2', [c.id, uid]);
    if (typeof ack === 'function') ack({ ok: true });
  });
  on('challenge:delete', async (p, ack) => {
    if (!uid || !p) return;
    const c = (await db.query('SELECT id, gid FROM challenges WHERE id = $1', [String(p.cid || '')])).rows[0]; if (!c || !(await isAdmin(c.gid, uid))) return;
    await db.query('DELETE FROM challenge_members WHERE cid = $1', [c.id]); await db.query('DELETE FROM challenges WHERE id = $1', [c.id]);
    if (typeof ack === 'function') ack({ ok: true });
  });
  on('group:role', async (p, ack) => {                                               // creator makes or removes admins
    const gid = String((p && p.id) || '').replace(/^g:/, ''), who = String((p && p.member) || '');
    if (!uid || who === uid) return;
    const g = (await db.query('SELECT created_by FROM chat_groups WHERE id = $1', [gid])).rows[0]; if (!g || g.created_by !== uid) return;
    await db.query('UPDATE group_members SET role = $3 WHERE gid = $1 AND user_id = $2', [gid, who, p.role === 'admin' ? 'admin' : 'member']);
    await pushGroup(gid); if (typeof ack === 'function') ack({ ok: true });
  });
  on('group:leave', async (p, ack) => { if (!uid || !p) return; await leaveGroup(String(p.id || '').replace(/^g:/, ''), uid); if (typeof ack === 'function') ack({ ok: true }); });
  on('group:remove', async (p, ack) => {
    const gid = String((p && p.id) || '').replace(/^g:/, ''), who = String((p && p.member) || '');
    if (!uid || who === uid || !(await isAdmin(gid, uid))) return;
    const gg = (await db.query('SELECT created_by FROM chat_groups WHERE id = $1', [gid])).rows[0], tr = (await db.query('SELECT role FROM group_members WHERE gid = $1 AND user_id = $2', [gid, who])).rows[0];
    if (!gg || !tr || (tr.role === 'admin' && gg.created_by !== uid)) return;      // only the creator can remove another admin
    await leaveGroup(gid, who, name); if (typeof ack === 'function') ack({ ok: true });
  });

  on('typing', async (p) => {
    if (!uid || !p) return; const to = peerId(p.to);
    if (isG(to)) { const mem = await memberIds(to); if (!mem.includes(uid) || limited('ty', 30, 10000)) return; io.to(mem.filter((x) => x !== uid).map((x) => 'u:' + x)).emit('typing', { from: uid, group: to, name }); }
    else io.to('u:' + to).emit('typing', { from: uid });
  });

  on('find', async (p, ack) => {
    if (typeof ack !== 'function') return;
    if (!uid) return ack({});
    if (limited('fd', 20, 60000)) return ack({});
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
    dropQr();
    if (!socket.data.joined) return;
    const o = online.get(uid);
    if (o && --o.n <= 0) online.delete(uid);
    broadcastOnline();
  });
});

process.on('unhandledRejection', (e) => console.error('unhandled', e && e.message));
async function checkStorage() {                                                    // tells you in the logs if uploads cannot work
  const key = 'healthcheck/' + crypto.randomUUID();
  try {
    await s3.send(new PutObjectCommand({ Bucket: BUCKET, Key: key, Body: Buffer.from('ok'), ContentType: 'text/plain' }));
    await s3.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: key }));
    console.log('R2 storage check: OK');
  } catch (e) { console.error('R2 storage check FAILED, uploads will not work: ' + (e.name || '') + ' ' + e.message); }
}
initDb().then(() => server.listen(env.PORT || 3000, () => { console.log('Chat server running on port ' + (env.PORT || 3000)); checkStorage(); }))
  .catch((e) => { console.error('Database setup failed:', e.message); process.exit(1); });
