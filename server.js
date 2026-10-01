const express = require('express');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Server } = require('socket.io');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const server = http.createServer(app);
const io = new Server(server);
app.use(express.static(path.join(__dirname, 'public')));

// ---- Google sign-in ----
// Set GOOGLE_CLIENT_ID (from Google Cloud Console) and SESSION_SECRET (any long random text) as environment variables.
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.SESSION_SECRET) console.warn('SESSION_SECRET is not set: everyone is signed out whenever the server restarts.');
if (!CLIENT_ID) console.warn('GOOGLE_CLIENT_ID is not set: nobody can sign in yet.');
const google = new OAuth2Client(CLIENT_ID);
app.get('/config.json', (req, res) => res.json({ clientId: CLIENT_ID }));

const mac = (b) => crypto.createHmac('sha256', SECRET).update(b).digest('base64url');
// Our own login ticket: after Google confirms who you are, you stay signed in for 30 days.
const sign = (u) => {
  const b = Buffer.from(JSON.stringify({ id: u.id, name: u.name, exp: Date.now() + 30 * 864e5 })).toString('base64url');
  return b + '.' + mac(b);
};
const unsign = (s) => {
  try {
    const [b, h] = String(s).split('.');
    const x = Buffer.from(h || ''), y = Buffer.from(mac(b));
    if (x.length !== y.length || !crypto.timingSafeEqual(x, y)) return null;
    const u = JSON.parse(Buffer.from(b, 'base64url').toString());
    return u.exp > Date.now() ? { id: u.id, name: u.name } : null;
  } catch (e) { return null; }
};
async function who(auth) {
  const { credential, session } = auth || {};
  if (session) return unsign(session);
  if (!credential || !CLIENT_ID) return null;
  try {
    const ticket = await google.verifyIdToken({ idToken: String(credential), audience: CLIENT_ID });
    const p = ticket.getPayload();
    return { id: p.sub, name: String(p.name || 'User').slice(0, 30) }; // email is never shared
  } catch (e) { return null; }
}

// Messages are appended to a file: no message limit except disk space.
// Before real users, replace this with PostgreSQL.
const DIR = path.join(__dirname, 'data');
const FILE = path.join(DIR, 'messages.jsonl');
fs.mkdirSync(DIR, { recursive: true });
const messages = fs.existsSync(FILE)
  ? fs.readFileSync(FILE, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
  : [];

const GROUPS = ['yoga', 'diet', 'weight-loss', 'general'];
const online = new Map(); // Google user id -> { id, name, sid }
const broadcast = () => io.emit('online', [...online.values()].map(({ id, name }) => ({ id, name })));
const dm = (a, b) => 'dm:' + [a, b].sort().join('|');
const page = (convo, before) =>
  messages.filter((m) => m.convo === convo && m.ts < (before || Infinity)).slice(-30);

io.on('connection', (socket) => {
  let uid = null;
  let name = null;
  let hits = [];

  const convoFor = (to) => {
    to = String(to);
    if (to.startsWith('group:') && GROUPS.includes(to.slice(6))) return to;
    if (to.startsWith('user:')) return dm(uid, to.slice(5));
    return null;
  };

  socket.on('join', async (auth, cb) => {
    if (typeof cb !== 'function') return;
    const u = await who(auth);
    if (socket.disconnected || !u || uid) return cb({ error: true });
    uid = u.id; name = u.name;
    const old = online.get(uid);
    online.set(uid, { id: uid, name, sid: socket.id });
    if (old && old.sid !== socket.id) {
      const s = io.sockets.sockets.get(old.sid);
      if (s) s.disconnect(true); // newest sign-in wins
    }
    socket.join('user:' + uid);
    GROUPS.forEach((g) => socket.join('group:' + g));
    cb({ id: uid, groups: GROUPS, session: sign(u) });
    broadcast();
  });

  socket.on('history', ({ to, before } = {}, cb) => {
    const c = uid && convoFor(to);
    if (c) cb(page(c, before));
  });

  socket.on('send', ({ to, text } = {}) => {
    text = String(text || '').trim().slice(0, 2000);
    const now = Date.now();
    hits = hits.filter((t) => now - t < 10000);
    const c = uid && convoFor(to);
    if (!c || !text || hits.length >= 20) return; // spam limit: 20 messages per 10 seconds
    hits.push(now);
    const m = { convo: c, from: uid, name, text, ts: now };
    messages.push(m);
    fs.appendFile(FILE, JSON.stringify(m) + '\n', () => {});
    if (c.startsWith('group:')) io.to(c).emit('message', m);
    else io.to('user:' + uid).to(String(to)).emit('message', m);
  });

  // Video call signalling: pass messages between the two users.
  socket.on('call', ({ to, data } = {}) => {
    if (uid) io.to('user:' + String(to)).emit('call', { from: uid, data });
  });

  socket.on('disconnect', () => {
    const cur = uid && online.get(uid);
    if (cur && cur.sid === socket.id) online.delete(uid);
    broadcast();
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log('Running on port ' + PORT));
