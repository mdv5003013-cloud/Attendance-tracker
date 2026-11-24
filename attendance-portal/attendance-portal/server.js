const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(express.static('public'));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && !/localhost|127\.0\.0\.1/.test(process.env.DATABASE_URL)
    ? { rejectUnauthorized: false } : false,
});
const SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const TODAY = "(now() at time zone 'Asia/Kolkata')::date";
const q = (sql, p) => pool.query(sql, p).then(r => r.rows);
const wrap = fn => (req, res) => fn(req, res).catch(e => { console.error(e); res.status(500).json({ error: 'Server error' }); });

async function init() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'employee');
    CREATE TABLE IF NOT EXISTS attendance (
      id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id) ON DELETE CASCADE,
      day DATE NOT NULL, check_in TIMESTAMPTZ, check_out TIMESTAMPTZ, UNIQUE (user_id, day));
    CREATE TABLE IF NOT EXISTS leaves (
      id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id) ON DELETE CASCADE,
      start_date DATE NOT NULL, end_date DATE NOT NULL, type TEXT NOT NULL, reason TEXT,
      status TEXT NOT NULL DEFAULT 'pending', created_at TIMESTAMPTZ DEFAULT now());
  `);
}

function auth(req, res, next) {
  try { req.user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET); next(); }
  catch { res.status(401).json({ error: 'Please sign in' }); }
}
const adminOnly = (req, res, next) => req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Admins only' });
const token = u => jwt.sign({ id: u.id, name: u.name, role: u.role }, SECRET, { expiresIn: '12h' });

// The first account created becomes the admin.
app.post('/api/register', wrap(async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password || password.length < 6) return res.status(400).json({ error: 'Name, email and a password of 6+ characters are required' });
  const [{ count }] = await q('SELECT count(*)::int FROM users');
  try {
    const [u] = await q('INSERT INTO users(name,email,password_hash,role) VALUES($1,$2,$3,$4) RETURNING *',
      [name.trim(), email.trim().toLowerCase(), await bcrypt.hash(password, 10), count === 0 ? 'admin' : 'employee']);
    res.json({ token: token(u), user: { name: u.name, role: u.role } });
  } catch { res.status(409).json({ error: 'That email is already registered' }); }
}));

app.post('/api/login', wrap(async (req, res) => {
  const [u] = await q('SELECT * FROM users WHERE email=$1', [(req.body.email || '').trim().toLowerCase()]);
  if (!u || !(await bcrypt.compare(req.body.password || '', u.password_hash))) return res.status(401).json({ error: 'Wrong email or password' });
  res.json({ token: token(u), user: { name: u.name, role: u.role } });
}));

app.post('/api/attendance/checkin', auth, wrap(async (req, res) => {
  const r = await q(`INSERT INTO attendance(user_id,day,check_in) VALUES($1,${TODAY},now()) ON CONFLICT DO NOTHING RETURNING *`, [req.user.id]);
  r.length ? res.json(r[0]) : res.status(409).json({ error: "You've already checked in today" });
}));

app.post('/api/attendance/checkout', auth, wrap(async (req, res) => {
  const r = await q(`UPDATE attendance SET check_out=now() WHERE user_id=$1 AND day=${TODAY} AND check_out IS NULL RETURNING *`, [req.user.id]);
  r.length ? res.json(r[0]) : res.status(409).json({ error: 'Check in first, or you already checked out' });
}));

app.get('/api/attendance/today', auth, wrap(async (req, res) => {
  res.json((await q(`SELECT * FROM attendance WHERE user_id=$1 AND day=${TODAY}`, [req.user.id]))[0] || null);
}));

// Own records for a month (admins can pass user_id)
app.get('/api/attendance', auth, wrap(async (req, res) => {
  const uid = req.user.role === 'admin' && req.query.user_id ? +req.query.user_id : req.user.id;
  const m = /^\d{4}-\d{2}$/.test(req.query.month) ? req.query.month : null;
  if (!m) return res.status(400).json({ error: 'month=YYYY-MM required' });
  res.json(await q(`SELECT to_char(day,'YYYY-MM-DD') day, check_in, check_out FROM attendance
    WHERE user_id=$1 AND to_char(day,'YYYY-MM')=$2 ORDER BY day`, [uid, m]));
}));

app.post('/api/leaves', auth, wrap(async (req, res) => {
  const { start_date, end_date, type, reason } = req.body;
  if (!start_date || !end_date || end_date < start_date) return res.status(400).json({ error: 'Choose a valid date range' });
  res.json((await q('INSERT INTO leaves(user_id,start_date,end_date,type,reason) VALUES($1,$2,$3,$4,$5) RETURNING *',
    [req.user.id, start_date, end_date, type || 'Casual', reason || '']))[0]);
}));

app.get('/api/leaves', auth, wrap(async (req, res) => {
  const all = req.user.role === 'admin';
  res.json(await q(`SELECT l.id, u.name, to_char(start_date,'YYYY-MM-DD') start_date, to_char(end_date,'YYYY-MM-DD') end_date,
    type, reason, status FROM leaves l JOIN users u ON u.id=l.user_id
    ${all ? '' : 'WHERE l.user_id=$1'} ORDER BY l.created_at DESC LIMIT 200`, all ? [] : [req.user.id]));
}));

app.patch('/api/leaves/:id', auth, adminOnly, wrap(async (req, res) => {
  if (!['approved', 'rejected'].includes(req.body.status)) return res.status(400).json({ error: 'Invalid status' });
  res.json((await q('UPDATE leaves SET status=$1 WHERE id=$2 RETURNING *', [req.body.status, req.params.id]))[0]);
}));

// Monthly dashboard: per employee, days present + approved leave days inside the month
app.get('/api/dashboard', auth, adminOnly, wrap(async (req, res) => {
  const m = /^\d{4}-\d{2}$/.test(req.query.month) ? req.query.month : null;
  if (!m) return res.status(400).json({ error: 'month=YYYY-MM required' });
  const first = m + '-01';
  res.json(await q(`
    SELECT u.id, u.name,
      (SELECT count(*)::int FROM attendance a WHERE a.user_id=u.id AND to_char(a.day,'YYYY-MM')=$1) AS present,
      (SELECT coalesce(sum(
         least(l.end_date, ($2::date + interval '1 month - 1 day')::date) - greatest(l.start_date, $2::date) + 1),0)::int
       FROM leaves l WHERE l.user_id=u.id AND l.status='approved'
         AND l.start_date <= ($2::date + interval '1 month - 1 day')::date AND l.end_date >= $2::date) AS leave_days,
      (SELECT coalesce(round(avg(extract(epoch FROM (check_out-check_in))/3600)::numeric,1),0)
       FROM attendance a WHERE a.user_id=u.id AND to_char(a.day,'YYYY-MM')=$1 AND check_out IS NOT NULL) AS avg_hours
    FROM users u ORDER BY u.name`, [m, first]));
}));

const port = process.env.PORT || 3000;
init().then(() => app.listen(port, () => console.log('Portal running on ' + port)))
  .catch(e => { console.error('Database setup failed:', e.message); process.exit(1); });
