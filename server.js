const express = require('express');
const fetch = require('node-fetch');
const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'futurebiochem-dev-secret-change-in-prod';

// ─── Database Setup ───────────────────────────────────────────────────────────
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'futurebiochem.db');

// Ensure data directory exists
const fs = require('fs');
const dataDir = path.dirname(DB_PATH);
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(DB_PATH);

// Enable WAL mode for better concurrency
db.pragma('journal_mode = WAL');

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    email       TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password    TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS preferences (
    user_id         INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    units           TEXT    NOT NULL DEFAULT 'mcg',
    bac_water_ml    REAL    NOT NULL DEFAULT 2.0,
    fav_compounds   TEXT    NOT NULL DEFAULT '[]',
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS orders (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    items       TEXT    NOT NULL,
    total       REAL    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'pending',
    invoice_url TEXT,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  -- Peptide Tracker: vials
  CREATE TABLE IF NOT EXISTS vials (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    compound        TEXT    NOT NULL,
    total_mg        REAL    NOT NULL,
    remaining_mg    REAL    NOT NULL,
    bac_water_ml    REAL    NOT NULL DEFAULT 2.0,
    concentration   REAL    GENERATED ALWAYS AS (total_mg / bac_water_ml) VIRTUAL,
    lot_note        TEXT,
    opened_at       TEXT    NOT NULL DEFAULT (datetime('now')),
    expires_at      TEXT,
    archived        INTEGER NOT NULL DEFAULT 0
  );

  -- Peptide Tracker: dose logs
  CREATE TABLE IF NOT EXISTS dose_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    vial_id     INTEGER REFERENCES vials(id) ON DELETE SET NULL,
    compound    TEXT    NOT NULL,
    dose_mg     REAL    NOT NULL,
    dose_units  TEXT    NOT NULL DEFAULT 'mg',
    site        TEXT,
    notes       TEXT,
    cycle_id    INTEGER REFERENCES cycles(id) ON DELETE SET NULL,
    logged_at   TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  -- Peptide Tracker: cycles / protocols
  CREATE TABLE IF NOT EXISTS cycles (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT    NOT NULL,
    compounds   TEXT    NOT NULL DEFAULT '[]',
    start_date  TEXT    NOT NULL,
    end_date    TEXT,
    status      TEXT    NOT NULL DEFAULT 'active',
    notes       TEXT,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
  );
`);

// ─── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// JWT auth middleware — attaches req.user if valid token present
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Authentication required.' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token.' });
  }
}

// ─── Auth Routes ──────────────────────────────────────────────────────────────

// POST /api/auth/register
app.post('/api/auth/register', (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email, and password are required.' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) {
    return res.status(409).json({ error: 'An account with that email already exists.' });
  }

  const hash = bcrypt.hashSync(password, 12);
  const { lastInsertRowid: userId } = db.prepare(
    'INSERT INTO users (name, email, password) VALUES (?, ?, ?)'
  ).run(name.trim(), email.trim().toLowerCase(), hash);

  // Create default preferences row
  db.prepare('INSERT INTO preferences (user_id) VALUES (?)').run(userId);

  const token = jwt.sign({ id: userId, email: email.trim().toLowerCase(), name: name.trim() }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: userId, name: name.trim(), email: email.trim().toLowerCase() } });
});

// POST /api/auth/login
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.trim().toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid email or password.' });
  }

  const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
});

// GET /api/auth/me — validate token & return profile
app.get('/api/auth/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id, name, email, created_at FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  res.json({ user });
});

// ─── Preferences Routes ───────────────────────────────────────────────────────

// GET /api/user/preferences
app.get('/api/user/preferences', requireAuth, (req, res) => {
  let prefs = db.prepare('SELECT * FROM preferences WHERE user_id = ?').get(req.user.id);
  if (!prefs) {
    db.prepare('INSERT INTO preferences (user_id) VALUES (?)').run(req.user.id);
    prefs = db.prepare('SELECT * FROM preferences WHERE user_id = ?').get(req.user.id);
  }
  res.json({
    units: prefs.units,
    bac_water_ml: prefs.bac_water_ml,
    fav_compounds: JSON.parse(prefs.fav_compounds || '[]'),
    updated_at: prefs.updated_at
  });
});

// PUT /api/user/preferences
app.put('/api/user/preferences', requireAuth, (req, res) => {
  const { units, bac_water_ml, fav_compounds } = req.body || {};
  const validUnits = ['mcg', 'mg', 'units'];

  const updates = {};
  if (units !== undefined) {
    if (!validUnits.includes(units)) return res.status(400).json({ error: 'Invalid units value.' });
    updates.units = units;
  }
  if (bac_water_ml !== undefined) {
    const ml = parseFloat(bac_water_ml);
    if (isNaN(ml) || ml <= 0) return res.status(400).json({ error: 'Invalid bac_water_ml value.' });
    updates.bac_water_ml = ml;
  }
  if (fav_compounds !== undefined) {
    if (!Array.isArray(fav_compounds)) return res.status(400).json({ error: 'fav_compounds must be an array.' });
    updates.fav_compounds = JSON.stringify(fav_compounds);
  }

  if (Object.keys(updates).length === 0) return res.status(400).json({ error: 'No valid fields to update.' });

  const setClauses = Object.keys(updates).map(k => `${k} = ?`).join(', ');
  db.prepare(`UPDATE preferences SET ${setClauses}, updated_at = datetime('now') WHERE user_id = ?`)
    .run(...Object.values(updates), req.user.id);

  res.json({ ok: true });
});

// ─── Orders / Purchase History Routes ────────────────────────────────────────

// GET /api/user/orders
app.get('/api/user/orders', requireAuth, (req, res) => {
  const orders = db.prepare(
    'SELECT id, items, total, status, invoice_url, created_at FROM orders WHERE user_id = ? ORDER BY created_at DESC'
  ).all(req.user.id);

  res.json(orders.map(o => ({ ...o, items: JSON.parse(o.items) })));
});

// POST /api/user/orders — save an order record (called after checkout)
app.post('/api/user/orders', requireAuth, (req, res) => {
  const { items, total, invoice_url } = req.body || {};
  if (!items || !Array.isArray(items) || total === undefined) {
    return res.status(400).json({ error: 'items (array) and total are required.' });
  }

  const { lastInsertRowid: orderId } = db.prepare(
    'INSERT INTO orders (user_id, items, total, invoice_url) VALUES (?, ?, ?, ?)'
  ).run(req.user.id, JSON.stringify(items), parseFloat(total), invoice_url || null);

  res.json({ id: orderId, ok: true });
});

// ─── Tracker: Vials ──────────────────────────────────────────────────────────

// GET /api/tracker/vials
app.get('/api/tracker/vials', requireAuth, (req, res) => {
  const archived = req.query.archived === '1' ? 1 : 0;
  const vials = db.prepare(
    'SELECT * FROM vials WHERE user_id = ? AND archived = ? ORDER BY opened_at DESC'
  ).all(req.user.id, archived);
  res.json(vials);
});

// POST /api/tracker/vials
app.post('/api/tracker/vials', requireAuth, (req, res) => {
  const { compound, total_mg, bac_water_ml, lot_note, expires_at } = req.body || {};
  if (!compound || !total_mg) return res.status(400).json({ error: 'compound and total_mg are required.' });
  const mg = parseFloat(total_mg);
  const water = parseFloat(bac_water_ml) || 2.0;
  if (isNaN(mg) || mg <= 0) return res.status(400).json({ error: 'Invalid total_mg.' });
  const { lastInsertRowid: id } = db.prepare(
    'INSERT INTO vials (user_id, compound, total_mg, remaining_mg, bac_water_ml, lot_note, expires_at) VALUES (?,?,?,?,?,?,?)'
  ).run(req.user.id, compound.trim(), mg, mg, water, lot_note || null, expires_at || null);
  res.json({ id, ok: true });
});

// PATCH /api/tracker/vials/:id/archive
app.patch('/api/tracker/vials/:id/archive', requireAuth, (req, res) => {
  db.prepare('UPDATE vials SET archived = 1 WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  res.json({ ok: true });
});

// DELETE /api/tracker/vials/:id
app.delete('/api/tracker/vials/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM vials WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  res.json({ ok: true });
});

// ─── Tracker: Dose Logs ───────────────────────────────────────────────────────

// GET /api/tracker/logs  — optional ?compound=&limit=
app.get('/api/tracker/logs', requireAuth, (req, res) => {
  const limit   = Math.min(parseInt(req.query.limit) || 50, 200);
  const compound = req.query.compound || null;
  let query = 'SELECT * FROM dose_logs WHERE user_id = ?';
  const params = [req.user.id];
  if (compound) { query += ' AND compound = ?'; params.push(compound); }
  query += ' ORDER BY logged_at DESC LIMIT ?';
  params.push(limit);
  res.json(db.prepare(query).all(...params));
});

// POST /api/tracker/logs
app.post('/api/tracker/logs', requireAuth, (req, res) => {
  const { compound, dose_mg, dose_units, vial_id, site, notes, cycle_id, logged_at } = req.body || {};
  if (!compound || dose_mg === undefined) return res.status(400).json({ error: 'compound and dose_mg are required.' });
  const mg = parseFloat(dose_mg);
  if (isNaN(mg) || mg <= 0) return res.status(400).json({ error: 'Invalid dose_mg.' });

  const ts = logged_at || new Date().toISOString();
  const { lastInsertRowid: id } = db.prepare(
    'INSERT INTO dose_logs (user_id, compound, dose_mg, dose_units, vial_id, site, notes, cycle_id, logged_at) VALUES (?,?,?,?,?,?,?,?,?)'
  ).run(req.user.id, compound.trim(), mg, dose_units || 'mg', vial_id || null, site || null, notes || null, cycle_id || null, ts);

  // Deduct from vial if provided
  if (vial_id) {
    db.prepare('UPDATE vials SET remaining_mg = MAX(0, remaining_mg - ?) WHERE id = ? AND user_id = ?')
      .run(mg, vial_id, req.user.id);
  }

  res.json({ id, ok: true });
});

// DELETE /api/tracker/logs/:id
app.delete('/api/tracker/logs/:id', requireAuth, (req, res) => {
  const log = db.prepare('SELECT * FROM dose_logs WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!log) return res.status(404).json({ error: 'Log not found.' });
  // Restore vial quantity if applicable
  if (log.vial_id) {
    db.prepare('UPDATE vials SET remaining_mg = MIN(total_mg, remaining_mg + ?) WHERE id = ? AND user_id = ?')
      .run(log.dose_mg, log.vial_id, req.user.id);
  }
  db.prepare('DELETE FROM dose_logs WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  res.json({ ok: true });
});

// GET /api/tracker/stats
app.get('/api/tracker/stats', requireAuth, (req, res) => {
  const uid = req.user.id;
  const totalDoses  = db.prepare('SELECT COUNT(*) as n FROM dose_logs WHERE user_id = ?').get(uid).n;
  const totalVials  = db.prepare('SELECT COUNT(*) as n FROM vials WHERE user_id = ? AND archived = 0').get(uid).n;
  const topCompound = db.prepare(
    'SELECT compound, COUNT(*) as n FROM dose_logs WHERE user_id = ? GROUP BY compound ORDER BY n DESC LIMIT 1'
  ).get(uid);

  // Streak: consecutive days with at least one dose (ending today or yesterday)
  const dates = db.prepare(
    "SELECT DISTINCT date(logged_at) as d FROM dose_logs WHERE user_id = ? ORDER BY d DESC"
  ).all(uid).map(r => r.d);

  let streak = 0;
  if (dates.length) {
    const today = new Date().toISOString().slice(0, 10);
    const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
    let cursor = dates[0] === today || dates[0] === yesterday ? dates[0] : null;
    if (cursor) {
      for (const d of dates) {
        if (d === cursor) { streak++; cursor = new Date(new Date(cursor) - 86400000).toISOString().slice(0, 10); }
        else break;
      }
    }
  }

  res.json({ totalDoses, totalVials, streak, topCompound: topCompound?.compound || null });
});

// ─── Tracker: Cycles ─────────────────────────────────────────────────────────

// GET /api/tracker/cycles
app.get('/api/tracker/cycles', requireAuth, (req, res) => {
  const cycles = db.prepare('SELECT * FROM cycles WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id);
  res.json(cycles.map(c => ({ ...c, compounds: JSON.parse(c.compounds) })));
});

// POST /api/tracker/cycles
app.post('/api/tracker/cycles', requireAuth, (req, res) => {
  const { name, compounds, start_date, end_date, notes } = req.body || {};
  if (!name || !start_date) return res.status(400).json({ error: 'name and start_date are required.' });
  const { lastInsertRowid: id } = db.prepare(
    'INSERT INTO cycles (user_id, name, compounds, start_date, end_date, notes) VALUES (?,?,?,?,?,?)'
  ).run(req.user.id, name.trim(), JSON.stringify(compounds || []), start_date, end_date || null, notes || null);
  res.json({ id, ok: true });
});

// PATCH /api/tracker/cycles/:id
app.patch('/api/tracker/cycles/:id', requireAuth, (req, res) => {
  const { status, end_date, notes } = req.body || {};
  const updates = [];
  const params = [];
  if (status)   { updates.push('status = ?');   params.push(status); }
  if (end_date) { updates.push('end_date = ?');  params.push(end_date); }
  if (notes !== undefined) { updates.push('notes = ?'); params.push(notes); }
  if (!updates.length) return res.status(400).json({ error: 'Nothing to update.' });
  db.prepare(`UPDATE cycles SET ${updates.join(', ')} WHERE id = ? AND user_id = ?`)
    .run(...params, req.params.id, req.user.id);
  res.json({ ok: true });
});

// DELETE /api/tracker/cycles/:id
app.delete('/api/tracker/cycles/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM cycles WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  res.json({ ok: true });
});

// ─── Checkout (existing, enhanced to save order for logged-in users) ──────────
app.post('/api/checkout', async (req, res) => {
  const { items, total } = req.body;

  const PAYGATE_API_KEY  = process.env.PAYGATE_API_KEY  || '';
  const PAYGATE_STORE_ID = process.env.PAYGATE_STORE_ID || '';
  const SITE_URL = process.env.SITE_URL || `http://localhost:${PORT}`;

  if (!PAYGATE_API_KEY || !PAYGATE_STORE_ID) {
    return res.status(500).json({ error: 'PayGate credentials not configured.' });
  }

  try {
    const response = await fetch('https://paygate.to/api/v1/invoices', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${PAYGATE_API_KEY}`
      },
      body: JSON.stringify({
        store_id:    PAYGATE_STORE_ID,
        amount:      parseFloat(total).toFixed(2),
        currency:    'USD',
        description: 'FutureBioChem Research Peptides',
        items:       items.map(i => ({ name: i.name, quantity: i.qty, price: i.price })),
        redirect_url: `${SITE_URL}/thank-you`,
        cancel_url:   `${SITE_URL}/`
      })
    });

    const data = await response.json();
    if (!response.ok) return res.status(response.status).json({ error: data.message || 'PayGate error' });

    const invoiceUrl = data.invoice_url || data.url;

    // If user is authenticated, persist this order automatically
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (token) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        db.prepare('INSERT INTO orders (user_id, items, total, status, invoice_url) VALUES (?, ?, ?, ?, ?)')
          .run(decoded.id, JSON.stringify(items), parseFloat(total), 'invoiced', invoiceUrl);
      } catch { /* ignore auth errors for anonymous checkout */ }
    }

    res.json({ invoiceUrl });
  } catch (err) {
    console.error('Checkout error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Catch-all — serve the SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`FutureBioChem running at http://localhost:${PORT}`);
});
