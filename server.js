/**
 * ConcoursPro — Backend Express + MySQL (XAMPP)
 * Port : 3001
 */

const express    = require('express');
const mysql      = require('mysql2/promise');
const cors       = require('cors');
const jwt        = require('jsonwebtoken');
const bcrypt     = require('bcryptjs');
const path       = require('path');
const fs         = require('fs');
const multer     = require('multer');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app        = express();
const PORT       = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET.length < 16) {
  console.error('[SECURITE] JWT_SECRET manquant ou trop court dans backend/.env. Arrêt du serveur.');
  process.exit(1);
}

app.use(cors({ origin: process.env.CORS_ORIGIN || 'http://localhost:5173', credentials: true }));
app.use(express.json());

// Pool MySQL
const pool = mysql.createPool({
  host:     process.env.DB_HOST     || 'localhost',
  port:     parseInt(process.env.DB_PORT || '3306'),
  user:     process.env.DB_USER     || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME     || 'concourspro',
  waitForConnections: true,
  connectionLimit: 10,
});

// ── Envoi d'emails (SMTP réel si configuré, sinon simulation dans les logs) ────
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';
const SMTP_CONFIGURED = !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);

const mailTransporter = SMTP_CONFIGURED
  ? nodemailer.createTransport({
      host:   process.env.SMTP_HOST,
      port:   parseInt(process.env.SMTP_PORT || '587'),
      secure: process.env.SMTP_SECURE === 'true', // true pour le port 465, false pour les autres
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    })
  : null;

if (!SMTP_CONFIGURED) {
  console.warn('[email] SMTP non configure (SMTP_HOST/SMTP_USER/SMTP_PASS manquants) -> les emails seront simules dans les logs.');
}

/**
 * Envoie un email. Retourne { sent: true } si envoyé réellement,
 * { sent: false, simulated: true } si SMTP n'est pas configuré (mode démo).
 * Ne lève jamais d'exception : en cas d'échec SMTP, on retourne { sent: false, error }.
 */
async function sendMail(to, subject, html) {
  if (!SMTP_CONFIGURED) {
    console.info(`[email] (SIMULE) -> ${to} | ${subject}`);
    return { sent: false, simulated: true };
  }
  try {
    await mailTransporter.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to,
      subject,
      html,
    });
    return { sent: true };
  } catch (err) {
    console.error(`[email] Echec envoi vers ${to} :`, err.message);
    return { sent: false, error: err.message };
  }
}

// Génère un mot de passe lisible et suffisamment fort (évite les caractères ambigus 0/O, 1/l/I)
function generatePassword(length = 10) {
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  const bytes = require('crypto').randomBytes(length);
  let out = '';
  for (let i = 0; i < length; i++) out += chars[bytes[i] % chars.length];
  return out;
}

// Mapping entite -> table
const ENTITY_MAP = {
  Candidate:        'candidates',
  Concours:         'concours',
  SalleExamen:      'salle_examen',
  CandidatDocument: 'candidat_document',
  JuryLog:          'jury_log',
  Reclamation:      'reclamation',
  AuditLog:         'audit_log',
  ConcoursConfig:   'concours_config',
  Pointage:         'pointage',
  User:             'app_users',
  SuperAdminConfig: 'super_admin_config',
  JuryConfig:       'jury_config',
  Filiere:          'filieres',
  Departement:      'departements',
};

// Middleware Auth JWT
function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Non authentifie' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Token invalide ou expire' }); }
}

function requireSuperAdmin(req, res, next) {
  if (req.user?.role !== 'super_admin')
    return res.status(403).json({ error: 'Acces reserve au Super Admin' });
  next();
}

// ── Rate limiting basique sur /api/auth/login (anti brute-force) ──────────────
const loginAttempts = new Map(); // ip -> { count, firstAttempt }
const LOGIN_MAX_ATTEMPTS = 8;
const LOGIN_WINDOW_MS    = 15 * 60 * 1000; // 15 min

function loginRateLimit(req, res, next) {
  const ip  = req.ip || req.connection.remoteAddress || 'unknown';
  const now = Date.now();
  const rec = loginAttempts.get(ip);
  if (!rec || now - rec.firstAttempt > LOGIN_WINDOW_MS) {
    loginAttempts.set(ip, { count: 1, firstAttempt: now });
    return next();
  }
  if (rec.count >= LOGIN_MAX_ATTEMPTS) {
    const waitMin = Math.ceil((LOGIN_WINDOW_MS - (now - rec.firstAttempt)) / 60000);
    return res.status(429).json({ error: `Trop de tentatives. Reessayez dans ${waitMin} min.` });
  }
  rec.count++;
  next();
}

// ── Permissions par entité et par rôle sur le CRUD générique ──────────────────
// 'read'  : qui peut lire (GET)
// 'write' : qui peut créer/modifier/supprimer (POST/PUT/DELETE)
// Rôles : super_admin, admin, jury, enseignant
const ENTITY_PERMISSIONS = {
  Candidate:        { read: ['super_admin','admin','jury','enseignant','user'], write: ['super_admin','admin','jury'] },
  Concours:         { read: ['super_admin','admin','jury','enseignant','user'], write: ['super_admin','admin'] },
  SalleExamen:      { read: ['super_admin','admin','jury','enseignant'],        write: ['super_admin','admin'] },
  CandidatDocument: { read: ['super_admin','admin','jury','enseignant','user'], write: ['super_admin','admin','jury','enseignant','user'] },
  JuryLog:          { read: ['super_admin','admin','jury'],                     write: ['super_admin','admin','jury'] },
  Reclamation:      { read: ['super_admin','admin','jury','enseignant','user'], write: ['super_admin','admin','jury','enseignant','user'] },
  AuditLog:         { read: ['super_admin','admin'],                            write: ['super_admin'] },
  ConcoursConfig:   { read: ['super_admin','admin','jury'],                     write: ['super_admin','admin'] },
  Pointage:         { read: ['super_admin','admin','jury'],                     write: ['super_admin','admin','jury'] },
  User:             { read: ['super_admin'],                                    write: ['super_admin'] },
  SuperAdminConfig: { read: ['super_admin'],                                    write: ['super_admin'] },
  JuryConfig:       { read: ['super_admin','admin'],                            write: ['super_admin'] },
  Filiere:          { read: ['super_admin','admin','jury','enseignant','user'], write: ['super_admin','admin'] },
  Departement:      { read: ['super_admin','admin','jury','enseignant','user'], write: ['super_admin','admin'] },
};
// Note : le rôle "user" (candidat / grand public) obtient des droits minimaux :
// lecture des données publiques de consultation (Candidate, Concours, Filiere,
// Departement) et lecture/écriture de ses propres réclamations (Reclamation).
// Il n'a explicitement PAS le droit d'écrire sur Candidate, SalleExamen, etc.
//
// Reclamation est ouvert en lecture/écriture à TOUS les rôles (y compris jury
// et enseignant) car les pages "/" (Home) et "/reclamations" sont accessibles
// à ALL_ROLES dans src/lib/roleAccess.js (PAGE_ACCESS) — un rôle autorisé à
// ouvrir une page doit toujours avoir les droits sur les entités qu'elle
// charge, sous peine d'erreurs 403 en cascade qui cassent toute la page
// (cf. bug : page d'accueil non fonctionnelle pour jury/enseignant faute
// d'accès à Reclamation, alors qu'ils pouvaient lire Candidate et Concours).

function checkEntityPermission(mode) {
  return (req, res, next) => {
    const entity = req.params.entity;
    const perm   = ENTITY_PERMISSIONS[entity];
    if (!perm) return res.status(404).json({ error: 'Entite inconnue' });
    const allowed = perm[mode] || [];
    if (!allowed.includes(req.user?.role)) {
      return res.status(403).json({ error: `Acces refuse pour le role "${req.user?.role}" sur ${entity}` });
    }
    next();
  };
}

function parseSort(s) {
  if (!s) return 'created_date DESC';
  const desc = s.startsWith('-');
  const col  = s.replace(/^-/, '');
  if (!/^[a-zA-Z_]+$/.test(col)) return 'created_date DESC';
  return `\`${col}\` ${desc ? 'DESC' : 'ASC'}`;
}

// Champs numériques à convertir (MySQL2 retourne les DECIMAL en string)
const NUMERIC_FIELDS = new Set([
  'concours_score', 'bac_moyenne', 'cutoff_score', 'max_score',
  'seuil_admission', 'capacite', 'quota_places', 'quota_liste_attente',
  'numero_place', 'concours_passed', 'notes_locked', 'auto_filtered',
  'priorite_mention',
  // Champs filières
  'actif', 'ordre',
]);

function safeRow(row) {
  if (!row) return row;
  const { password_hash, pin_hash, ...safe } = row;
  // Convertir les DECIMAL/TINYINT en Number pour éviter les bugs de comparaison JS
  for (const [k, v] of Object.entries(safe)) {
    if (NUMERIC_FIELDS.has(k) && v !== null && v !== undefined) {
      safe[k] = Number(v);
    }
  }
  // Désérialiser les champs JSON stockés en TEXT
  const JSON_FIELDS = ['priorite_mentions_ordre'];
  for (const field of JSON_FIELDS) {
    if (safe[field] && typeof safe[field] === 'string') {
      try { safe[field] = JSON.parse(safe[field]); } catch(e) { /* garder tel quel */ }
    }
  }
  return safe;
}

// ===== AUTH =====

app.post('/api/auth/login', loginRateLimit, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis' });
  try {
    // ── 1. Vérification .env EN PRIORITÉ (toujours fonctionnel même si la BD est corrompue)
    const saEnvEmail = (process.env.SUPER_ADMIN_EMAIL || '').toLowerCase();
    const saEnvPass  =  process.env.SUPER_ADMIN_PASSWORD || '';
    if (saEnvEmail && email.toLowerCase() === saEnvEmail && saEnvPass && password === saEnvPass) {
      // Récupérer le nom depuis la BD si disponible
      let saName = 'Super Admin';
      try {
        const [nr] = await pool.query('SELECT name FROM super_admin_config LIMIT 1');
        if (nr.length > 0) saName = nr[0].name;
      } catch {}
      const payload = { id: 'sa_env', name: saName, email: saEnvEmail, role: 'super_admin', status: 'actif' };
      loginAttempts.delete(req.ip);
      return res.json({ token: jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' }), user: payload });
    }

    // ── 2. Super Admin via hash BD (utilisé quand le mot de passe a été changé depuis l'interface)
    const [saRows] = await pool.query('SELECT * FROM super_admin_config LIMIT 1');
    if (saRows.length > 0) {
      const sa = saRows[0];
      if (email.toLowerCase() === sa.email.toLowerCase()) {
        const ok = await bcrypt.compare(password, sa.password_hash);
        if (!ok) return res.status(401).json({ error: 'Mot de passe incorrect' });
        const payload = { id: sa.id, name: sa.name, email: sa.email, role: 'super_admin', status: 'actif' };
        loginAttempts.delete(req.ip);
        return res.json({ token: jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' }), user: payload });
      }
    }
    // Utilisateurs normaux
    const [rows] = await pool.query('SELECT * FROM app_users WHERE email = ? LIMIT 1', [email.toLowerCase()]);
    if (!rows.length) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    const u = rows[0];
    if (u.status === 'suspendu') return res.status(403).json({ error: 'Compte suspendu' });
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    const payload = { id: u.id, name: u.name, email: u.email, role: u.role, status: u.status };
    loginAttempts.delete(req.ip);
    res.json({ token: jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' }), user: payload });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Erreur serveur' }); }
});

app.get('/api/auth/me', authMiddleware, (req, res) => res.json(req.user));

// ===== USERS (routes dediees) =====

app.get('/api/users', authMiddleware, requireSuperAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, name, email, role, status, created_date FROM app_users ORDER BY created_date DESC');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

const VALID_ROLES = ['admin', 'jury', 'enseignant', 'user'];
app.post('/api/users', authMiddleware, requireSuperAdmin, async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Nom, email et mot de passe requis' });
  if (password.length < 8) return res.status(400).json({ error: 'Le mot de passe doit faire au moins 8 caracteres' });
  const safeRole = VALID_ROLES.includes(role) ? role : 'jury';
  try {
    const [ex] = await pool.query('SELECT id FROM app_users WHERE email = ?', [email.toLowerCase()]);
    if (ex.length) return res.status(409).json({ error: 'Email deja utilise' });
    const hash = await bcrypt.hash(password, 10);
    const id   = require('crypto').randomUUID();
    await pool.query(
      'INSERT INTO app_users (id, name, email, password_hash, role, status, created_by) VALUES (?,?,?,?,?,?,?)',
      [id, name, email.toLowerCase(), hash, safeRole, 'actif', req.user.email]
    );
    const [rows] = await pool.query('SELECT id, name, email, role, status, created_date FROM app_users WHERE id = ?', [id]);
    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/users/:id', authMiddleware, requireSuperAdmin, async (req, res) => {
  const { name, email, password, role, status } = req.body;
  try {
    const up = [], vl = [];
    if (name)     { up.push('name=?');   vl.push(name); }
    if (email)    { up.push('email=?');  vl.push(email.toLowerCase()); }
    if (role && VALID_ROLES.includes(role)) { up.push('role=?'); vl.push(role); }
    if (status)   { up.push('status=?'); vl.push(status); }
    if (password) { up.push('password_hash=?'); vl.push(await bcrypt.hash(password, 10)); }
    up.push('updated_date=NOW()');
    vl.push(req.params.id);
    await pool.query(`UPDATE app_users SET ${up.join(',')} WHERE id=?`, vl);
    const [rows] = await pool.query('SELECT id, name, email, role, status, created_date FROM app_users WHERE id=?', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Non trouve' });
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/users/:id', authMiddleware, requireSuperAdmin, async (req, res) => {
  try { await pool.query('DELETE FROM app_users WHERE id=?', [req.params.id]); res.json({ success: true }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/users/:id/toggle', authMiddleware, requireSuperAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT status FROM app_users WHERE id=?', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Non trouve' });
    const ns = rows[0].status === 'actif' ? 'suspendu' : 'actif';
    await pool.query('UPDATE app_users SET status=?, updated_date=NOW() WHERE id=?', [ns, req.params.id]);
    res.json({ status: ns });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Super Admin config
app.get('/api/super-admin', authMiddleware, requireSuperAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, name, email, created_date FROM super_admin_config LIMIT 1');
    res.json(rows[0] || null);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/super-admin', authMiddleware, requireSuperAdmin, async (req, res) => {
  const { name, email, currentPassword, newPassword } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Nom et email requis' });
  try {
    const [rows] = await pool.query('SELECT * FROM super_admin_config LIMIT 1');
    if (newPassword) {
      if (rows.length > 0) {
        const ok = await bcrypt.compare(currentPassword || '', rows[0].password_hash);
        if (!ok) return res.status(400).json({ error: 'Mot de passe actuel incorrect' });
      }
      const hash = await bcrypt.hash(newPassword, 10);
      if (rows.length > 0) {
        await pool.query('UPDATE super_admin_config SET name=?,email=?,password_hash=?,updated_date=NOW() WHERE id=?',
          [name, email.toLowerCase(), hash, rows[0].id]);
      } else {
        await pool.query('INSERT INTO super_admin_config (id,name,email,password_hash) VALUES (UUID(),?,?,?)',
          [name, email.toLowerCase(), hash]);
      }
    } else {
      if (!rows.length) return res.status(400).json({ error: 'Definissez un mot de passe initial' });
      await pool.query('UPDATE super_admin_config SET name=?,email=?,updated_date=NOW() WHERE id=?',
        [name, email.toLowerCase(), rows[0].id]);
    }
    const [updated] = await pool.query('SELECT id,name,email,created_date FROM super_admin_config LIMIT 1');
    res.json(updated[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== COMPTES CANDIDATS ADMIS (génération en masse) =====

// Aperçu : liste des candidats admis n'ayant pas encore de compte utilisateur
app.get('/api/users/admitted-candidates', authMiddleware, requireSuperAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT c.id, c.full_name, c.email
         FROM candidates c
        WHERE c.final_status = 'admis'
          AND c.email IS NOT NULL AND c.email <> ''
          AND NOT EXISTS (
                SELECT 1 FROM app_users u WHERE u.email = LOWER(c.email)
              )
        ORDER BY c.full_name ASC`
    );
    const [[{ sansEmail }]] = await pool.query(
      `SELECT COUNT(*) AS sansEmail FROM candidates
        WHERE final_status = 'admis' AND (email IS NULL OR email = '')`
    );
    res.json({ eligibles: rows, sansEmail });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Génération en masse : crée un compte + envoie un email pour chaque candidat admis éligible
app.post('/api/users/generate-for-admitted', authMiddleware, requireSuperAdmin, async (req, res) => {
  const candidateIds = Array.isArray(req.body?.candidateIds) ? req.body.candidateIds : null;
  try {
    let query = `SELECT c.id, c.full_name, c.email
                   FROM candidates c
                  WHERE c.final_status = 'admis'
                    AND c.email IS NOT NULL AND c.email <> ''
                    AND NOT EXISTS (
                          SELECT 1 FROM app_users u WHERE u.email = LOWER(c.email)
                        )`;
    const params = [];
    if (candidateIds && candidateIds.length) {
      query += ` AND c.id IN (${candidateIds.map(() => '?').join(',')})`;
      params.push(...candidateIds);
    }
    const [candidats] = await pool.query(query, params);

    const created = [];
    const echoues  = [];

    for (const cand of candidats) {
      const email = cand.email.toLowerCase();
      try {
        // Un email en double dans le lot pourrait déjà avoir été créé lors de cette boucle
        const [ex] = await pool.query('SELECT id FROM app_users WHERE email = ?', [email]);
        if (ex.length) { echoues.push({ full_name: cand.full_name, email, raison: 'Compte déjà existant' }); continue; }

        const password = generatePassword(10);
        const hash     = await bcrypt.hash(password, 10);
        const id       = require('crypto').randomUUID();

        await pool.query(
          'INSERT INTO app_users (id, name, email, password_hash, role, status, created_by) VALUES (?,?,?,?,?,?,?)',
          [id, cand.full_name, email, hash, 'user', 'actif', req.user.email]
        );

        const loginUrl = `${FRONTEND_URL}/connexion`;
        const html = `
          <div style="font-family: Arial, sans-serif; max-width: 560px; margin: auto;">
            <h2 style="color:#0f172a;">Félicitations, ${cand.full_name} !</h2>
            <p>Vous êtes <strong>admis(e)</strong> au concours. Votre compte candidat a été créé sur la plateforme ConcoursPro.</p>
            <p style="background:#f1f5f9; padding:12px 16px; border-radius:8px;">
              <strong>Email de connexion :</strong> ${email}<br/>
              <strong>Mot de passe temporaire :</strong> ${password}
            </p>
            <p><a href="${loginUrl}" style="background:#2563eb;color:#fff;padding:10px 18px;border-radius:6px;text-decoration:none;display:inline-block;">Accéder à la plateforme</a></p>
            <p style="font-size:13px;color:#64748b;">Lien direct : ${loginUrl}<br/>
            Pour votre sécurité, pensez à modifier ce mot de passe après votre première connexion.</p>
          </div>`;
        const mailResult = await sendMail(email, 'Votre compte ConcoursPro — Résultat d\'admission', html);

        created.push({
          full_name: cand.full_name,
          email,
          password,           // renvoyé une seule fois, pour affichage/export immédiat côté admin
          emailEnvoye: mailResult.sent,
          simulated: !!mailResult.simulated,
        });
      } catch (err) {
        echoues.push({ full_name: cand.full_name, email: cand.email, raison: err.message });
      }
    }

    res.json({
      total: candidats.length,
      crees: created.length,
      echoues: echoues.length,
      comptes: created,
      erreurs: echoues,
      smtpConfigure: SMTP_CONFIGURED,
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== CRUD GENERIQUE =====

app.get('/api/entities/:entity', authMiddleware, checkEntityPermission('read'), async (req, res) => {
  const table = ENTITY_MAP[req.params.entity];
  if (!table) return res.status(404).json({ error: 'Entite inconnue' });
  const sort = parseSort(req.query.sort);
  const limit = Math.min(parseInt(req.query.limit) || 100, 100000);
  const offset = Math.max(parseInt(req.query.offset) || 0, 0);
  const reserved = new Set(['sort', 'limit', 'offset']);
  const filters = [], values = [];
  for (const [k, v] of Object.entries(req.query)) {
    if (reserved.has(k) || !/^[a-zA-Z_]+$/.test(k)) continue;
    filters.push(`\`${k}\` = ?`); values.push(v);
  }
  // Un rôle "user" ne doit voir QUE ses propres documents candidat, jamais
  // ceux des autres — on force le filtre candidate_email côté serveur au
  // lieu de faire confiance à ce que le frontend envoie (sinon un candidat
  // pourrait simplement retirer ce paramètre de sa requête pour tout voir).
  if (req.params.entity === 'CandidatDocument' && req.user?.role === 'user') {
    const idx = filters.findIndex(f => f.startsWith('`candidate_email`'));
    if (idx !== -1) { filters.splice(idx, 1); values.splice(idx, 1); }
    filters.push('LOWER(`candidate_email`) = LOWER(?)'); values.push(req.user.email || '');
  }
  const where = filters.length ? `WHERE ${filters.join(' AND ')}` : '';
  try {
    const [rows] = await pool.query(`SELECT * FROM \`${table}\` ${where} ORDER BY ${sort} LIMIT ? OFFSET ?`, [...values, limit, offset]);
    res.json(rows.map(safeRow));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/entities/:entity/:id', authMiddleware, checkEntityPermission('read'), async (req, res) => {
  const table = ENTITY_MAP[req.params.entity];
  if (!table) return res.status(404).json({ error: 'Entite inconnue' });
  try {
    const [rows] = await pool.query(`SELECT * FROM \`${table}\` WHERE id=? LIMIT 1`, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Non trouve' });
    if (req.params.entity === 'CandidatDocument' && req.user?.role === 'user' && !isOwnCandidateDocument(rows[0], req.user)) {
      return res.status(403).json({ error: "Vous ne pouvez consulter que vos propres documents." });
    }
    res.json(safeRow(rows[0]));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Empêche que la somme des quota_places de toutes les configs d'un même
// concours dépasse le total_places défini sur ce concours (sinon le moteur
// de statut finit par admettre plus de candidats que la capacité réelle).
// excludeId : id de la config en cours de modification (à exclure du total existant).
async function validateConcoursConfigQuota(concoursId, newQuota, excludeId) {
  if (!concoursId || newQuota === undefined || newQuota === null) return null;
  const [concRows] = await pool.query('SELECT total_places, name FROM concours WHERE id=?', [concoursId]);
  const conc = concRows[0];
  if (!conc || conc.total_places === null || conc.total_places === undefined) return null; // pas de plafond défini
  const [usedRows] = await pool.query(
    `SELECT COALESCE(SUM(quota_places),0) AS used FROM concours_config WHERE concours_id=?${excludeId ? ' AND id<>?' : ''}`,
    excludeId ? [concoursId, excludeId] : [concoursId]
  );
  const used = Number(usedRows[0]?.used || 0);
  const projected = used + Number(newQuota);
  if (projected > Number(conc.total_places)) {
    const dispo = Math.max(0, Number(conc.total_places) - used);
    return `Total dépassé pour "${conc.name}" : ${used} déjà réparties + ${newQuota} demandées = ${projected}, pour ${conc.total_places} places au total (il reste ${dispo}).`;
  }
  return null;
}

// Revalide la capacité d'une salle côté serveur quand un candidat se voit
// affecter salle_examen_id (empêche une race condition entre deux utilisateurs
// affectant en parallèle et dépassant la capacité réelle — cf. audit bug #8).
async function validateSalleCapacity(salleId, excludeCandidateId) {
  if (!salleId) return null;
  const [salleRows] = await pool.query('SELECT capacite, nom_salle FROM salle_examen WHERE id=?', [salleId]);
  const salle = salleRows[0];
  if (!salle) return 'Salle introuvable.';
  const [countRows] = await pool.query(
    `SELECT COUNT(*) AS nb FROM candidates WHERE salle_examen_id=?${excludeCandidateId ? ' AND id<>?' : ''}`,
    excludeCandidateId ? [salleId, excludeCandidateId] : [salleId]
  );
  const current = Number(countRows[0]?.nb || 0);
  if (current >= Number(salle.capacite || 0)) {
    return `Salle "${salle.nom_salle}" pleine (${current}/${salle.capacite}).`;
  }
  return null;
}

// Un rôle "user" (candidat) ne doit jamais pouvoir lire/modifier/supprimer le
// document d'UN AUTRE candidat — même si ENTITY_PERMISSIONS l'autorise à lire/
// écrire l'entité CandidatDocument en général. L'appartenance d'un document
// est déterminée par candidate_email : on considère qu'un compte "user" est
// le document de CE candidat si son email de connexion correspond (comparaison
// insensible à la casse), exactement comme Reclamations.jsx retrouve déjà les
// réclamations d'un candidat par son email.
function isOwnCandidateDocument(row, user) {
  if (!row || !user?.email) return false;
  return String(row.candidate_email || '').toLowerCase() === String(user.email).toLowerCase();
}

app.post('/api/entities/:entity', authMiddleware, checkEntityPermission('write'), async (req, res) => {
  const entityName = req.params.entity;
  const table = ENTITY_MAP[entityName];
  if (!table) return res.status(404).json({ error: 'Entite inconnue' });
  if (entityName === 'User') {
    return res.status(403).json({ error: 'Utilisez /api/users pour creer un utilisateur' });
  }
  if (table === 'concours_config') {
    const err = await validateConcoursConfigQuota(req.body.concours_id, req.body.quota_places, null);
    if (err) return res.status(400).json({ error: err });
  }
  // Défense en profondeur : `centre_examen` est NOT NULL sans valeur par
  // défaut en base. La validation frontend (SallesExamen.jsx) l'exige déjà,
  // mais un appel API direct (ou un futur oubli côté UI) planterait sinon
  // avec une erreur SQL brute au lieu d'un message clair.
  if (table === 'salle_examen') {
    if (!req.body.nom_salle || !req.body.centre_examen || !req.body.capacite) {
      return res.status(400).json({ error: 'nom_salle, centre_examen et capacite sont requis pour créer une salle.' });
    }
  }
  const data = { ...req.body };
  if (!data.id) data.id = require('crypto').randomUUID();
  data.created_date = data.created_date || new Date();
  data.updated_date = new Date();
  // Un rôle "user" ne peut créer un document QUE sous sa propre identité —
  // on écrase toute valeur envoyée par le client pour candidate_email, afin
  // qu'un candidat ne puisse pas déposer un document au nom de quelqu'un
  // d'autre en modifiant simplement la requête.
  if (entityName === 'CandidatDocument' && req.user?.role === 'user') {
    data.candidate_email = req.user.email;
  }
  // Tables sans colonne created_by — ne pas injecter
  const TABLES_NO_CREATED_BY = ['filieres', 'departements', 'jury_config', 'super_admin_config'];
  if (!TABLES_NO_CREATED_BY.includes(table)) {
    data.created_by = data.created_by || req.user?.email || null;
  }
  if ((table === 'app_users' || table === 'super_admin_config') && data.password) {
    data.password_hash = await bcrypt.hash(data.password, 10);
    delete data.password;
  }
  // Sérialiser les tableaux/objets JSON avant INSERT
  const JSON_COLS = ['priorite_mentions_ordre'];
  for (const col of JSON_COLS) {
    if (data[col] !== undefined && typeof data[col] !== 'string') {
      data[col] = JSON.stringify(data[col]);
    }
  }
  try {
    await pool.query(`INSERT INTO \`${table}\` SET ?`, [data]);
    const [rows] = await pool.query(`SELECT * FROM \`${table}\` WHERE id=?`, [data.id]);
    res.status(201).json(safeRow(rows[0]));
  } catch (err) { console.error(err); res.status(500).json({ error: err.message }); }
});

app.put('/api/entities/:entity/:id', authMiddleware, checkEntityPermission('write'), async (req, res) => {
  const entityName = req.params.entity;
  const table = ENTITY_MAP[entityName];
  if (!table) return res.status(404).json({ error: 'Entite inconnue' });
  if (entityName === 'User') {
    return res.status(403).json({ error: 'Utilisez /api/users/:id pour modifier un utilisateur' });
  }
  if (table === 'concours_config' && req.body.quota_places !== undefined) {
    const [existingRows] = await pool.query('SELECT concours_id FROM concours_config WHERE id=?', [req.params.id]);
    const concoursId = req.body.concours_id || existingRows[0]?.concours_id;
    const err = await validateConcoursConfigQuota(concoursId, req.body.quota_places, req.params.id);
    if (err) return res.status(400).json({ error: err });
  }
  if (table === 'candidates' && req.body.salle_examen_id !== undefined && req.body.salle_examen_id !== null) {
    const [existingCandRows] = await pool.query('SELECT salle_examen_id FROM candidates WHERE id=?', [req.params.id]);
    // On ne revalide que si la salle change réellement (sinon un simple
    // re-save du même candidat déjà dans la salle serait bloqué à tort).
    if (existingCandRows[0]?.salle_examen_id !== req.body.salle_examen_id) {
      const err = await validateSalleCapacity(req.body.salle_examen_id, req.params.id);
      if (err) return res.status(409).json({ error: err });
    }
  }
  // Un rôle "user" ne peut modifier QUE son propre document candidat — et
  // même sur son propre document, il ne peut pas toucher aux champs réservés
  // au jury (statut_verification, commentaire_jury, verifie_par), sinon il
  // pourrait "auto-valider" son propre document.
  if (entityName === 'CandidatDocument' && req.user?.role === 'user') {
    const [ownRows] = await pool.query('SELECT candidate_email FROM candidat_document WHERE id=?', [req.params.id]);
    if (!ownRows.length) return res.status(404).json({ error: 'Non trouve' });
    if (!isOwnCandidateDocument(ownRows[0], req.user)) {
      return res.status(403).json({ error: "Vous ne pouvez modifier que vos propres documents." });
    }
  }
  const data = { ...req.body };
  delete data.id;
  // Un non-super_admin ne peut jamais s'auto-promouvoir via le CRUD générique
  if (data.role && req.user?.role !== 'super_admin') delete data.role;
  // Un rôle "user" ne peut pas réassigner son document à un autre email
  // (ce qui reviendrait à s'approprier — ou céder — un document candidat),
  // ni toucher aux champs de validation réservés au jury/admin.
  if (entityName === 'CandidatDocument' && req.user?.role === 'user') {
    delete data.candidate_email;
    delete data.statut_verification;
    delete data.commentaire_jury;
    delete data.verifie_par;
  }
  data.updated_date = new Date();
  if ((table === 'app_users' || table === 'super_admin_config') && data.password) {
    data.password_hash = await bcrypt.hash(data.password, 10);
    delete data.password;
  }
  // Sérialiser les tableaux/objets JSON avant UPDATE
  const JSON_COLS_PUT = ['priorite_mentions_ordre'];
  for (const col of JSON_COLS_PUT) {
    if (data[col] !== undefined && typeof data[col] !== 'string') {
      data[col] = JSON.stringify(data[col]);
    }
  }
  try {
    await pool.query(`UPDATE \`${table}\` SET ? WHERE id=?`, [data, req.params.id]);
    const [rows] = await pool.query(`SELECT * FROM \`${table}\` WHERE id=?`, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Non trouve' });
    res.json(safeRow(rows[0]));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/entities/:entity/:id', authMiddleware, checkEntityPermission('write'), async (req, res) => {
  const entityName = req.params.entity;
  const table = ENTITY_MAP[entityName];
  if (!table) return res.status(404).json({ error: 'Entite inconnue' });
  if (entityName === 'User') {
    return res.status(403).json({ error: 'Utilisez /api/users/:id pour supprimer un utilisateur' });
  }
  // Un rôle "user" ne peut supprimer QUE son propre document candidat.
  if (entityName === 'CandidatDocument' && req.user?.role === 'user') {
    const [ownRows] = await pool.query('SELECT candidate_email FROM candidat_document WHERE id=?', [req.params.id]);
    if (!ownRows.length) return res.status(404).json({ error: 'Non trouve' });
    if (!isOwnCandidateDocument(ownRows[0], req.user)) {
      return res.status(403).json({ error: "Vous ne pouvez supprimer que vos propres documents." });
    }
  }
  try { await pool.query(`DELETE FROM \`${table}\` WHERE id=?`, [req.params.id]); res.json({ success: true }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== UPLOAD + IMPORT BAC IA =====

const UPLOAD_DIR = process.env.UPLOAD_DIR || './uploads';
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const storage = multer.diskStorage({
  destination: UPLOAD_DIR,
  filename: (_r, f, cb) => cb(null, `${Date.now()}_${f.originalname}`),
});
const upload = multer({ storage, limits: { fileSize: 20 * 1024 * 1024 } });

app.post('/api/upload', authMiddleware, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Aucun fichier recu' });
  res.json({ file_url: `/api/uploads/${req.file.filename}`, filename: req.file.filename, original: req.file.originalname });
});
app.use('/api/uploads', express.static(UPLOAD_DIR));

// ─── Parsers natifs BAC Cameroun ─────────────────────────────────────────────

/**
 * Parser GCE A-Level — Format Crystal Reports GCE Board
 * Structure : "Passed in N Subjects:" suivi des noms, par centre
 */
function parseGCEAdvancedLevel(text) {
  const rows = [];
  let currentCentre = '';
  const lines = text.split('\n').map(l => l.trim()).filter(Boolean);

  const centreRegex  = /Centre No:\s*(\d+)\s+(.+)/i;
  const passedInRegex = /Passed in (\d+) Subjects?:/i;
  const candidatRegex = /^\((\d+)\)\s+(.+)$/;

  let currentSubjectCount = 0;
  let expectingNames = false;
  let pendingNumbers = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Détection centre (peut s'étendre sur 2 lignes)
    const cm = line.match(centreRegex);
    if (cm) {
      let centreName = cm[2].trim();
      if (i + 1 < lines.length && !lines[i + 1].match(/^(Regist|Passed|Centre|\(\d+\))/i)) {
        centreName += ' ' + lines[i + 1].trim();
        i++;
      }
      currentCentre = centreName.replace(/\s+/g, ' ').trim();
      expectingNames = false;
      pendingNumbers = [];
      continue;
    }

    // Ignorer lignes de stats / en-têtes
    if (/Results of Successful/i.test(line)) continue;
    if (/GCEB \d{4} Session/i.test(line)) continue;
    if (/^(Regist:|%\s*Passed|Passed\s*:)/i.test(line)) continue;
    if (/GENERAL CERTIFICATE OF EDUCATION/i.test(line)) continue;
    if (/^2025 RESULTS:/i.test(line)) continue;

    // Section "Passed in N Subjects:"
    const pm = line.match(passedInRegex);
    if (pm) {
      currentSubjectCount = parseInt(pm[1], 10);
      expectingNames = true;
      pendingNumbers = [];
      continue;
    }

    if (!expectingNames) continue;

    // Format "(N) NOM COMPLET" — cas avec nom immédiat
    const cm2 = line.match(candidatRegex);
    if (cm2) {
      const namePart = cm2[2].trim();
      if (namePart.length < 2) {
        // Nom absent sur cette ligne (format Crystal Reports 2 colonnes)
        pendingNumbers.push(parseInt(cm2[1], 10));
      } else {
        rows.push(buildGCERow(namePart, currentSubjectCount, currentCentre));
      }
      continue;
    }

    // Nom pur correspondant aux pendingNumbers accumulés (colonnes séparées)
    if (pendingNumbers.length > 0) {
      rows.push(buildGCERow(line, currentSubjectCount, currentCentre));
      pendingNumbers.shift();
      continue;
    }

    // Nom sans numéro (tout caps, >5 chars)
    if (/^[A-Z][A-Z\s\-\.\,']+$/.test(line) && line.length > 5) {
      rows.push(buildGCERow(line, currentSubjectCount, currentCentre));
    }
  }

  return rows;
}

function buildGCERow(fullName, subjectCount, centre) {
  let mention = 'passable';
  if (subjectCount >= 5)      mention = 'tres_bien';
  else if (subjectCount === 4) mention = 'bien';
  else if (subjectCount === 3) mention = 'assez_bien';

  const parts = fullName.trim().replace(/\s+/g, ' ').split(' ');
  return {
    full_name:      fullName.trim().replace(/\s+/g, ' '),
    nom:            parts[0] || '',
    prenom:         parts.slice(1).join(' ') || '',
    numero_bac:     '',
    resultat:       'pass',
    mention,
    serie:          'A-LEVEL',
    moyenne:        null,
    centre:         centre || '',
    annee:          '2025',
    subjects_count: subjectCount,
  };
}

/**
 * Parser ESG/IBTE — Résultats BAC Technique Cameroun (séries F1-F7, IBTE, TMG)
 * Source: MINESEC / Scribd — format tableau ou liste
 */
function parseESGIBTE(text) {
  const rows = [];
  const lines = text.split('\n').map(l => l.trim()).filter(Boolean);

  for (const line of lines) {
    // Skip en-têtes
    if (/matricule|numéro|résultat|mention|série|nom|prenom/i.test(line) && line.length < 120) continue;
    if (/résultats.*bac|examen|minesec|ibte|esg|2024|2025/i.test(line) && line.length < 100) continue;
    if (/^[-|+\s=]{3,}$/.test(line)) continue;

    // Format tabulaire avec pipe
    if (line.includes('|')) {
      const parts = line.split('|').map(p => p.trim()).filter(Boolean);
      if (parts.length >= 3) {
        const row = parseESGIBTETableLine(parts);
        if (row) rows.push({ ...row, source_format: 'esg_ibte' });
      }
      continue;
    }

    // Format liste : MATRICULE NOM PRENOM ... SERIE MENTION RESULTAT
    const matriculeMatch = line.match(/^([A-Z0-9\-]{4,15})\s+(.+)/);
    if (matriculeMatch) {
      const mat  = matriculeMatch[1];
      const rest = matriculeMatch[2];
      const mentionM  = rest.match(/\b(très bien|tres bien|assez bien|bien|passable)\b/i);
      const serieM    = rest.match(/\b(F[1-9]|TMG|IBTE|G[1-3]|ESG|TI)\b/i);
      const resultatM = rest.match(/\b(admis|reçu|reussi|ajourné|echoue|fail|pass)\b/i);
      const moyM      = rest.match(/\b(\d{1,2}[,\.]\d{1,2})\b/);

      const nom = rest
        .replace(/(très bien|tres bien|assez bien|bien|passable|admis|ajourné|échoué|F[1-9]|TMG|IBTE|G[1-3]|\d{1,2}[,\.]\d{1,2})/gi, '')
        .trim();

      rows.push({
        numero_bac: mat,
        full_name:  nom,
        nom:        nom.split(' ')[0] || '',
        prenom:     nom.split(' ').slice(1).join(' ') || '',
        resultat:   resultatM ? resultatM[1] : 'pass',
        mention:    mentionM  ? mentionM[1]  : '',
        serie:      serieM    ? serieM[1].toUpperCase() : '',
        moyenne:    moyM      ? parseFloat(moyM[1].replace(',', '.')) : null,
        centre:     '',
        annee:      '2024',
        source_format: 'esg_ibte',
      });
    }
  }

  return rows;
}

function parseESGIBTETableLine(parts) {
  let matricule = '', nom = '', prenom = '', serie = '', mention = '', resultat = '', moyenne = null;

  for (const p of parts) {
    if (/^[A-Z0-9\-]{4,15}$/.test(p) && !matricule)                     { matricule = p; continue; }
    if (/^\d{1,2}[,\.]\d{1,2}$/.test(p) && !moyenne)                    { moyenne = parseFloat(p.replace(',', '.')); continue; }
    if (/\b(F[1-9]|TMG|IBTE|G[1-3]|ESG|TI)\b/i.test(p) && !serie)      { serie = p.match(/F[1-9]|TMG|IBTE|G[1-3]|ESG|TI/i)?.[0]?.toUpperCase() || ''; continue; }
    if (/très bien|tres bien|assez bien|bien|passable/i.test(p))          { mention = p; continue; }
    if (/admis|reçu|reussi|ajourné|echoue|fail|pass/i.test(p))           { resultat = p; continue; }
    if (!nom)   { nom   = p; continue; }
    if (!prenom) { prenom = p; }
  }

  if (!nom && !matricule) return null;
  return {
    numero_bac: matricule,
    nom, prenom,
    full_name:  `${nom} ${prenom}`.trim(),
    resultat:   resultat || 'pass',
    mention,
    serie,
    moyenne,
    centre:     '',
    annee:      '2024',
  };
}

/**
 * Détection automatique du format et parsing natif.
 * Retourne null si format non reconnu (→ fallback IA).
 */
/**
 * Parser MINESEC — Bordereau des Résultats BAC Francophone
 * En-tête : SESSION · EXAMEN · REGION · SOUS-CENTRE · CODE · JURY · SERIE
 * Tableau  : N° | NOMS ET PRÉNOMS | NÉ(E) LE | MENTION | MATRICULE
 * Séries   : A, B, C, D, E, F1-F9, G1-G3, TMG, TI, BAA4ALL, etc.
 */
function parseMINESECBordereau(text) {
  const rows  = [];
  const lines = text.split('\n').map(l => l.trim()).filter(Boolean);

  // ── Métadonnées de l'en-tête ──────────────────────────────────────────────
  let session = '', serie = '', sousCentre = '', region = '', jury = '';

  for (const line of lines) {
    const sessionM     = line.match(/SESSION\s*[:\-]?\s*(\d{4})/i);
    if (sessionM) session = sessionM[1];

    const serieM       = line.match(/S[ÉE]RIE\s*[:\-]?\s*([A-Z0-9]+(?:\s+[A-Z0-9]+)*)/i);
    if (serieM) serie  = serieM[1].trim();

    const sousCentreM  = line.match(/SOUS[-\s]CENTRE\s*[:\-]?\s*(.+?)(?:\s{2,}|CODE|$)/i);
    if (sousCentreM) sousCentre = sousCentreM[1].trim();

    const regionM      = line.match(/R[ÉE]GION\s*[:\-]?\s*([A-ZÉÀÈÊË\s]+)/i);
    if (regionM) region = regionM[1].trim();

    const juryM        = line.match(/JURY\s*[:\-]?\s*(\d+)/i);
    if (juryM) jury    = juryM[1];
  }

  const annee    = session || new Date().getFullYear().toString();
  const centre   = [sousCentre, region, jury ? `Jury ${jury}` : ''].filter(Boolean).join(' — ');

  // Normalisation série : garder BAA4ALL tel quel, sinon extraire la lettre
  let serieNorm = serie.toUpperCase().trim();
  if (!/^BAA/i.test(serieNorm)) {
    const sm = serieNorm.match(/\b([A-Z]{1,3}\d?)\b/);
    if (sm) serieNorm = sm[1];
  }

  // ── Parsing des lignes candidats ─────────────────────────────────────────
  // Format pdf-parse : "1 AGOA VERANE JAMYLA 15-05-2007 ASSEZ BIEN 63821189023"
  // Le matricule MINESEC = 11 chiffres terminant par l'année (…2023, …2024)

  const MENTION_RE   = /(TRES BIEN|TRÈS BIEN|ASSEZ BIEN|BIEN|PASSABLE)/i;
  const DATE_RE      = /\b(\d{2}[-\/]\d{2}[-\/]\d{4})\b/;
  const MATRICULE_RE = /\b(\d{10,12})\b/;
  const NUM_START_RE = /^\d{1,4}\s+/;

  // Lignes à ignorer (en-têtes, séparateurs, texte introductif)
  const SKIP_RE = /^(N[°o]?$|NOMS?|PR[ÉE]NOMS?|N[ÉE]\(?E?\)?|MENTION|MATRICULE|SESSION|EXAMEN|SOUS[-\s]CENTRE|JURY|S[ÉE]RIE|R[ÉE]GION|CODE|Sont d[eé]clar[eé]s|BORDEREAU|BACCALAUR|CAMEROUN|MINESEC)/i;

  for (const line of lines) {
    if (SKIP_RE.test(line))       continue;
    if (/^[-=_|\s]+$/.test(line)) continue;
    if (line.length < 10)         continue;

    // Doit contenir un matricule (signal clé d'une ligne candidat)
    const matM = line.match(MATRICULE_RE);
    if (!matM) continue;

    const matricule    = matM[1];
    const menM         = line.match(MENTION_RE);
    const mention      = menM ? menM[1].trim() : '';
    const dateM        = line.match(DATE_RE);
    const dateNaissance = dateM ? dateM[1] : '';

    // Nom brut = ce qui reste après retrait du numéro, date, mention, matricule
    let nomBrut = line
      .replace(NUM_START_RE, '')
      .replace(DATE_RE,      '')
      .replace(MENTION_RE,   '')
      .replace(MATRICULE_RE, '')
      .replace(/\s{2,}/g, ' ')
      .trim()
      .replace(/^\d+\s*/, ''); // résidu numérique

    if (!nomBrut || nomBrut.length < 3) continue;

    // Séparation NOM / PRÉNOM (convention MINESEC : tout en majuscules)
    // Heuristique : si ≥3 mots → 2 premiers = nom de famille, reste = prénoms
    const parts = nomBrut.split(/\s+/);
    let nomFam = '', prenom = '';
    if (parts.length >= 3) {
      nomFam = parts.slice(0, 2).join(' ');
      prenom = parts.slice(2).join(' ');
    } else if (parts.length === 2) {
      nomFam = parts[0];
      prenom = parts[1];
    } else {
      nomFam = nomBrut;
    }

    rows.push({
      numero_bac:     matricule,
      matricule,
      nom:            nomFam,
      prenom,
      full_name:      nomBrut,
      date_naissance: dateNaissance,
      resultat:       'pass',   // seuls les admis figurent dans le bordereau
      mention,
      serie:          serieNorm,
      moyenne:        null,     // bordereau MINESEC n'indique pas la moyenne
      centre,
      annee,
      source_format:  'minesec_bordereau',
    });
  }

  return rows;
}

function detectAndParseNative(text) {
  // GCE A-Level (GCE Board anglophone)
  if (/GENERAL CERTIFICATE OF EDUCATION|Passed in \d+ Subjects?/i.test(text)) {
    return { format_detected: 'GCE Advanced Level', rows: parseGCEAdvancedLevel(text) };
  }
  // MINESEC Bordereau des Résultats (BAC francophone toutes séries)
  if (/BORDEREAU\s+DES\s+R[ÉE]SULTATS?|BACCALAUR[ÉE]AT\s+DE\s+L.ENSEIGNEMENT/i.test(text) ||
      (/MENTION/i.test(text) && /MATRICULE/i.test(text) && /NOMS?\s+ET\s+PR[ÉE]NOMS?/i.test(text))) {
    return { format_detected: 'MINESEC Bordereau', rows: parseMINESECBordereau(text) };
  }
  // ESG/IBTE (BAC technique)
  if (/\b(F[1-7]|IBTE|TMG|ESG)\b/i.test(text) && /\b(admis|ajourné|mention)\b/i.test(text)) {
    return { format_detected: 'ESG/IBTE Technique', rows: parseESGIBTE(text) };
  }
  return null;
}

// ─── Route POST /api/ai/parse-bac ────────────────────────────────────────────
app.post('/api/ai/parse-bac', authMiddleware, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Aucun fichier recu' });
  const filePath = req.file.path;
  const ext = path.extname(req.file.originalname).toLowerCase();
  try {
    let rows = [];
    let format_detected = ext.replace('.', '');

    // ── Étape 1 : extraction du texte brut ──
    let text = '';
    if (ext === '.pdf') {
      const data = await require('pdf-parse')(fs.readFileSync(filePath));
      if (!data.text?.trim()) throw new Error('PDF vide ou scanné (image). Convertissez-le en CSV/Excel d\'abord.');
      text = data.text;
    } else if (ext === '.docx' || ext === '.doc') {
      const r = await require('mammoth').extractRawText({ path: filePath });
      text = r.value;
    } else {
      throw new Error(`Format ${ext} non supporté ici`);
    }

    // ── Étape 2 : essai parsers natifs (GCE A-Level, ESG/IBTE) ──
    const native = detectAndParseNative(text);
    if (native && native.rows.length > 0) {
      console.log(`[parse-bac] Format natif détecté : ${native.format_detected} — ${native.rows.length} lignes`);
      return res.json({ rows: native.rows, count: native.rows.length, format_detected: native.format_detected });
    }

    // ── Étape 3 : fallback analyse IA (BAC francophone MINESEC ou autre) ──
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey || apiKey.startsWith('sk-ant-REMPLACEZ')) {
      // Si pas de clé IA et pas de parser natif → erreur explicite
      throw new Error(
        'Format non reconnu automatiquement et ANTHROPIC_API_KEY non configurée dans backend/.env. ' +
        'Pour les PDF GCE A-Level et ESG/IBTE, le parsing natif est utilisé. Pour les autres formats, configurez la clé API Anthropic.'
      );
    }

    const Anthropic = require('@anthropic-ai/sdk');
    const client    = new Anthropic({ apiKey });
    const truncated = text.length > 30000 ? text.slice(0, 30000) : text;

    const response = await client.messages.create({
      model: 'claude-sonnet-4-6', max_tokens: 4096,
      system: [
        'Tu es un expert en résultats du Baccalauréat camerounais (MINESEC).',
        'Extrais TOUS les candidats du bordereau fourni.',
        'Réponds UNIQUEMENT en JSON valide, sans markdown, sans texte avant ou après.',
        'Chaque candidat : { "numero_bac": "", "nom": "", "prenom": "", "full_name": "", "resultat": "pass|fail", "mention": "", "serie": "", "moyenne": null, "centre": "", "annee": "" }',
        'Si un champ est absent, mets null ou chaîne vide.',
        '"resultat" = "pass" si admis/reçu/réussi, "fail" si ajourné/échoué.',
      ].join(' '),
      messages: [{
        role: 'user',
        content: `Extrais tous les candidats. Réponds UNIQUEMENT avec {"rows":[...]}.\n\nTEXTE:\n${truncated}`,
      }],
    });

    const raw    = response.content.find(b => b.type === 'text')?.text || '{}';
    const parsed = JSON.parse(raw.replace(/```json|```/g, '').trim());
    rows = Array.isArray(parsed.rows) ? parsed.rows : [];
    format_detected = 'BAC Francophone (IA)';

    console.log(`[parse-bac] Extraction IA : ${rows.length} candidat(s)`);
    res.json({ rows, count: rows.length, format_detected });

  } catch (err) {
    console.error('[parse-bac]', err.message);
    res.status(500).json({ error: err.message });
  } finally {
    try { fs.unlinkSync(filePath); } catch {}
  }
});


// ===== JURY CONFIG (PIN saisie notes) =====

// GET /api/jury-config — vérifier si un PIN est configuré (sans exposer le hash)
app.get('/api/jury-config', authMiddleware, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, updated_date, updated_by FROM jury_config LIMIT 1');
    res.json({ configured: rows.length > 0, ...(rows[0] || {}) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/jury-config/verify — vérifier le PIN entré (retourne true/false)
app.post('/api/jury-config/verify', async (req, res) => {
  const { pin } = req.body;
  if (!pin) return res.status(400).json({ valid: false });
  try {
    const [rows] = await pool.query('SELECT pin_hash FROM jury_config LIMIT 1');
    if (!rows.length) {
      // Aucun PIN configure -> acces refuse tant qu'un super_admin n'en a pas defini un
      return res.json({ valid: false, error: 'Aucun PIN jury configure. Contactez le Super Admin.' });
    }
    const valid = await bcrypt.compare(pin, rows[0].pin_hash);
    res.json({ valid });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// PUT /api/jury-config — modifier le PIN (super_admin uniquement)
app.put('/api/jury-config', authMiddleware, requireSuperAdmin, async (req, res) => {
  const { pin, currentPin } = req.body;
  if (!pin || pin.length < 4) return res.status(400).json({ error: 'Le PIN doit faire au moins 4 caractères' });
  try {
    const [rows] = await pool.query('SELECT * FROM jury_config LIMIT 1');
    if (rows.length > 0 && currentPin) {
      const ok = await bcrypt.compare(currentPin, rows[0].pin_hash);
      if (!ok) return res.status(400).json({ error: 'PIN actuel incorrect' });
    }
    const hash = await bcrypt.hash(pin, 10);
    if (rows.length > 0) {
      await pool.query('UPDATE jury_config SET pin_hash=?, updated_date=NOW(), updated_by=? WHERE id=?',
        [hash, req.user.email, rows[0].id]);
    } else {
      await pool.query('INSERT INTO jury_config (id, pin_hash, updated_by) VALUES (UUID(), ?, ?)',
        [hash, req.user.email]);
    }
    res.json({ success: true, message: 'PIN jury mis à jour' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/email/send', authMiddleware, async (req, res) => {
  console.info(`[email] → ${req.body.to} | ${req.body.subject}`);
  res.json({ success: true, simulated: true });
});

app.get('/api/health', async (_req, res) => {
  try { await pool.query('SELECT 1'); res.json({ status: 'ok', db: 'connected', version: '2.0' }); }
  catch { res.status(500).json({ status: 'error', db: 'disconnected' }); }
});

app.listen(PORT, () => {
  console.log(`ConcoursPro API v2 -> http://localhost:${PORT}`);
});
