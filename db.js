import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'qualidade.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS resposta (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tipo TEXT NOT NULL,
    app_origem TEXT NOT NULL DEFAULT 'gestao-qualidade',
    fonte_id TEXT,
    submitted_at TEXT NOT NULL,
    inserido_por TEXT,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE UNIQUE INDEX IF NOT EXISTS idx_resposta_fonte
    ON resposta(tipo, app_origem, fonte_id) WHERE fonte_id IS NOT NULL;
  CREATE INDEX IF NOT EXISTS idx_resposta_tipo_data ON resposta(tipo, submitted_at);
`);

// Migração única: JSONs legados (gravação efêmera antiga) → banco
const LEGADOS = {
  'respostas-geral.json': 'geral',
  'respostas-pdvs.json': 'pdvs',
  'respostas-eventos.json': 'eventos',
};
for (const [arquivo, tipo] of Object.entries(LEGADOS)) {
  const p = path.join(DATA_DIR, arquivo);
  if (!fs.existsSync(p)) continue;
  try {
    const arr = JSON.parse(fs.readFileSync(p, 'utf8'));
    const ins = db.prepare(`
      INSERT OR IGNORE INTO resposta (tipo, app_origem, fonte_id, submitted_at, inserido_por, payload)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    db.transaction(() => {
      for (const r of arr) {
        ins.run(
          r.tipo || tipo,
          'gestao-qualidade',
          r.id != null ? String(r.id) : null,
          r.submitted_at || new Date().toISOString(),
          r.inserido_por || null,
          JSON.stringify(r)
        );
      }
    })();
    fs.renameSync(p, p + '.migrado');
    console.log(`[db] migrado ${arquivo}: ${arr.length} registros`);
  } catch (e) {
    console.error(`[db] falha ao migrar ${arquivo}:`, e.message);
  }
}

export function inserirResposta({ tipo, app_origem = 'gestao-qualidade', fonte_id = null, submitted_at, inserido_por = null, payload, ignorarDuplicado = false }) {
  const stmt = db.prepare(`
    INSERT ${ignorarDuplicado ? 'OR IGNORE ' : ''}INTO resposta
      (tipo, app_origem, fonte_id, submitted_at, inserido_por, payload)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  const info = stmt.run(
    tipo,
    app_origem,
    fonte_id != null ? String(fonte_id) : null,
    submitted_at || new Date().toISOString(),
    inserido_por,
    JSON.stringify(payload)
  );
  return { id: info.lastInsertRowid, duplicado: info.changes === 0 };
}

export function contarRespostas() {
  return db.prepare(`SELECT tipo, COUNT(*) AS total FROM resposta GROUP BY tipo`).all();
}

export function listarRespostas({ tipo = null, from = null, to = null, q = null, page = 1, limit = 20 } = {}) {
  const conds = [], args = [];
  if (tipo) { conds.push('tipo = ?'); args.push(tipo); }
  if (from) { conds.push("substr(submitted_at,1,10) >= ?"); args.push(from); }
  if (to)   { conds.push("substr(submitted_at,1,10) <= ?"); args.push(to); }
  if (q)    { conds.push("(payload LIKE ? OR inserido_por LIKE ?)"); args.push(`%${q}%`, `%${q}%`); }
  const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
  const total = db.prepare(`SELECT COUNT(*) AS n FROM resposta ${where}`).get(...args).n;
  const offset = (page - 1) * limit;
  const rows = db.prepare(`SELECT id, tipo, submitted_at, inserido_por, payload FROM resposta ${where} ORDER BY submitted_at DESC, id DESC LIMIT ? OFFSET ?`).all(...args, limit, offset);
  return {
    total,
    items: rows.map(r => {
      let p = {};
      try { p = JSON.parse(r.payload); } catch {}
      return {
        id: r.id,
        tipo: r.tipo,
        date: r.submitted_at.slice(0, 10).split('-').reverse().join('/'),
        nome: p.nome || p.empresa || '—',
        email: p.email || p.empresa || '—',
        tipo_pesquisa: p.tipo_pesquisa || r.tipo,
        inserido_por: r.inserido_por || '—',
      };
    }),
  };
}

export default db;
