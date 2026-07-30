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
  CREATE TABLE IF NOT EXISTS gq_metas (
    tipo TEXT PRIMARY KEY,
    valor INTEGER NOT NULL DEFAULT 0,
    atualizado_por TEXT,
    atualizado_em TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS gq_admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    nivel TEXT NOT NULL DEFAULT 'operador',
    criado_por TEXT,
    criado_em TEXT NOT NULL DEFAULT (datetime('now'))
  );
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
  const mesAtual = new Date().toISOString().slice(0, 7);
  const totais = db.prepare(`SELECT tipo, COUNT(*) AS total FROM resposta GROUP BY tipo`).all();
  const mes    = db.prepare(`SELECT tipo, COUNT(*) AS total FROM resposta WHERE substr(submitted_at,1,7) = ? GROUP BY tipo`).all(mesAtual);
  const mesSub = db.prepare(`
    SELECT JSON_EXTRACT(payload,'$.tipo_pesquisa') AS subtipo, COUNT(*) AS total
    FROM resposta WHERE tipo='eventos' AND substr(submitted_at,1,7)=? GROUP BY subtipo
  `).all(mesAtual);
  const totaisSub = db.prepare(`
    SELECT JSON_EXTRACT(payload,'$.tipo_pesquisa') AS subtipo, COUNT(*) AS total
    FROM resposta WHERE tipo='eventos' GROUP BY subtipo
  `).all();
  return { totais, mes, mesSub, totaisSub };
}

const _LSCORE = { otimo: 9, bom: 3, regular: 1, ruim: 0, muitobom: 9, amelhorar: 0 };
const _LRATING_KEYS = {
  geral: ['rec_checkinout','rec_recepcao','rec_concierge','rec_mensageiros','rec_guestservice','rec_fitness',
          'apto_governanca','apto_limpeza','apto_enxoval','apto_conforto','apto_banheiro','apto_equipamentos','apto_manutencao','apto_wifi',
          'cafe_qualidade','cafe_variedade','cafe_cortesia','cafe_apresentacao',
          'qto_qualidade','qto_variedade','qto_cortesia','qto_apresentacao','qto_cafe'],
  pdvs: ['alim_qualidade','alim_variedade','alim_cortesia','alim_apresentacao',
         'inst_infraestrutura','inst_limpeza','inst_conforto','inst_wifi',
         'ger_experiencia','ger_expectativas'],
  'eventos-cliente': ['ev_servicos','ev_equipamentos','com_cortesia','com_receptividade','com_qualidade','com_presteza',
                      'op_agilidade','op_desenvolvimento','op_pontualidade','op_expectativa',
                      'ab_apresentacao','ab_qualidade','ab_variedade',
                      'inf_conforto','inf_temperatura','inf_iluminacao','inf_limpeza','inf_acesso','inf_internet','inf_manobristas','inf_allug'],
  'eventos-cerimonialista': ['ev_servicos','ev_equipamentos','com_cortesia','com_receptividade','com_qualidade','com_presteza',
                             'op_agilidade','op_desenvolvimento','op_pontualidade','op_expectativa',
                             'ab_apresentacao','ab_qualidade','ab_variedade','ab_quantidade','ab_horario'],
  'eventos-corporativos': ['ev_servicos','ev_equipamentos','com_cortesia','com_receptividade','com_qualidade',
                           'op_agilidade','op_desenvolvimento','op_pontualidade','op_expectativa',
                           'ab_apresentacao','ab_qualidade','ab_fidelidade',
                           'inf_conforto','inf_temperatura','inf_iluminacao','inf_limpeza','inf_acesso',
                           'wifi_apresentacao','wifi_facilidade','wifi_sinal','wifi_velocidade',
                           'ter_manobristas','ter_allug','ter_celular'],
  spa: ['servicos_expectativa','servicos_explicacao','servicos_atitude','servicos_tecnica',
        'instalacoes_conforto','instalacoes_organizacao','instalacoes_conveniencia'],
};

function computeLocalScore(tipo, payload) {
  const tipoPesquisa = (payload.tipo_pesquisa || tipo || '').replace('-granclass', '');
  const keys = _LRATING_KEYS[tipoPesquisa] || _LRATING_KEYS[tipo];
  if (!keys) return null;
  let sum = 0, count = 0;
  for (const k of keys) {
    const val = payload[k];
    if (val != null && val in _LSCORE) { sum += _LSCORE[val]; count++; }
  }
  if (count === 0) return null;
  return Math.round(sum / (count * 9) * 100);
}

export function listarRespostas({ tipo = null, subtipo = null, from = null, to = null, q = null, page = 1, limit = 20 } = {}) {
  const conds = [], args = [];
  if (tipo) { conds.push('tipo = ?'); args.push(tipo); }
  if (subtipo === 'eventos-sociais') {
    conds.push("(JSON_EXTRACT(payload,'$.tipo_pesquisa')='eventos-cliente' OR JSON_EXTRACT(payload,'$.tipo_pesquisa')='eventos-cerimonialista')");
  } else if (subtipo) {
    conds.push("JSON_EXTRACT(payload,'$.tipo_pesquisa')=?");
    args.push(subtipo);
  }
  if (from) { conds.push("substr(submitted_at,1,10) >= ?"); args.push(from); }
  if (to)   { conds.push("substr(submitted_at,1,10) <= ?"); args.push(to); }
  if (q)    { conds.push("(payload LIKE ? OR inserido_por LIKE ?)"); args.push(`%${q}%`, `%${q}%`); }
  const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
  const total = db.prepare(`SELECT COUNT(*) AS n FROM resposta ${where}`).get(...args).n;
  const offset = (page - 1) * limit;
  const rows = db.prepare(`SELECT id, tipo, app_origem, submitted_at, inserido_por, payload FROM resposta ${where} ORDER BY submitted_at DESC, id DESC LIMIT ? OFFSET ?`).all(...args, limit, offset);
  return {
    total,
    items: rows.map(r => {
      let p = {};
      try { p = JSON.parse(r.payload); } catch {}
      const score = computeLocalScore(r.tipo, p);
      return {
        id: r.id,
        tipo: r.tipo,
        app_origem: r.app_origem,
        date: r.submitted_at.slice(0, 10).split('-').reverse().join('/'),
        nome: p.nome || p.empresa || '—',
        email: p.email || p.empresa || '—',
        tipo_pesquisa: p.tipo_pesquisa || r.tipo,
        inserido_por: r.inserido_por || '—',
        media: score != null ? `${score}%` : null,
      };
    }),
  };
}

export function buscarResposta(id) {
  const row = db.prepare('SELECT id, tipo, app_origem, submitted_at, inserido_por, payload FROM resposta WHERE id = ?').get(id);
  if (!row) return null;
  let payload = {};
  try { payload = JSON.parse(row.payload); } catch {}
  return { id: row.id, tipo: row.tipo, app_origem: row.app_origem, submitted_at: row.submitted_at, inserido_por: row.inserido_por, payload };
}

export function atualizarResposta(id, payload) {
  const result = db.prepare('UPDATE resposta SET payload = ? WHERE id = ?').run(JSON.stringify(payload), id);
  return result.changes > 0;
}

export function contarPorUrna({ mes = null } = {}) {
  const where = mes ? 'WHERE substr(submitted_at,1,7) = ?' : '';
  const args = mes ? [mes] : [];
  return db.prepare(`
    SELECT JSON_EXTRACT(payload,'$.urna_id') AS urna_id, COUNT(*) AS total
    FROM resposta ${where}
    GROUP BY JSON_EXTRACT(payload,'$.urna_id')
    ORDER BY total DESC
  `).all(...args);
}

export function contarSpaSite({ mes = null } = {}) {
  const where = mes ? "WHERE app_origem='spa' AND substr(submitted_at,1,7) = ?" : "WHERE app_origem='spa'";
  const args = mes ? [mes] : [];
  return db.prepare(`SELECT COUNT(*) AS total FROM resposta ${where}`).get(...args).total;
}

export function listarMetas() {
  return db.prepare('SELECT tipo, valor FROM gq_metas').all();
}

export function upsertMetas(entries, por) {
  const stmt = db.prepare(
    `INSERT INTO gq_metas (tipo, valor, atualizado_por) VALUES (?, ?, ?) ON CONFLICT(tipo) DO UPDATE SET valor=excluded.valor, atualizado_por=excluded.atualizado_por, atualizado_em=datetime('now')`
  );
  db.transaction(() => { for (const { tipo, valor } of entries) stmt.run(tipo, Number(valor) || 0, por || null); })();
}

export function listarAdmins() {
  return db.prepare('SELECT id, email, nivel, criado_por, criado_em FROM gq_admins ORDER BY criado_em DESC').all();
}

export function upsertAdmin(email, nivel, criado_por) {
  return db.prepare(
    'INSERT INTO gq_admins (email, nivel, criado_por) VALUES (?, ?, ?) ON CONFLICT(email) DO UPDATE SET nivel=excluded.nivel, criado_por=excluded.criado_por'
  ).run(email.trim().toLowerCase(), nivel, criado_por || null);
}

export function removerAdmin(email) {
  return db.prepare('DELETE FROM gq_admins WHERE lower(email) = lower(?)').run(email);
}

export function buscarNivelAdmin(email) {
  return db.prepare('SELECT nivel FROM gq_admins WHERE lower(email) = lower(?)').get(email);
}

export default db;

