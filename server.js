import express from 'express';
import jwt from 'jsonwebtoken';
import path from 'path';
import { fileURLToPath } from 'url';
import { inserirResposta, listarRespostas, contarRespostas, buscarResposta, atualizarResposta, contarPorUrna, contarSpaSite, listarMetas, upsertMetas, listarAdmins, upsertAdmin, removerAdmin, buscarNivelAdmin } from './db.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;
const PESQUISA_URL = (process.env.PESQUISA_URL || 'https://pesquisa-satisfacao.fly.dev').replace(/\/$/, '');
const SSO_SECRET = process.env.SSO_SECRET;
const JWT_SECRET = process.env.JWT_SECRET;
const COOKIE = 'gq_sess';
const FETCH_TIMEOUT = 10000;
const GQ_CACHE_TTL = 2 * 60 * 1000; // 2 minutos
const _gqCache = new Map(); // cacheKey → { data, ts }

if (!SSO_SECRET) console.warn('[WARN] SSO_SECRET não configurado');
if (!JWT_SECRET) console.warn('[WARN] JWT_SECRET não configurado');

app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));

// Cabeçalhos de segurança HTTP
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

function getCookie(req, name) {
  const h = req.headers.cookie || '';
  const m = h.split(';').find(c => c.trim().startsWith(name + '='));
  return m ? decodeURIComponent(m.trim().slice(name.length + 1)) : null;
}

function setCookie(res, val) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.appendHeader('Set-Cookie', `${COOKIE}=${encodeURIComponent(val)}; HttpOnly; SameSite=Lax; Max-Age=28800; Path=/${secure}`);
}

function clearCookie(res) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.appendHeader('Set-Cookie', `${COOKIE}=; Max-Age=0; Path=/; HttpOnly${secure}`);
}

function requireSession(req, res, next) {
  const tok = getCookie(req, COOKIE);
  if (!tok) {
    if (req.path.startsWith('/api/')) return res.status(401).json({ ok: false, error: 'Não autenticado' });
    return res.redirect('/acesso-hub.html');
  }
  try {
    jwt.verify(tok, JWT_SECRET, { algorithms: ['HS256'] });
  } catch {
    clearCookie(res);
    if (req.path.startsWith('/api/')) return res.status(401).json({ ok: false, error: 'Sessão expirada' });
    return res.redirect('/acesso-hub.html');
  }
  req.gqToken = tok;
  next();
}

function requireMaster(req, res, next) {
  const tok = getCookie(req, COOKIE);
  if (!tok) return res.status(401).json({ ok: false, error: 'Não autenticado' });
  let payload;
  try { payload = jwt.verify(tok, JWT_SECRET, { algorithms: ['HS256'] }); }
  catch { return res.status(401).json({ ok: false, error: 'Sessão expirada' }); }
  if (payload.role !== 'master') return res.status(403).json({ ok: false, error: 'Acesso negado' });
  req.gqToken = tok;
  req.gqUser = payload;
  next();
}

function fetchWithTimeout(url, opts) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT);
  return fetch(url, { ...opts, signal: ctrl.signal }).finally(() => clearTimeout(timer));
}

// Health
app.get('/api/health', (_req, res) => res.json({ ok: true }));

// SSO — Hub redireciona para <url>/sso?sso_token=...
app.get('/sso', (req, res) => {
  const { sso_token, next: nextPath, theme } = req.query;
  if (!sso_token) return res.redirect('/acesso-hub.html');
  try {
    const payload = jwt.verify(sso_token, SSO_SECRET, { algorithms: ['HS256'] });
    const email = (payload.email || '').trim().toLowerCase();
    // A GQ SEGUE a autorizacao do Hub: quem o Hub libera para o sistema
    // 'gestao-de-qualidade' (o card do portal) pode entrar. Assim, ver o card e
    // conseguir abrir a GQ usam a MESMA fonte de verdade (sem loop de acesso).
    // O `role` abaixo define apenas a capacidade no proxy da Pesquisa
    // (master/satisfacao escrevem; admin e leitura).
    const SPA_ADMIN_EMAILS = ['richard@granmarquise.com.br', 'suporte.ti@granmarquise.com.br', 'estagio.ti@granmarquise.com.br'];
    // Papel do PROPRIO card 'gestao-de-qualidade' na aba Liberacao do Hub —
    // antes so o slug da Pesquisa era lido e a Liberacao da GQ nao tinha efeito.
    const roleGQ = payload.site_roles && payload.site_roles['gestao-de-qualidade'];
    const adminGQ = Array.isArray(payload.sites_admin) && payload.sites_admin.includes('gestao-de-qualidade');
    // Legado: papeis da Pesquisa continuam valendo aqui (nao remover — ha
    // contas que dependem disso desde antes da Liberacao propria da GQ).
    const siteRole = payload.site_roles && payload.site_roles['pesquisa-satisfacao'];
    const sistemas = Array.isArray(payload.sistemas) ? payload.sistemas : null;
    const autorizadoPeloHub = sistemas ? sistemas.includes('gestao-de-qualidade') : false;
    // O MAIOR papel entre todas as fontes vence (master > satisfacao > admin).
    // Cadeia if/else rebaixava: quem tinha 'satisfacao' via Pesquisa E 'admin'
    // via card da GQ cairia para admin (leitura) dependendo da ordem dos galhos.
    const RANK = { master: 3, satisfacao: 2, admin: 1 };
    const candidatos = [];
    if (SPA_ADMIN_EMAILS.includes(email) || payload.is_master) candidatos.push('master'); // TI / master do Hub
    // Liberacao do card da GQ: quem o admin do Hub coloca la espera as "coisas
    // de admin" — e aqui TODA a gestao (aba Admin, configuracoes, metas) e
    // gated por 'master'; o papel local 'admin' e so leitura. Por isso o papel
    // 'admin' gravado pela aba (o unico que a UI do Hub grava) vira 'master'.
    // 'satisfacao' explicito (via S2S) continua sendo o nivel intermediario.
    if (roleGQ === 'master' || roleGQ === 'admin') candidatos.push('master');
    else if (roleGQ === 'satisfacao') candidatos.push('satisfacao');
    else if (adminGQ) candidatos.push('master');
    if (siteRole === 'satisfacao' || siteRole === 'admin') candidatos.push(siteRole);     // legado via Pesquisa
    if (Array.isArray(payload.sites_admin) && payload.sites_admin.includes('pesquisa-satisfacao')) candidatos.push('admin');
    if (autorizadoPeloHub || payload.tipo === 'admin') candidatos.push('admin');          // liberado pelo Hub -> leitura
    let role = 'user';
    for (const c of candidatos) if ((RANK[c] || 0) > (RANK[role] || 0)) role = c;
    // Tabela local gq_admins sobrescreve nível para não-masters
    if (role !== 'master') {
      const adminEntry = buscarNivelAdmin(email);
      if (adminEntry) {
        role = adminEntry.nivel === 'operador' ? 'satisfacao' : 'admin';
      }
    }
    const ROLES_GQ = new Set(['master', 'satisfacao', 'admin']);
    if (!ROLES_GQ.has(role)) {
      console.warn('[SSO] acesso negado a GQ (sem autorizacao no Hub):', email);
      // Sessao antiga nao pode sobreviver ao rebaixamento no Hub.
      clearCookie(res);
      return res.redirect('/acesso-hub.html?erro=sem_acesso');
    }
    const token = jwt.sign({ sub: 0, username: email, role, nome: (payload.nome || null) }, JWT_SECRET, { expiresIn: '8h' });
    setCookie(res, token);
    if (theme) res.appendHeader('Set-Cookie', `gq_theme=${theme}; Max-Age=31536000; Path=/; SameSite=Lax`);
    const safeNext = nextPath && /^\/(?!\/)/.test(nextPath) ? nextPath : '/';
    res.redirect(safeNext);
  } catch (e) {
    console.error('[SSO] erro:', e.message);
    res.redirect('/acesso-hub.html');
  }
});

// Redireciona URL antiga que o Hub gerou com /login.html no base
app.get('/login.html/sso', (req, res) => {
  const qs = new URLSearchParams(req.query).toString();
  res.redirect('/sso' + (qs ? '?' + qs : ''));
});

// Logout
app.get('/api/logout', (_req, res) => { clearCookie(res); res.redirect('/acesso-hub.html'); });

// API proxy → pesquisa-satisfacao /api/gq/*
const GQ_ALLOWED_PARAMS = new Set(['slug','from','to','tipo','origem','q','page','limit','massagista']);

const MOCK_STATS = {
  ok: true, mediaGeral: 91, total: 6, semAvaliacao: 1, pctRecomendacao: 100.0,
  origemDistrib: { hospede: 5, colaborador: 1 },
  secoes: [
    { id: 1, ordem: 1, titulo: 'Serviços', perguntas: [
      { chave: 'servicos_expectativa', texto: 'A expectativa do tratamento', nota: '92%', respostas: 6, distribuicao: { otimo: 5, bom: 1, regular: 0, ruim: 0 } },
      { chave: 'servicos_explicacao', texto: 'A explicação da massoterapeuta', nota: '88%', respostas: 6, distribuicao: { otimo: 4, bom: 2, regular: 0, ruim: 0 } },
      { chave: 'servicos_atitude', texto: 'A atitude e a qualidade dos serviços', nota: '90%', respostas: 6, distribuicao: { otimo: 4, bom: 2, regular: 0, ruim: 0 } },
      { chave: 'servicos_tecnica', texto: 'A técnica e a habilidade da massoterapeuta', nota: '94%', respostas: 6, distribuicao: { otimo: 5, bom: 1, regular: 0, ruim: 0 } },
    ]},
    { id: 2, ordem: 2, titulo: 'Instalações', perguntas: [
      { chave: 'instalacoes_conforto', texto: 'Conforto e conservação do SPA', nota: '87%', respostas: 6, distribuicao: { otimo: 3, bom: 3, regular: 0, ruim: 0 } },
      { chave: 'instalacoes_organizacao', texto: 'Organização e atmosfera do ambiente', nota: '93%', respostas: 6, distribuicao: { otimo: 5, bom: 1, regular: 0, ruim: 0 } },
    ]},
  ],
  comentarios: [
    { chave: 'comentario_geral', label: 'Comentário geral', itens: [
      { text: 'Atendimento excelente, voltarei com certeza!', author: 'Maria S.', date: '22/07/2026' },
      { text: 'Ambiente muito agradável e profissionais muito atenciosos.', author: 'João P.', date: '21/07/2026' },
    ]},
  ],
};
const MOCK_RESPOSTAS = {
  ok: true, total: 6,
  items: [
    { id: 1, date: '22/07/2026', nome: 'Maria Souza', email: 'maria@example.com', tipo: 'casal', origem: 'hospede', media: '92%' },
    { id: 2, date: '21/07/2026', nome: 'João Pereira', email: 'joao@example.com', tipo: 'individual', origem: 'hospede', media: '88%' },
    { id: 3, date: '20/07/2026', nome: 'Ana Lima', email: 'ana@example.com', tipo: 'individual', origem: 'hospede', media: '94%' },
    { id: 4, date: '19/07/2026', nome: 'Carlos Mendes', email: 'carlos@example.com', tipo: 'individual', origem: 'colaborador', media: '90%' },
    { id: 5, date: '18/07/2026', nome: 'Beatriz Costa', email: 'beatriz@example.com', tipo: 'casal', origem: 'hospede', media: '87%' },
    { id: 6, date: '17/07/2026', nome: 'Rafael Andrade', email: 'rafael@example.com', tipo: 'individual', origem: 'hospede', media: '93%' },
  ],
};

// Insere no cache com teto de tamanho: chaves incluem busca livre/datas/página,
// então sem eviction o Map cresceria sem limite.
function _gqSet(cacheKey, data) {
  if (_gqCache.size >= 500) {
    let oldK = null, oldTs = Infinity;
    for (const [k, v] of _gqCache) if (v.ts < oldTs) { oldTs = v.ts; oldK = k; }
    if (oldK) _gqCache.delete(oldK);
  }
  _gqCache.set(cacheKey, { data, ts: Date.now() });
}

const _gqNeg = new Map(); // cacheKey → ts da última falha (cache negativo: evita esperar timeout de novo)
const GQ_NEG_TTL = 30 * 1000;

function _gqFallback(res, endpoint, cacheKey) {
  const stale = _gqCache.get(cacheKey);
  if (stale) return res.json(stale.data);
  if (endpoint === 'stats') return res.json(MOCK_STATS);
  if (endpoint === 'respostas') return res.json(MOCK_RESPOSTAS);
  res.status(502).json({ ok: false, error: 'Erro ao buscar dados' });
}

async function proxyGQ(req, res, endpoint) {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(req.query)) if (GQ_ALLOWED_PARAMS.has(k)) params.set(k, v);
  const cacheKey = `${endpoint}:${params}`;

  const hit = _gqCache.get(cacheKey);
  if (hit && Date.now() - hit.ts < GQ_CACHE_TTL) return res.json(hit.data);

  // SPA falhou há pouco: serve stale/mock imediato em vez de esperar o timeout de novo
  const neg = _gqNeg.get(cacheKey);
  if (neg && Date.now() - neg < GQ_NEG_TTL) return _gqFallback(res, endpoint, cacheKey);

  try {
    const url = `${PESQUISA_URL}/api/gq/${endpoint}?${params}`;
    const r = await fetchWithTimeout(url, {
      headers: { Authorization: `Bearer ${req.gqToken}` },
    });
    const data = await r.json();
    if (r.ok) { _gqSet(cacheKey, data); _gqNeg.delete(cacheKey); }
    res.status(r.status).json(data);
  } catch (e) {
    _gqNeg.set(cacheKey, Date.now());
    _gqFallback(res, endpoint, cacheKey);
  }
}

app.get('/api/stats', requireSession, (req, res) => proxyGQ(req, res, 'stats'));
app.get('/api/respostas', requireSession, (req, res) => proxyGQ(req, res, 'respostas'));

app.get('/api/resposta/:id', requireSession, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ ok: false, error: 'ID inválido' });
    const r = await fetchWithTimeout(`${PESQUISA_URL}/api/gq/resposta/${id}`, {
      headers: { Authorization: `Bearer ${req.gqToken}` },
    });
    const data = await r.json();
    res.status(r.status).json(data);
  } catch (e) {
    res.status(502).json({ ok: false, error: 'Erro ao buscar detalhes' });
  }
});

app.post('/api/nova-resposta', requireSession, async (req, res) => {
  const b = req.body || {};
  if (!['hospede', 'colaborador'].includes(b.origem)) return res.status(400).json({ ok: false, error: 'Origem inválida' });
  if (b.data_tratamento) {
    const today = new Date().toISOString().slice(0, 10);
    if (b.data_tratamento > today) return res.status(400).json({ ok: false, error: 'Data do tratamento não pode ser futura' });
  }
  const decoded = jwt.decode(req.gqToken);
  const inserido_por = decoded?.username || null;
  try {
    const r = await fetchWithTimeout(`${PESQUISA_URL}/api/feedback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${req.gqToken}` },
      body: JSON.stringify({ ...req.body, inserido_por }),
    });
    const data = await r.json();
    res.status(r.status).json(data);
  } catch (e) {
    res.status(502).json({ ok: false, error: 'Erro ao enviar resposta' });
  }
});

app.get('/api/metas', requireSession, (_req, res) => {
  try {
    const rows = listarMetas();
    const map = Object.fromEntries(rows.map(r => [r.tipo, r.valor]));
    res.json({ ok: true, metas: map });
  } catch(e) { res.status(500).json({ ok: false, error: 'Erro ao listar metas' }); }
});

app.post('/api/metas', requireMaster, (req, res) => {
  const entries = req.body?.entries;
  if (!Array.isArray(entries) || entries.some(e => typeof e.tipo !== 'string' || isNaN(Number(e.valor)))) {
    return res.status(400).json({ ok: false, error: 'entries deve ser [{tipo, valor}]' });
  }
  try {
    const d = jwt.decode(req.gqToken);
    upsertMetas(entries, d?.username || null);
    res.json({ ok: true });
  } catch(e) { console.error('[metas] erro ao salvar:', e.message); res.status(500).json({ ok: false, error: 'Erro ao salvar metas' }); }
});

app.get('/api/me', requireSession, (req, res) => {
  const d = jwt.decode(req.gqToken);
  res.json({ ok: true, email: d?.username || '', role: d?.role || '', nome: d?.nome || null });
});

// Foto de perfil vem do Hub; token curto assinado com SSO_SECRET (gq_sess usa JWT_SECRET)
app.get('/api/me/foto', requireSession, async (req, res) => {
  try {
    const d = jwt.decode(req.gqToken);
    const email = d?.username || '';
    if (!email.includes('@')) return res.status(404).end();
    const tok = jwt.sign({ app: 'gq' }, SSO_SECRET, { expiresIn: '2m' });
    const r = await fetchWithTimeout(`https://hub-granmarquise.fly.dev/api/foto?email=${encodeURIComponent(email)}`, {
      headers: { Authorization: `Bearer ${tok}` }
    });
    // Cacheia o 404 também: sem isso, cada page load de quem não tem foto
    // dispara uma chamada GQ->Hub.
    if (!r.ok) { res.setHeader('Cache-Control', 'private, max-age=300'); return res.status(404).end(); }
    const buf = Buffer.from(await r.arrayBuffer());
    res.setHeader('Content-Type', 'image/jpeg');
    res.setHeader('Cache-Control', 'private, max-age=300');
    res.end(buf);
  } catch {
    res.status(404).end();
  }
});

app.get('/api/admins', requireMaster, (_req, res) => {
  try { res.json({ ok: true, admins: listarAdmins() }); }
  catch(e) { res.status(500).json({ ok: false, error: 'Erro ao listar' }); }
});

app.post('/api/admins', requireMaster, (req, res) => {
  const { email = '', nivel = 'operador' } = req.body || {};
  const e = email.trim().toLowerCase();
  if (!e || !/^[^@]+@[^@]+\.[^@]+$/.test(e)) return res.status(400).json({ ok: false, error: 'E-mail inválido' });
  if (!['operador', 'leitura'].includes(nivel)) return res.status(400).json({ ok: false, error: 'Nível inválido' });
  try {
    const d = jwt.decode(req.gqToken);
    upsertAdmin(e, nivel, d?.username || null);
    res.json({ ok: true });
  } catch(err) { res.status(500).json({ ok: false, error: 'Erro ao salvar' }); }
});

app.delete('/api/admins/:email', requireMaster, (req, res) => {
  try {
    removerAdmin(decodeURIComponent(req.params.email));
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ ok: false, error: 'Erro ao remover' }); }
});

// Armazenamento local (SQLite em ./data/qualidade.db — volume persistente no Fly)
function novaRespostaLocal(tipoPadrao) {
  return (req, res) => {
    const b = req.body || {};
    const decoded = jwt.decode(req.gqToken);
    try {
      const { id } = inserirResposta({
        tipo: typeof b.tipo === 'string' && b.tipo.trim() ? b.tipo.trim() : tipoPadrao,
        submitted_at: b._submitted_at || null,
        inserido_por: decoded?.username || null,
        payload: b,
      });
      res.json({ ok: true, id });
    } catch (e) {
      console.error(`[nova-resposta-${tipoPadrao}]`, e);
      res.status(500).json({ ok: false, error: 'Erro ao salvar' });
    }
  };
}

app.post('/api/nova-resposta-geral', requireSession, novaRespostaLocal('geral'));
app.post('/api/nova-resposta-pdvs', requireSession, novaRespostaLocal('pdvs'));
app.post('/api/nova-resposta-eventos', requireSession, novaRespostaLocal('eventos'));

// Ingestão server-to-server (SPA → GestaoQualidade), autenticada por JWT assinado com SSO_SECRET
app.post('/api/ingest/resposta', (req, res) => {
  const auth = req.headers.authorization || '';
  const tok = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!tok) return res.status(401).json({ ok: false, error: 'Token ausente' });
  let claims;
  try {
    claims = jwt.verify(tok, SSO_SECRET, { algorithms: ['HS256'] });
  } catch {
    return res.status(401).json({ ok: false, error: 'Token inválido' });
  }
  const b = req.body || {};
  if (!b.tipo || typeof b.tipo !== 'string' || typeof b.payload !== 'object' || b.payload === null) {
    return res.status(400).json({ ok: false, error: 'Campos obrigatórios: tipo (string), payload (objeto)' });
  }
  try {
    const { id, duplicado } = inserirResposta({
      tipo: b.tipo.trim(),
      app_origem: String(claims.app || 'spa'),
      fonte_id: b.fonte_id,
      submitted_at: b.submitted_at,
      inserido_por: b.inserido_por || null,
      payload: b.payload,
      ignorarDuplicado: true,
    });
    res.json({ ok: true, id, duplicado });
  } catch (e) {
    console.error('[ingest]', e);
    res.status(500).json({ ok: false, error: 'Erro ao salvar' });
  }
});

// Dados de referência (dropdowns) — quase estáticos: cache com TTL próprio + stale em falha
const REF_CACHE_TTL = 10 * 60 * 1000;
async function proxyRef(res, cacheKey, url, errMsg) {
  const hit = _gqCache.get(cacheKey);
  if (hit && Date.now() - hit.ts < REF_CACHE_TTL) return res.json(hit.data);
  try {
    const r = await fetchWithTimeout(url);
    const data = await r.json();
    if (r.ok) _gqSet(cacheKey, data);
    res.status(r.status).json(data);
  } catch (e) {
    const stale = _gqCache.get(cacheKey);
    if (stale) return res.json(stale.data);
    res.status(502).json({ ok: false, error: errMsg });
  }
}

app.get('/api/quartos', requireSession, (_req, res) =>
  proxyRef(res, 'ref:quartos', `${PESQUISA_URL}/api/quartos`, 'Erro ao buscar quartos'));

app.get('/api/massagistas', requireSession, (_req, res) =>
  proxyRef(res, 'ref:massagistas', `${PESQUISA_URL}/api/massagistas-ativas`, 'Erro ao buscar massagistas'));

app.get('/api/tratamentos', requireSession, (_req, res) =>
  proxyRef(res, 'ref:tratamentos', `${PESQUISA_URL}/api/tipos-massagem-ativos`, 'Erro ao buscar tratamentos'));

app.get('/api/resposta-local/:id', requireSession, (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ ok: false, error: 'ID inválido' });
  try {
    const item = buscarResposta(id);
    if (!item) return res.status(404).json({ ok: false, error: 'Não encontrado' });
    res.json({ ok: true, item });
  } catch(e) {
    console.error('[resposta-local]', e);
    res.status(500).json({ ok: false, error: 'Erro' });
  }
});

app.put('/api/resposta-local/:id', requireSession, (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ ok: false, error: 'ID inválido' });
  const payload = req.body;
  if (!payload || typeof payload !== 'object') return res.status(400).json({ ok: false, error: 'Payload inválido' });
  try {
    const item = buscarResposta(id);
    if (!item) return res.status(404).json({ ok: false, error: 'Não encontrado' });
    const novoPayload = { ...item.payload, ...payload };
    const ok = atualizarResposta(id, novoPayload);
    res.json({ ok });
  } catch(e) {
    console.error('[resposta-local PUT]', e);
    res.status(500).json({ ok: false, error: 'Erro' });
  }
});

app.get('/api/stats-local', requireSession, (req, res) => {
  try {
    const stats = contarRespostas({ mes: req.query.mes || null });
    res.json({ ok: true, ...stats });
  }
  catch (e) { console.error('[stats-local]', e); res.status(500).json({ ok: false, error: 'Erro' }); }
});

app.get('/api/urnas-stats', requireSession, (req, res) => {
  try {
    const mes = req.query.mes || new Date().toISOString().slice(0, 7);
    res.json({ ok: true, mes: contarPorUrna({ mes }), spa_site: contarSpaSite({ mes }) });
  } catch(e) { console.error('[urnas-stats]', e); res.status(500).json({ ok: false }); }
});

app.get('/api/respostas-local', requireSession, (req, res) => {
  const tipoRaw = req.query.tipo;
  let tipo = null, subtipo = null;
  if (tipoRaw === 'eventos-corp') {
    tipo = 'eventos'; subtipo = 'eventos-corporativos';
  } else if (tipoRaw === 'eventos-soc') {
    tipo = 'eventos'; subtipo = req.query.subtipo || 'eventos-sociais';
  } else if (['geral', 'pdvs', 'eventos'].includes(tipoRaw)) {
    tipo = tipoRaw; subtipo = req.query.subtipo || null;
  }
  try {
    const result = listarRespostas({
      tipo, subtipo,
      from: req.query.from || null,
      to:   req.query.to   || null,
      q:    req.query.q    || null,
      page:  Math.max(1, parseInt(req.query.page)  || 1),
      limit: Math.min(50, Math.max(1, parseInt(req.query.limit) || 20)),
    });
    res.json({ ok: true, ...result });
  } catch (e) {
    console.error('[respostas-local]', e);
    res.status(500).json({ ok: false, error: 'Erro ao buscar respostas' });
  }
});

// Root e index.html → dashboard (requires session)
app.get('/', requireSession, (_req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'index.html'))
);
app.get('/index.html', requireSession, (_req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'index.html'))
);

// Static
app.use(express.static(path.join(__dirname, 'public')));

// Fallback
app.use((req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ ok: false, error: 'Rota não encontrada' });
  res.status(404).send('Não encontrado');
});

app.listen(PORT, () => {
  console.log(`GestaoQualidade rodando na porta ${PORT}`);
  // Mantém pesquisa-satisfacao acordada para evitar cold start no proxy
  const _warmup = () => fetchWithTimeout(`${PESQUISA_URL}/api/health`).catch(() => {});
  _warmup();
  setInterval(_warmup, 4 * 60 * 1000);
});
