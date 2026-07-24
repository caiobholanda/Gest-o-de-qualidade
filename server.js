import express from 'express';
import jwt from 'jsonwebtoken';
import path from 'path';
import { fileURLToPath } from 'url';
import { inserirResposta, listarRespostas, contarRespostas } from './db.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;
const PESQUISA_URL = (process.env.PESQUISA_URL || 'https://pesquisa-satisfacao.fly.dev').replace(/\/$/, '');
const SSO_SECRET = process.env.SSO_SECRET;
const JWT_SECRET = process.env.JWT_SECRET;
const COOKIE = 'gq_sess';
const FETCH_TIMEOUT = 10000;

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
    const isMaster = payload.is_master || (payload.sites_admin || []).includes('pesquisa-satisfacao');
    const siteRole = payload.site_roles && payload.site_roles['pesquisa-satisfacao'];
    const role = isMaster ? 'master' : (siteRole || 'satisfacao');
    const token = jwt.sign({ sub: 0, username: email, role }, JWT_SECRET, { expiresIn: '8h' });
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

async function proxyGQ(req, res, endpoint) {
  try {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(req.query)) if (GQ_ALLOWED_PARAMS.has(k)) params.set(k, v);
    const url = `${PESQUISA_URL}/api/gq/${endpoint}?${params}`;
    const r = await fetchWithTimeout(url, {
      headers: { Authorization: `Bearer ${req.gqToken}` },
    });
    const data = await r.json();
    res.status(r.status).json(data);
  } catch (e) {
    if (endpoint === 'stats') return res.json(MOCK_STATS);
    if (endpoint === 'respostas') return res.json(MOCK_RESPOSTAS);
    res.status(502).json({ ok: false, error: 'Erro ao buscar dados' });
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
  if (!b.nome?.trim()) return res.status(400).json({ ok: false, error: 'Nome obrigatório' });
  if (!b.email?.trim()) return res.status(400).json({ ok: false, error: 'E-mail obrigatório' });
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

// Armazenamento local (SQLite em ./data/qualidade.db — volume persistente no Fly)
function novaRespostaLocal(tipoPadrao) {
  return (req, res) => {
    const b = req.body || {};
    if (!b.nome?.trim()) return res.status(400).json({ ok: false, error: 'Nome obrigatório' });
    const decoded = jwt.decode(req.gqToken);
    try {
      const { id } = inserirResposta({
        tipo: typeof b.tipo === 'string' && b.tipo.trim() ? b.tipo.trim() : tipoPadrao,
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

app.get('/api/quartos', requireSession, async (req, res) => {
  try {
    const r = await fetchWithTimeout(`${PESQUISA_URL}/api/quartos`);
    const data = await r.json();
    res.status(r.status).json(data);
  } catch (e) {
    res.status(502).json({ ok: false, error: 'Erro ao buscar quartos' });
  }
});

app.get('/api/massagistas', requireSession, async (req, res) => {
  try {
    const r = await fetchWithTimeout(`${PESQUISA_URL}/api/massagistas-ativas`);
    const data = await r.json();
    res.status(r.status).json(data);
  } catch (e) {
    res.status(502).json({ ok: false, error: 'Erro ao buscar massagistas' });
  }
});

app.get('/api/tratamentos', requireSession, async (req, res) => {
  try {
    const r = await fetchWithTimeout(`${PESQUISA_URL}/api/tipos-massagem-ativos`);
    const data = await r.json();
    res.status(r.status).json(data);
  } catch (e) {
    res.status(502).json({ ok: false, error: 'Erro ao buscar tratamentos' });
  }
});

app.get('/api/stats-local', requireSession, (_req, res) => {
  try {
    const { totais, mes } = contarRespostas();
    res.json({ ok: true, totais, mes });
  }
  catch (e) { console.error('[stats-local]', e); res.status(500).json({ ok: false, error: 'Erro' }); }
});

app.get('/api/respostas-local', requireSession, (req, res) => {
  const TIPOS = new Set(['geral', 'pdvs', 'eventos']);
  const tipo = TIPOS.has(req.query.tipo) ? req.query.tipo : null;
  try {
    const result = listarRespostas({
      tipo,
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

app.listen(PORT, () => console.log(`GestaoQualidade rodando na porta ${PORT}`));
