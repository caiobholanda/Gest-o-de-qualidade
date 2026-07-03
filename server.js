import express from 'express';
import jwt from 'jsonwebtoken';
import path from 'path';
import { fileURLToPath } from 'url';

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
app.use(express.json({ limit: '100kb' }));

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
const GQ_ALLOWED_PARAMS = new Set(['slug','from','to','tipo','origem','q','page','limit']);
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
    res.status(502).json({ ok: false, error: 'Erro ao buscar dados' });
  }
}

app.get('/api/stats', requireSession, (req, res) => proxyGQ(req, res, 'stats'));
app.get('/api/respostas', requireSession, (req, res) => proxyGQ(req, res, 'respostas'));

app.get('/api/resposta/:id', requireSession, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ ok: false, error: 'ID inválido' });
    const r = await fetchWithTimeout(`${PESQUISA_URL}/api/feedback/item/${id}`, {
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
  try {
    const r = await fetchWithTimeout(`${PESQUISA_URL}/api/feedback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${req.gqToken}` },
      body: JSON.stringify(req.body),
    });
    const data = await r.json();
    res.status(r.status).json(data);
  } catch (e) {
    res.status(502).json({ ok: false, error: 'Erro ao enviar resposta' });
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
