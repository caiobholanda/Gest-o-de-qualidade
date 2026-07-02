import 'node:process';
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;
const PESQUISA_URL = (process.env.PESQUISA_URL || 'https://pesquisa-satisfacao.fly.dev').replace(/\/$/, '');
const COOKIE = 'gq_sess';

app.set('trust proxy', 1);
app.use(express.json());

function getCookie(req, name) {
  const h = req.headers.cookie || '';
  const m = h.split(';').find(c => c.trim().startsWith(name + '='));
  return m ? decodeURIComponent(m.trim().slice(name.length + 1)) : null;
}

function setCookie(res, val) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.appendHeader('Set-Cookie', `${COOKIE}=${encodeURIComponent(val)}; HttpOnly; SameSite=Lax; Max-Age=43200; Path=/${secure}`);
}

function clearCookie(res) {
  res.appendHeader('Set-Cookie', `${COOKIE}=; Max-Age=0; Path=/; HttpOnly`);
}

function requireSession(req, res, next) {
  const tok = getCookie(req, COOKIE);
  if (!tok) {
    if (req.path.startsWith('/api/')) return res.status(401).json({ ok: false, error: 'Não autenticado' });
    return res.redirect('/login.html');
  }
  req.gqToken = tok;
  next();
}

// Health
app.get('/api/health', (_req, res) => res.json({ ok: true }));

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ ok: false, error: 'Usuário e senha obrigatórios' });
  try {
    const r = await fetch(`${PESQUISA_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await r.json();
    if (!data.ok) return res.status(401).json({ ok: false, error: data.error || 'Credenciais inválidas' });
    setCookie(res, data.token);
    res.json({ ok: true });
  } catch (e) {
    res.status(502).json({ ok: false, error: 'Erro ao conectar ao servidor de autenticação' });
  }
});

// Logout
app.get('/api/logout', (req, res) => { clearCookie(res); res.redirect('/login.html'); });

// API proxy → pesquisa-satisfacao /api/gq/*
async function proxyGQ(req, res, endpoint) {
  try {
    const url = `${PESQUISA_URL}/api/gq/${endpoint}?${new URLSearchParams(req.query)}`;
    const r = await fetch(url, {
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

// Root → dashboard (requires session)
app.get('/', requireSession, (_req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'index.html'))
);

// Static (login.html, assets)
app.use(express.static(path.join(__dirname, 'public')));

// Fallback
app.use((req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ ok: false, error: 'Rota não encontrada' });
  res.status(404).send('Não encontrado');
});

app.listen(PORT, () => console.log(`GestaoQualidade rodando na porta ${PORT}`));
