
import express from 'express';
import axios from 'axios';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import cookieSession from 'cookie-session';
import crypto from 'crypto';

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const IS_PROD = process.env.NODE_ENV === 'production';

app.set('trust proxy', 1); // necessário atrás de proxy (Render/Vercel)

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- cookie session por usuário ---
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
app.use(cookieSession({
  name: 'mlb_sess',
  secret: SESSION_SECRET,
  httpOnly: true,
  sameSite: 'lax',
  secure: IS_PROD,   // em produção exige HTTPS
  maxAge: 1000 * 60 * 60 * 12 // 12h
}));

const PORT = process.env.PORT || 3000;

// Helpers para sessão
const getCreds = req => req.session?.creds || null;
const setCreds = (req, { client_id, client_secret, redirect_uri }) => req.session.creds = { client_id, client_secret, redirect_uri };
const getTokens = req => req.session?.tokens || null;
const setTokens = (req, tokens) => req.session.tokens = tokens;
const clearSession = req => req.session = null;

async function exchangeCodeForTokens(req, code) {
  const creds = getCreds(req);
  if (!creds) throw new Error('Missing client setup');
  const url = 'https://api.mercadolibre.com/oauth/token';
  const payload = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: creds.client_id,
    client_secret: creds.client_secret,
    code,
    redirect_uri: creds.redirect_uri
  });
  const { data } = await axios.post(url, payload);
  const expires_at = Date.now() + ((data.expires_in || 21600) - 60) * 1000;
  setTokens(req, { access_token: data.access_token, refresh_token: data.refresh_token, expires_at });
  return data;
}

async function refreshIfNeeded(req) {
  const creds = getCreds(req);
  if (!creds) throw new Error('Missing client setup');
  const tok = getTokens(req);
  if (!tok?.refresh_token) throw new Error('Not authorized');
  if (tok.access_token && Date.now() < (tok.expires_at || 0)) return tok.access_token;

  const url = 'https://api.mercadolibre.com/oauth/token';
  const payload = new URLSearchParams({
    grant_type: 'refresh_token',
    client_id: creds.client_id,
    client_secret: creds.client_secret,
    refresh_token: tok.refresh_token
  });
  const { data } = await axios.post(url, payload);
  const expires_at = Date.now() + ((data.expires_in || 21600) - 60) * 1000;
  setTokens(req, { access_token: data.access_token, refresh_token: tok.refresh_token, expires_at });
  return data.access_token;
}

async function meliGET(req, endpoint, { params = {}, auth = false } = {}) {
  const url = `https://api.mercadolibre.com${endpoint}`;
  const headers = { 'Accept': 'application/json' };
  if (auth) {
    const token = await refreshIfNeeded(req);
    headers['Authorization'] = `Bearer ${token}`;
  }
  for (let i = 0; i < 3; i++) {
    try {
      const resp = await axios.get(url, { params, headers });
      return resp.data;
    } catch (err) {
      const status = err.response?.status;
      if (status === 429) { await new Promise(r => setTimeout(r, 1200 * (i + 1))); continue; }
      if (status === 401 && auth && i === 0) { await refreshIfNeeded(req); continue; }
      throw err;
    }
  }
}

// Rotas utilitárias
app.get('/api/ping', (req,res)=>res.json({ ok:true, time:Date.now(), prod: IS_PROD }));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// Sessão/Setup
app.get('/api/session', (req, res) => {
  const creds = getCreds(req);
  const tokens = getTokens(req);
  res.json({
    creds_set: !!creds,
    authed: !!tokens?.access_token,
    redirect_uri: creds?.redirect_uri || null
  });
});

app.post('/api/setup', (req, res) => {
  const { client_id, client_secret, redirect_uri } = req.body || {};
  if (!client_id || !client_secret || !redirect_uri) {
    return res.status(400).json({ error: 'missing_fields' });
  }
  setCreds(req, { client_id, client_secret, redirect_uri });
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => { clearSession(req); res.json({ ok:true }); });

// OAuth
app.get('/authorize', (req, res) => {
  const creds = getCreds(req);
  if (!creds) return res.status(400).send('Configure client_id, client_secret e redirect_uri primeiro.');
  const state = crypto.randomBytes(8).toString('hex');
  req.session.oauth_state = state;

  const url = new URL('https://auth.mercadolibre.com/authorization');
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', creds.client_id);
  url.searchParams.set('redirect_uri', creds.redirect_uri);
  url.searchParams.set('state', state);
  res.redirect(url.toString());
});

app.get('/oauth/callback', async (req, res) => {
  const { code, state, error, error_description } = req.query;
  if (error) return res.status(400).send(`OAuth error: ${error} - ${error_description}`);
  if (!code) return res.status(400).send('Missing code');
  if (req.session.oauth_state && state !== req.session.oauth_state) {
    return res.status(400).send('Invalid state');
  }
  try {
    await exchangeCodeForTokens(req, code);
    res.redirect('/?authed=1');
  } catch (e) {
    res.status(500).send('Failed to exchange code: ' + (e.response?.data?.error_description || e.message));
  }
});

// APIs
app.get('/api/me', async (req, res) => {
  try { res.json(await meliGET(req, '/users/me', { auth:true })); }
  catch (e) { res.status(401).json({ error: 'me_failed', detail: e.response?.data || e.message }); }
});

app.get('/api/me/items', async (req, res) => {
  try {
    const me = await meliGET(req, '/users/me', { auth: true });
    const sellerId = me.id;
    let offset = 0, limit = 100; const ids = [];
    while (true) {
      const found = await meliGET(req, `/users/${sellerId}/items/search`, { params: { limit, offset }, auth: true });
      const arr = found?.results || [];
      if (!arr.length) break; ids.push(...arr);
      offset += arr.length; if (arr.length < limit) break;
    }
    const out = [];
    for (let i = 0; i < ids.length; i += 20) {
      const chunk = ids.slice(i, i + 20).join(',');
      const data = await meliGET(req, '/items', { params: { ids: chunk, attributes: 'id,title,price,original_price,sold_quantity,available_quantity,listing_type_id,status,permalink,last_updated' } });
      (data || []).forEach(e => out.push(e.body));
    }
    res.json(out);
  } catch (e) {
    res.status(500).json({ error: 'my_items_failed', detail: e.response?.data || e.message });
  }
});

app.get('/api/search', async (req, res) => {
  try {
    const { q, category, seller_id, limit = 50, max = 100 } = req.query;
    let offset = 0; const cap = Math.min(Number(max) || 100, 1000);
    const all = [];
    while (all.length < cap) {
      const resp = await meliGET(req, '/sites/MLB/search', { params: { q, category, seller_id, limit: Math.min(50, cap - all.length), offset } });
      const arr = resp?.results || []; if (!arr.length) break;
      all.push(...arr); offset += arr.length;
    }
    res.json(all);
  } catch (e) {
    res.status(500).json({ error: 'search_failed', detail: e.response?.data || e.message });
  }
});

app.get('/api/seller/:sellerId/items', async (req, res) => {
  try {
    const sellerId = req.params.sellerId;
    const max = Math.min(Number(req.query.max) || 300, 1000);
    let offset = 0; const all = [];
    while (all.length < max) {
      const resp = await meliGET(req, '/sites/MLB/search', { params: { seller_id: sellerId, limit: Math.min(50, max - all.length), offset } });
      const arr = resp?.results || []; if (!arr.length) break;
      all.push(...arr); offset += arr.length;
    }
    res.json(all);
  } catch (e) {
    res.status(500).json({ error: 'seller_items_failed', detail: e.response?.data || e.message });
  }
});

app.get('/api/items', async (req, res) => {
  try {
    const ids = String(req.query.ids || '').split(',').map(s => s.trim()).filter(Boolean);
    const out = [];
    for (let i = 0; i < ids.length; i += 20) {
      const chunk = ids.slice(i, i + 20).join(',');
      const data = await meliGET(req, '/items', { params: { ids: chunk, attributes: 'id,title,price,original_price,sold_quantity,available_quantity,listing_type_id,status,permalink,last_updated' } });
      (data || []).forEach(e => out.push(e.body));
    }
    res.json(out);
  } catch (e) {
    res.status(500).json({ error: 'items_failed', detail: e.response?.data || e.message });
  }
});

// Error handler
app.use((err, req, res, next) => { console.error('Unhandled error:', err); res.status(500).send('Server error'); });

app.listen(PORT, '0.0.0.0', () => console.log(`MLB Dashboard (multiuser) em http://localhost:${PORT} (prod=${IS_PROD})`));
