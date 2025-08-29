
import express from 'express';
import axios from 'axios';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import cookieSession from 'cookie-session';
import crypto from 'crypto';
import { install, detectBrowserPlatform, Browser, resolveBuildId, computeExecutablePath } from '@puppeteer/browsers';
import fs from 'fs';
import puppeteer from 'puppeteer';

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const IS_PROD = process.env.NODE_ENV === 'production';

app.set('trust proxy', 1); // necessário atrás de proxy (Render/Vercel)

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ==== RASPAGEM (HTML) SEM TOKEN — "Passo 8" ====

// Headers p/ parecer navegador
const UA_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36',
  'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'Referer': 'https://lista.mercadolivre.com.br/'
};

async function fetchHtml(url) {
  const { data } = await axios.get(url, { headers: UA_HEADERS, maxRedirects: 5, timeout: 20000 });
  return data;
}

function canonicalMlbId(s) {
  const m = /MLB-?(\d{6,})/.exec(s);
  return m ? 'MLB' + m[1] : null;
}

function extractIdsFromHtml(html) {
  const ids = new Set();

  // IDs em texto
  const re1 = /MLB-?\d{6,}/g;
  let m;
  while ((m = re1.exec(html))) {
    const id = canonicalMlbId(m[0]);
    if (id) ids.add(id);
  }

  // IDs em JSON: "id":"MLB123..."
  const re2 = /"id"\s*:\s*"MLB(\d{6,})"/g;
  while ((m = re2.exec(html))) ids.add('MLB' + m[1]);

  // IDs em JSON por permalink: "permalink":"https://.../MLB123..."
  const re3 = /"permalink"\s*:\s*"https?:\/\/[^"]*\/(MLB\d{6,})/g;
  while ((m = re3.exec(html))) ids.add(m[1]);

  return Array.from(ids);
}

// tenta pegar dados do <script type="application/ld+json"> e outros pontos da página
function parseProductFromHtml(html, id) {
  let title = '', price = null, permalink = '', sold_quantity = null;

  // 1) JSON-LD Product
  const reLd = /<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let match;
  while ((match = reLd.exec(html))) {
    try {
      const json = JSON.parse(match[1].trim());
      const arr = Array.isArray(json) ? json : [json];
      for (const obj of arr) {
        const t = obj['@type'];
        const isProduct = t === 'Product' || (Array.isArray(t) && t.includes('Product'));
        if (isProduct) {
          title = title || obj.name || '';
          const offers = Array.isArray(obj.offers) ? obj.offers[0] : obj.offers;
          const p = offers?.price ?? offers?.priceSpecification?.price;
          const pn = p != null ? Number(String(p).replace(/[^\d.,-]/g, '').replace('.', '').replace(',', '.')) : NaN;
          if (!Number.isNaN(pn)) price = pn;
          permalink = permalink || obj.url || '';
        }
      }
    } catch { }
  }

  // 2) sold_quantity em JSON interno
  let m2 = html.match(/"sold_quantity"\s*:\s*(\d+)/);
  if (m2) sold_quantity = parseInt(m2[1], 10);

  // 3) fallback em texto ("vendidos")
  if (!sold_quantity) {
    const m3 = html.match(/(\d[\d\.]*)\s*(vendidos|vendido)/i);
    if (m3) sold_quantity = parseInt(m3[1].replace(/\./g, ''), 10);
  }

  // 4) canonical link
  if (!permalink) {
    const m4 = html.match(/<link\s+rel=["']canonical["']\s+href=["']([^"']+)["']/i);
    if (m4) permalink = m4[1];
  }

  return { id, title, price, sold_quantity, permalink };
}

async function scrapeSellerItems(sellerId, max = 100) {
  const cap = Math.min(max, 300);
  const pageSize = 50;
  const seen = new Set();

  let offset = 0, tries = 0;
  while (seen.size < cap && tries < 12) {
    const pageUrl = offset === 0
      ? `https://lista.mercadolivre.com.br/_CustId_${sellerId}`
      : `https://lista.mercadolivre.com.br/_CustId_${sellerId}_Desde_${offset + 1}`;

    let html = '';
    try { html = await fetchHtml(pageUrl); }
    catch { offset += pageSize; tries++; continue; }

    const ids = extractIdsFromHtml(html);
    ids.forEach(id => seen.add(id));
    if (ids.length === 0) break;

    offset += pageSize; tries++;
  }

  const list = Array.from(seen).slice(0, cap);
  if (!list.length) return [];

  const out = [];
  const pool = Math.min(6, list.length);
  let idx = 0;
  async function worker() {
    while (idx < list.length) {
      const id = list[idx++];
      try {
        const h = await fetchHtml(`https://produto.mercadolivre.com.br/${id}`);
        out.push(parseProductFromHtml(h, id));
      } catch { out.push({ id, error: 'fetch_failed' }); }
    }
  }
  await Promise.all(Array.from({ length: pool }, () => worker()));
  return out;
}

// Busca via API oficial (com fallback a app token) e padroniza o formato do Passo 8
// Usa SEMPRE o token de USUÁRIO (OAuth) e ainda envia também como query param
// Busca itens do seller via API oficial, tentando primeiro TOKEN DE USUÁRIO,
// e se der 401/403, tenta automaticamente com APP TOKEN (client_credentials).
async function fetchSellerViaApi(req, sellerId, max = 100) {
  const creds = getCreds(req) || {};
  const X_CALLER = creds.client_id || process.env.APP_CLIENT_ID || process.env.CLIENT_ID || '';
  const cap = Math.min(Number(max) || 100, 1000);
  let offset = 0;
  const all = [];

  let userToken = null;
  try { userToken = await refreshIfNeeded(req); } catch (_) { }

  while (all.length < cap) {
    const limit = Math.min(50, cap - all.length);
    const url = 'https://api.mercadolibre.com/sites/MLB/search';
    const baseParams = { seller_id: sellerId, limit, offset };

    let data = null;

    // 1) tenta com token de USUÁRIO (header + query)
    if (userToken) {
      try {
        const r = await axios.get(url, {
          params: { ...baseParams, access_token: userToken },
          headers: {
            'Accept': 'application/json',
            'Authorization': `Bearer ${userToken}`,
            'X-Caller-Id': X_CALLER
          },
          timeout: 20000
        });
        data = r.data;
      } catch (e) {
        const s = e.response?.status;
        if (s !== 401 && s !== 403) throw e;
      }
    }

    // 2) se falhou/sem dados, tenta APP TOKEN (client_credentials)
    if (!data) {
      const appTok = await getAppToken(req);
      const r2 = await axios.get(url, {
        params: { ...baseParams, access_token: appTok },
        headers: {
          'Accept': 'application/json',
          'Authorization': `Bearer ${appTok}`,   // <- CORRIGIDO
          'X-Caller-Id': X_CALLER
        },
        timeout: 20000
      });
      data = r2.data;
    }

    const arr = data?.results || [];
    if (!arr.length) break;
    all.push(...arr);
    offset += arr.length;
  }

  return all.map(x => ({
    id: x.id,
    title: x.title,
    price: x.price,
    sold_quantity: x.sold_quantity,
    permalink: x.permalink
  }));
}


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
const sleep = (ms) => new Promise(res => setTimeout(res, ms));
const extractMlbs = (txt) => {
  if (!txt) return [];
  const m = String(txt).match(/MLB-?\d{6,}/g) || [];
  return Array.from(new Set(m.map(s => s.replace('-', ''))));
};

async function autoScroll(page, steps = 12, gap = 450) {
  for (let i = 0; i < steps; i++) {
    await page.evaluate(() => window.scrollBy(0, window.innerHeight * 0.9));
    await sleep(gap);
  }
}

async function maybeAcceptCookies(page) {
  try {
    const btns = await page.$$('button, [role="button"]');
    for (const b of btns) {
      const txt = ((await page.evaluate(el => el.textContent || '', b)) || '').toLowerCase();
      if (txt.includes('entendi') || txt.includes('aceitar') || txt.includes('accept') || txt.includes('continuar')) {
        await b.click({ delay: 30 });
        await sleep(400);
        break;
      }
    }
  } catch { }
}


// token da aplicação (client_credentials) para chamadas públicas
async function getAppToken(req) {
  // tenta pegar da sessão…
  let creds = getCreds(req);

  // …ou das variáveis de ambiente (plano B)
  const envId = process.env.APP_CLIENT_ID || process.env.CLIENT_ID;
  const envSecret = process.env.APP_CLIENT_SECRET || process.env.CLIENT_SECRET;
  if ((!creds || !creds.client_id || !creds.client_secret) && envId && envSecret) {
    creds = { client_id: envId, client_secret: envSecret };
  }

  if (!creds || !creds.client_id || !creds.client_secret) {
    throw new Error('no_app_credentials'); // sem credenciais; não dá para pedir app token
  }

  const now = Date.now();
  const appTok = req.session?.app_token;
  if (appTok && now < appTok.expires_at) return appTok.access_token;

  const url = 'https://api.mercadolibre.com/oauth/token';
  const payload = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: creds.client_id,
    client_secret: creds.client_secret
  });
  const { data } = await axios.post(url, payload);
  const expires_at = now + ((data.expires_in || 3600) - 60) * 1000;
  req.session.app_token = { access_token: data.access_token, expires_at };
  return data.access_token;
}


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

  // quando auth=true usa o token do usuário
  if (auth) headers['Authorization'] = `Bearer ${await refreshIfNeeded(req)}`;

  for (let i = 0; i < 3; i++) {
    try {
      const resp = await axios.get(url, { params, headers });
      return resp.data;
    } catch (err) {
      const status = err.response?.status;
      const msg = err.response?.data?.message || err.response?.data?.error || '';

      // 🔁 se a chamada era "pública" e falhou por falta de auth, tenta com app token
      if (!auth && i === 0 && (status === 401 || status === 403)) {
        try {
          const appToken = await getAppToken(req);
          headers['Authorization'] = `Bearer ${appToken}`;
          headers['X-Caller-Id'] = getCreds(req)?.client_id || process.env.APP_CLIENT_ID || process.env.CLIENT_ID || '';
          continue;
        } catch (_) { }
      }

      if (status === 429) { await new Promise(r => setTimeout(r, 1200 * (i + 1))); continue; }
      if (status === 401 && auth && i === 0) { await refreshIfNeeded(req); continue; }
      throw err;
    }
  }
}

// pega nickname do seller (usa seu token de usuário)
async function getSellerNickname(req, sellerId) {
  try {
    const data = await meliGET(req, `/users/${sellerId}`, { auth: true });
    return data?.nickname || null;
  } catch (e) {
    console.warn('nickname fail', e?.response?.status || e.message);
    return null;
  }
}

// extrai IDs de possíveis JSONs embutidos no perfil
function extractIdsFromProfileHtml(html) {
  const ids = new Set();

  // 1) pegue qualquer MLB... que apareça no HTML
  const re = /MLB-?\d{6,}/g;
  let m;
  while ((m = re.exec(html))) {
    const id = canonicalMlbId(m[0]);
    if (id) ids.add(id);
  }

  // 2) pegue de trechos JSON (ex.: "id":"MLB123...")
  const reJsonId = /"id"\s*:\s*"MLB(\d{6,})"/g;
  while ((m = reJsonId.exec(html))) {
    ids.add('MLB' + m[1]);
  }

  // 3) pegue de "permalink":"https://produto.mercadolivre.com.br/MLB..."
  const rePerm = /"permalink"\s*:\s*"https?:\/\/[^"]*\/(MLB\d{6,})/g;
  while ((m = rePerm.exec(html))) {
    ids.add(m[1]);
  }

  return Array.from(ids);
}

// raspa pelo perfil do vendedor usando nickname
async function scrapeSellerByNickname(req, nickname, max = 100) {
  const url = `https://www.mercadolivre.com.br/perfil/${encodeURIComponent(nickname)}#search`;
  const html = await fetchHtml(url);
  let ids = extractIdsFromProfileHtml(html);
  if (!ids.length) return [];

  ids = ids.slice(0, Math.min(max, 300));
  const out = [];
  const pool = Math.min(6, ids.length);
  let idx = 0;

  async function worker() {
    while (idx < ids.length) {
      const my = ids[idx++];
      try {
        const purl = `https://produto.mercadolivre.com.br/${my}`;
        const h = await fetchHtml(purl);
        out.push(parseProductFromHtml(h, my));
      } catch {
        out.push({ id: my, error: 'fetch_failed' });
      }
    }
  }
  await Promise.all(Array.from({ length: pool }, () => worker()));
  return out;
}



// Rotas utilitárias
app.get('/api/ping', (req, res) => res.json({ ok: true, time: Date.now(), prod: IS_PROD }));
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

app.post('/api/logout', (req, res) => { clearSession(req); res.json({ ok: true }); });

app.get('/logout', (req, res) => {
  clearSession(req);           // req.session = null
  res.redirect('/?logged_out=1');
});

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
  try { res.json(await meliGET(req, '/users/me', { auth: true })); }
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

// Rota do "Passo 8" — sem token: raspa a vitrine pública e as páginas dos produtos
// HÍBRIDA: vitrine (_CustId_), depois perfil (nickname), por fim API com token de usuário
// SCRAPE-ONLY por padrão (igual à planilha).
// Se quiser tentar API como último recurso, chame com ?mode=hybrid
// SCRAPE-ONLY por padrão (igual à planilha).
// Se quiser tentar API como último recurso, chame com ?mode=hybrid
app.get('/api/scrape/seller/:sellerId', async (req, res) => {
  try {
    const sellerId = req.params.sellerId;
    const max = Math.min(parseInt(req.query.max || '100', 10), 300);
    const mode = String(req.query.mode || 'scrape').toLowerCase(); // 'scrape' | 'hybrid'

    if (!/^\d{6,}$/.test(sellerId)) {
      return res.status(400).json({ error: 'invalid_seller_id' });
    }

    let rows = [];

    // 1) SCRAPE da vitrine (paginado)
    try {
      rows = await scrapeSellerItems(sellerId, max);
      console.log(`[scrape] vitrine: ${rows.length} itens`);
    } catch (e) {
      console.warn('[scrape] vitrine falhou:', e?.response?.status || e.message);
    }

    // 2) Se vazio, SCRAPE do perfil (nickname)
    if (!rows.length) {
      try {
        const nickname = await getSellerNickname(req, sellerId); // usa /users/{id} com seu token
        if (nickname) {
          rows = await scrapeSellerByNickname(req, nickname, max);
          console.log(`[scrape] perfil ${nickname}: ${rows.length} itens`);
        }
      } catch (e) {
        console.warn('[scrape] perfil falhou:', e?.response?.status || e.message);
      }
    }

    // 3) Só se você pedir explicitamente: tenta API como último recurso
    if (!rows.length && mode === 'hybrid') {
      try {
        rows = await fetchSellerViaApi(req, sellerId, max);
        console.log(`[api] fallback: ${rows.length} itens`);
      } catch (e) {
        console.error('[api] fallback falhou:', e?.response?.status, e?.response?.data || e.message);
        // IMPORTANTE: não joga 500 — segue devolvendo []
        rows = [];
      }
    }

    return res.json(rows); // igual planilha: retorna lista ou []
  } catch (e) {
    console.error('Erro final /api/scrape/seller:', e?.response?.data || e.message);
    res.status(500).json({ error: 'seller_hybrid_failed', detail: e?.response?.data || e.message });
  }
});




app.get('/api/seller/:sellerId/items-auth', async (req, res) => {
  try {
    const sellerId = req.params.sellerId;
    const max = Math.min(parseInt(req.query.max || '100', 10), 1000);
    const out = await fetchSellerViaApi(req, sellerId, max);
    res.json(out);
  } catch (e) {
    console.error('seller items auth error', e?.response?.status, e?.response?.data || e.message);
    res.status(500).json({ error: 'seller_items_auth_failed', detail: e?.response?.data || e.message });
  }
});

// Usa SEU token de USUÁRIO direto no /sites/MLB/search
app.get('/api/raw/sites-search', async (req, res) => {
  try {
    const token = await refreshIfNeeded(req); // precisa estar authed:true na MESMA aba
    const creds = getCreds(req) || {};
    const X_CALLER = creds.client_id || process.env.APP_CLIENT_ID || process.env.CLIENT_ID || '';

    const url = 'https://api.mercadolibre.com/sites/MLB/search';
    const params = { ...req.query, access_token: token };
    const headers = {
      'Accept': 'application/json',
      'Authorization': `Bearer ${token}`,
      'X-Caller-Id': X_CALLER
    };

    const r = await axios.get(url, { params, headers, timeout: 20000 });
    res.json(r.data);
  } catch (e) {
    res.status(e.response?.status || 500).json({
      error: 'raw_sites_search_failed',
      detail: e.response?.data || e.message
    });
  }
});


let __CHROME_PATH_PROMISE = null;

async function ensureChromiumPath() {
  if (__CHROME_PATH_PROMISE) return __CHROME_PATH_PROMISE;
  __CHROME_PATH_PROMISE = (async () => {
    if (process.env.PUPPETEER_EXECUTABLE_PATH && fs.existsSync(process.env.PUPPETEER_EXECUTABLE_PATH)) {
      return process.env.PUPPETEER_EXECUTABLE_PATH;
    }
    try {
      const p = puppeteer.executablePath();
      if (p && fs.existsSync(p)) return p;
    } catch { }

    const cacheDir = process.env.PUPPETEER_CACHE_DIR || '/tmp/puppeteer';
    fs.mkdirSync(cacheDir, { recursive: true });

    const platform = detectBrowserPlatform();
    const buildId = await resolveBuildId(Browser.CHROMIUM, platform, 'latest'); // <- latest

    await install({ cacheDir, browser: Browser.CHROMIUM, platform, buildId });
    const execPath = computeExecutablePath({ cacheDir, browser: Browser.CHROMIUM, platform, buildId });

    process.env.PUPPETEER_EXECUTABLE_PATH = execPath;
    return execPath;
  })();
  return __CHROME_PATH_PROMISE;
}

async function headlessCollectIds(sellerId, max = 120) {
  const profileDir = fs.mkdtempSync(path.join('/tmp/', 'pupp_collect_'));

  const browser = await puppeteer.launch({
    executablePath: await ensureChromiumPath(),
    headless: 'new',
    args: [
      '--no-sandbox','--disable-setuid-sandbox',
      '--disable-dev-shm-usage','--disable-gpu',
      '--no-first-run','--no-zygote',
      '--disable-background-networking',
      '--disable-features=site-per-process,Translate,BackForwardCache',
      `--user-data-dir=${profileDir}`,
      '--lang=pt-BR'
    ],
    defaultViewport: { width: 1280, height: 1024 }
  });

  let page;
  try {
    page = await browser.newPage();
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36');
    await page.setExtraHTTPHeaders({ 'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8' });

    // bloqueia recursos pesados (mantém XHR/fetch/doc liberados)
    await page.setRequestInterception(true);
    page.on('request', req => {
      const t = req.resourceType();
      if (['image','font','media','stylesheet'].includes(t)) req.abort();
      else req.continue();
    });

    // anti-deteção básica
    await page.evaluateOnNewDocument(() => {
      Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
    });

    // 🕵️ farear TODOS os payloads de rede (xhr/fetch/document) e também as URLs
    const sniffed = new Set();
    page.on('response', async (res) => {
      try {
        const rt = res.request().resourceType();
        const url = res.url();
        extractMlbs(url).forEach(id => sniffed.add(id));

        if (!['xhr','fetch','document'].includes(rt)) return;

        // só tenta ler texto de payloads “razoáveis”
        const ct = (res.headers()['content-type'] || '').toLowerCase();
        // até ~2.5MB para evitar memória alta
        const buf = await res.buffer().catch(() => null);
        if (!buf || buf.length > 2_500_000) return;

        // se JSON, ótimo; se não, mesmo assim varre como texto
        const text = buf.toString('utf8');
        extractMlbs(text).forEach(id => sniffed.add(id));
      } catch {}
    });

    const pageSize = 50;
    const seen = new Set();

    for (let offset = 0; seen.size < max && offset <= 600; offset += pageSize) {
      const url = offset === 0
        ? `https://lista.mercadolivre.com.br/_CustId_${sellerId}`
        : `https://lista.mercadolivre.com.br/_CustId_${sellerId}_Desde_${offset + 1}`;

      await page.goto(url, { waitUntil: ['domcontentloaded','networkidle0'], timeout: 60000 });
      await maybeAcceptCookies(page);
      await sleep(800);
      await autoScroll(page, 12, 350);     // força lazy-load

      // 1) DOM (links)
      const viaAnchors = await page.$$eval('a[href*="MLB"]', as =>
        Array.from(new Set(
          as.map(a => (a.getAttribute('href') || '')
            .match(/(MLB-?\d{6,})/i)?.[1])
            .filter(Boolean)
            .map(s => s.replace('-', ''))
        ))
      );

      // 2) Scripts inline
      const viaScripts = await page.evaluate(() => {
        const txt = Array.from(document.scripts).map(s => s.textContent || '').join('\n');
        const m = txt.match(/MLB-?\d{6,}/g) || [];
        return Array.from(new Set(m.map(s => s.replace('-', ''))));
      });

      // 3) HTML renderizado
      const viaHtml = await page.evaluate(() => {
        const html = document.documentElement.innerHTML;
        const m = html.match(/MLB-?\d{6,}/g) || [];
        return Array.from(new Set(m.map(s => s.replace('-', ''))));
      });

      // 4) Rede (XHR/fetch/doc)
      const viaNet = Array.from(sniffed);

      [...viaAnchors, ...viaScripts, ...viaHtml, ...viaNet].forEach(id => seen.add(id));
      const got = viaAnchors.length + viaScripts.length + viaHtml.length + viaNet.length;
      console.log(`[scrape2] offset=${offset} a=${viaAnchors.length} s=${viaScripts.length} h=${viaHtml.length} n=${viaNet.length} unique=${seen.size}`);

      if (got === 0 && offset === 0) {
        // primeira página sem nada: não insiste
        break;
      }
      if (got === 0) {
        // página seguinte sem nada: encerra
        break;
      }
    }

    return Array.from(seen).slice(0, max);
  } finally {
    if (page) { try { await page.close(); } catch {} }
    try { await browser.close(); } catch {}
  }
}




async function headlessCollectIdsFromProfile(nickname, max = 120) {
  const profileDir = fs.mkdtempSync(path.join('/tmp/', 'pupp_profile_'));
  const browser = await puppeteer.launch({
    executablePath: await ensureChromiumPath(),
    headless: 'new',
    args: [
      '--no-sandbox', '--disable-setuid-sandbox',
      '--disable-dev-shm-usage', '--disable-gpu',
      '--no-first-run', '--no-zygote',
      '--disable-background-networking',
      '--disable-features=site-per-process,Translate,BackForwardCache',
      `--user-data-dir=${profileDir}`
    ],
    defaultViewport: { width: 1280, height: 1024 }
  });

  let page;
  try {
    page = await browser.newPage();
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36');
    await page.setExtraHTTPHeaders({ 'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8' });
    await page.goto(`https://www.mercadolivre.com.br/perfil/${encodeURIComponent(nickname)}#search`, { waitUntil: ['domcontentloaded', 'networkidle0'], timeout: 60000 });
    await maybeAcceptCookies(page);
    await sleep(1200);
    await autoScroll(page, 8, 400);

    const ids = await page.evaluate(() => {
      const html = document.documentElement.innerHTML;
      const m = html.match(/MLB-?\d{6,}/g) || [];
      return Array.from(new Set(m.map(s => s.replace('-', ''))));
    });

    console.log(`[scrape2] perfil ${nickname} ids=${ids.length}`);
    return ids.slice(0, max);
  } finally {
    if (page) { try { await page.close(); } catch { } }
    try { await browser.close(); } catch { }
  }
}


// Abre a página do produto e extrai título/preço/vendidos/permalink via DOM/JSON-LD
async function headlessFetchItems(ids) {
  const profileDir = fs.mkdtempSync(path.join('/tmp/', 'pupp_fetch_')); // perfil único

  const browser = await puppeteer.launch({
    executablePath: await ensureChromiumPath(), // <- nome correto
    headless: 'new',
    args: [
      '--no-sandbox', '--disable-setuid-sandbox',
      '--disable-dev-shm-usage', '--disable-gpu',
      '--no-first-run', '--no-zygote',
      '--disable-background-networking',
      '--disable-features=site-per-process,Translate,BackForwardCache',
      `--user-data-dir=${profileDir}`
    ]
  });

  const out = [];
  const pool = Math.min(3, ids.length); // um pouco mais conservador
  let idx = 0;

  async function worker() {
    while (idx < ids.length) {
      const id = ids[idx++];
      const url = `https://produto.mercadolivre.com.br/${id}`;
      let p;
      try {
        p = await browser.newPage();
        await p.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36');
        await p.setExtraHTTPHeaders({ 'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8' });
        await p.goto(url, { waitUntil: 'domcontentloaded', timeout: 60000 });

        const data = await p.evaluate(() => {
          const ld = Array.from(document.querySelectorAll('script[type="application/ld+json"]'))
            .map(s => { try { return JSON.parse(s.textContent || 'null'); } catch { return null; } })
            .flatMap(x => Array.isArray(x) ? x : [x])
            .filter(x => x && (x['@type'] === 'Product' || (Array.isArray(x['@type']) && x['@type'].includes('Product'))));

          let title = '', price = null, permalink = '', sold_quantity = null;

          for (const obj of ld) {
            title ||= obj.name || '';
            const offers = Array.isArray(obj.offers) ? obj.offers[0] : obj.offers;
            const p = offers?.price ?? offers?.priceSpecification?.price;
            if (p != null) {
              const pn = Number(String(p).replace(/[^\d.,-]/g, '').replace('.', '').replace(',', '.'));
              if (!Number.isNaN(pn)) price = pn;
            }
            permalink ||= obj.url || '';
          }

          if (!permalink) {
            const can = document.querySelector('link[rel="canonical"]')?.href;
            if (can) permalink = can;
          }
          if (!title) {
            title = document.querySelector('h1')?.textContent?.trim()
              || document.querySelector('meta[property="og:title"]')?.getAttribute('content') || '';
          }
          if (!price) {
            const frac = document.querySelector('.andes-money-amount__fraction')?.textContent || '';
            const dec = document.querySelector('.andes-money-amount__cents')?.textContent || '';
            const raw = (frac ? frac : '') + (dec ? ',' + dec : '');
            const pn = Number(raw.replace(/\./g, '').replace(',', '.'));
            if (!Number.isNaN(pn)) price = pn;
          }
          if (!sold_quantity) {
            const sold = Array.from(document.querySelectorAll('span, small'))
              .map(e => e.textContent || '')
              .find(t => /vendid/i.test(t));
            if (sold) {
              const n = parseInt(sold.replace(/[^\d]/g, ''), 10);
              if (!Number.isNaN(n)) sold_quantity = n;
            }
          }
          return { title, price, sold_quantity, permalink };
        });

        out.push({ id, ...data });
      } catch {
        out.push({ id, error: 'fetch_failed' });
      } finally {
        if (p) { try { await p.close(); } catch { } }
      }
    }
  }

  try {
    await Promise.all(Array.from({ length: pool }, () => worker()));
  } finally {
    try { await browser.close(); } catch { }
  }
  return out;
}



// Concorrentes (scrape com navegador real): lista anúncios de um seller SEM usar a API
app.get('/api/scrape2/seller/:sellerId', async (req, res) => {
  try {
    const sellerId = req.params.sellerId;
    const max = Math.min(parseInt(req.query.max || '100', 10), 200);
    if (!/^\d{6,}$/.test(sellerId)) return res.status(400).json({ error: 'invalid_seller_id' });

    let ids = await headlessCollectIds(sellerId, max);
    if (!ids.length) {
      // tenta descobrir nickname (usa seu token) e raspa o perfil
      try {
        const nick = await getSellerNickname(req, sellerId);
        if (nick) ids = await headlessCollectIdsFromProfile(nick, max);
      } catch { }
    }
    if (!ids.length) return res.json([]);

    const items = await headlessFetchItems(ids);
    res.json(items);
  } catch (e) {
    console.error('scrape2 error', e?.response?.status, e?.response?.data || e.message);
    res.status(500).json({ error: 'scrape2_failed', detail: e?.response?.data || e.message });
  }
});

// Error handler
app.use((err, req, res, next) => { console.error('Unhandled error:', err); res.status(500).send('Server error'); });

ensureChromiumPath()
  .then(p => console.log('Chromium ready:', p))
  .catch(e => console.error('Chromium prep failed:', e.message));

app.listen(PORT, '0.0.0.0', () => console.log(`MLB Dashboard (multiuser) em http://localhost:${PORT} (prod=${IS_PROD})`));
