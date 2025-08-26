
# MLB Dashboard — Multi-User (deploy pronto)

Cada usuário informa **Client ID / Client Secret / Redirect URI** (do próprio app do Mercado Libre) e usa o painel. Tokens ficam na **sessão** (cookie httpOnly).

## Rodando local
```
npm install
cp .env.example .env   # edite SESSION_SECRET
npm run dev
```
Acesse http://localhost:3000 (para OAuth local, use túnel HTTPS como cloudflared/ngrok e cadastre a Redirect URI do domínio do túnel).

## Deploy (Render, Railway etc.)
1. Crie um serviço **Web** Node 18+ e publique este repositório.
2. Variáveis de ambiente:
   - `NODE_ENV=production`
   - `SESSION_SECRET=uma_string_bem_grande`
3. Start command: `node server.js`
4. Após deploy, o app estará em **https://SEU-DOMINIO**. No Mercado Libre Developers, cadastre a Redirect URI:  
   `https://SEU-DOMINIO/oauth/callback`
5. Acesse o site em **https://SEU-DOMINIO**, tela de Setup já sugere o Redirect correto. Salve, Conecte, Autorize e use.
# REPOSITORIO_TESTE_MLB
