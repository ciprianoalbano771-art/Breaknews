// Servidor simples: serve a página e bloqueia acesso direto aos vídeos.
// Os vídeos só são entregues quando pedidos pelo script da página
// (cabeçalho X-Video-Token + pedido vindo do mesmo site).
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ---------- Aviso de pagamento no Telegram ----------
// Definir no alojamento (nunca escrever os valores aqui):
//   SMOOPAY_WEBHOOK_SECRET  — o mesmo segredo colocado no painel do Smoopay
//   TELEGRAM_BOT_TOKEN      — token dado pelo @BotFather
//   TELEGRAM_CHAT_ID        — o teu chat.id
const WEBHOOK_SECRET = process.env.SMOOPAY_WEBHOOK_SECRET || '';
const TG_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TG_CHAT = process.env.TELEGRAM_CHAT_ID || '';

function iguais(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

// O formato exato da assinatura do Smoopay não está documentado publicamente,
// por isso aceitamos as formas mais comuns: HMAC-SHA256 do corpo (hex ou base64,
// com ou sem prefixo "sha256=") num cabeçalho ou campo do JSON, o próprio segredo
// num cabeçalho/campo, ou o segredo no próprio URL (?key=SEGREDO).
const NOME_ASSINATURA = /sign|secret|webhook|hmac|token|hash|key/i;

function assinaturaValida(corpo, headers, query, ev) {
  if (!WEBHOOK_SECRET) return false;
  const hex = crypto.createHmac('sha256', WEBHOOK_SECRET).update(corpo).digest('hex');
  const b64 = Buffer.from(hex, 'hex').toString('base64');
  const confere = (valor) => {
    const v = String(valor).trim().replace(/^sha256=/i, '');
    return iguais(v, hex) || iguais(v, b64) || iguais(v, WEBHOOK_SECRET);
  };
  const candidatos = [
    ...Object.entries(headers),
    ...query.entries(),
    ...Object.entries(ev && typeof ev === 'object' ? ev : {}),
  ];
  return candidatos.some(([nome, valor]) =>
    NOME_ASSINATURA.test(nome) && (typeof valor === 'string' || typeof valor === 'number') && confere(valor));
}

function procurar(obj, chaves) {
  if (!obj || typeof obj !== 'object') return undefined;
  for (const [k, v] of Object.entries(obj)) {
    if (chaves.includes(k.toLowerCase()) && (typeof v === 'string' || typeof v === 'number')) return v;
    const dentro = procurar(v, chaves);
    if (dentro !== undefined) return dentro;
  }
}

function enviarTelegram(texto) {
  if (!TG_TOKEN || !TG_CHAT) return console.log('Telegram não configurado. Mensagem:\n' + texto);
  const dados = JSON.stringify({ chat_id: TG_CHAT, text: texto });
  const req = https.request({
    hostname: 'api.telegram.org',
    path: '/bot' + TG_TOKEN + '/sendMessage',
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(dados) },
  }, (r) => {
    let resp = '';
    r.on('data', (c) => resp += c);
    r.on('end', () => console.log('Telegram respondeu', r.statusCode, r.statusCode === 200 ? 'OK' : resp.slice(0, 200)));
  });
  req.on('error', (e) => console.log('Erro Telegram:', e.message));
  req.end(dados);
}

function webhookSmoopay(req, res) {
  const partes = [];
  req.on('data', (p) => partes.push(p));
  req.on('end', () => {
    const corpo = Buffer.concat(partes);
    const query = new URL(req.url, 'http://x').searchParams;
    let ev = {};
    try { ev = JSON.parse(corpo.toString('utf8')); } catch (e) {}
    if (!assinaturaValida(corpo, req.headers, query, ev)) {
      // Só NOMES (nunca valores secretos), para ajustar a verificação se preciso
      console.log('Webhook rejeitado.',
        '| Remetente:', req.headers['user-agent'] || '?',
        '| Cabeçalhos:', Object.keys(req.headers).join(', '),
        '| Campos do URL:', [...query.keys()].join(', ') || '(nenhum)',
        '| Campos do JSON:', Object.keys(ev || {}).join(', ') || '(nenhum)',
        '| Segredo definido:', WEBHOOK_SECRET ? 'sim' : 'NÃO');
      res.writeHead(401); return res.end('invalid signature');
    }
    console.log('Webhook Smoopay recebido:', corpo.toString('utf8').slice(0, 2000));

    const evento = procurar(ev, ['event', 'type']) || '';
    const status = procurar(ev, ['status']) || '';
    const estado = [evento, status].filter(Boolean).join(' / ') || 'pagamento';
    const valor = procurar(ev, ['amount', 'value', 'total', 'valor']);
    const moeda = procurar(ev, ['currency', 'moeda']) || '';
    const email = procurar(ev, ['email', 'customer_email', 'payer_email']);
    const nome = procurar(ev, ['name', 'customer_name', 'payer_name', 'nome']);
    const id = procurar(ev, ['id', 'transaction_id', 'payment_id', 'reference']);
    const cliente = nome || email || 'Cliente';

    // Classifica o evento pelo nome/estado
    const e = estado.toLowerCase();
    let titulo;
    if (/fail|declin|refus|reject|cancel|abandon|expir|void|recus|falh|cancelad|expirad/.test(e)) {
      titulo = '❌ ' + cliente + ' não pagou';
    } else if (/refund|chargeback|reembols|estorn/.test(e)) {
      titulo = '↩️ Reembolso: ' + cliente;
    } else if (/pend|wait|process|creat|init|aguard|iniciad/.test(e)) {
      titulo = '⏳ ' + cliente + ' iniciou o pagamento (ainda não pagou)';
    } else if (/paid|success|succeed|complet|approv|confirm|captur|pago|aprovad|conclu/.test(e)) {
      titulo = '✅ ' + cliente + ' pagou';
    } else {
      titulo = 'ℹ️ Smoopay: ' + cliente;
    }

    enviarTelegram([
      titulo,
      'Estado: ' + estado,
      valor !== undefined ? 'Valor: ' + valor + ' ' + moeda : null,
      nome ? 'Nome: ' + nome : null,
      email ? 'Email: ' + email : null,
      id ? 'ID: ' + id : null,
    ].filter(Boolean).join('\n'));

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end('{"ok":true}');
  });
}

const PORT = process.env.PORT || 8080;
const ROOT = __dirname;
// Endereço secreto da página de acesso (redirecionamento após pagamento).
// Pode ser trocado no alojamento com a variável ACCESS_SLUG.
const ACESSO_PATH = '/acesso/' + (process.env.ACCESS_SLUG || 'ccacc95f4e4849afe7631918');

// Vídeos que podem ser servidos: chave pedida pelo script + página de onde tem de vir.
// (o video_4.mp4 original nunca é servido)
const VIDEOS = {
  '/videos/teaser.mp4': { token: 'sc18-teaser', pagina: null },
  '/videos/completo.mp4': { token: 'sc18-full', pagina: ACESSO_PATH },
};
// Únicos ficheiros públicos (tudo o resto dá 403)
const PUBLICOS = new Set(['/index.html']);

const TIPOS = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mp4': 'video/mp4',
  '.jpg': 'image/jpeg',
  '.png': 'image/png',
  '.webp': 'image/webp',
};

function negar(res) {
  res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('403 — Acesso negado');
}

http.createServer((req, res) => {
  let url = decodeURIComponent(req.url.split('?')[0]);
  if (url === '/') url = '/index.html';

  if (url === '/webhook/smoopay' && req.method === 'POST') return webhookSmoopay(req, res);

  // Página de acesso (só pelo endereço secreto)
  if (url === ACESSO_PATH || url === ACESSO_PATH + '/') url = '/acesso.html';
  else if (url.startsWith('/videos/')) {
    const regra = VIDEOS[url];
    const host = req.headers.host || '';
    const referer = req.headers.referer || '';
    const mesmoSite = referer.startsWith('http://' + host + '/') || referer.startsWith('https://' + host + '/');
    const paginaCerta = !regra || !regra.pagina ||
      referer.split('?')[0].replace(/\/$/, '').endsWith(regra.pagina);
    const doScript = regra && req.headers['x-video-token'] === regra.token;
    const abertoDireto = req.headers['sec-fetch-dest'] === 'document';
    if (!regra || !doScript || !mesmoSite || !paginaCerta || abertoDireto) {
      return negar(res);
    }
  } else if (!PUBLICOS.has(url)) {
    // server.js, acesso.html direto, package.json, etc.
    return negar(res);
  }

  const ficheiro = path.join(ROOT, url);
  if (!ficheiro.startsWith(ROOT)) return negar(res);

  fs.stat(ficheiro, (err, st) => {
    if (err || !st.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('404');
    }
    res.writeHead(200, {
      'Content-Type': TIPOS[path.extname(ficheiro)] || 'application/octet-stream',
      'Content-Length': st.size,
      'Cache-Control': url.startsWith('/videos/') || url === '/acesso.html' ? 'no-store' : 'no-cache',
      'X-Robots-Tag': 'noindex, nofollow',
      'Referrer-Policy': 'same-origin',
    });
    fs.createReadStream(ficheiro).pipe(res);
  });
}).listen(PORT, () => console.log('Servidor em http://localhost:' + PORT));
