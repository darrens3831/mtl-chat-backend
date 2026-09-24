// server.js — Backend MTL Chat
// ------------------------------------------------------------------
// 1) Paiements Stripe (VIP)
// 2) Mise en relation video aleatoire via Socket.IO + relais WebRTC.
// ------------------------------------------------------------------

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const Stripe = require('stripe');
const crypto = require('crypto');

const app = express();
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// Adresse du site (retour après paiement Stripe). Sans « / » final.
// Si la variable n'est pas définie sur Render, on utilise le domaine du site.
const FRONTEND_URL = (process.env.FRONTEND_URL || 'https://mtlchats.com').trim().replace(/\/+$/, '');
app.use(cors({ origin: '*' }));

app.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;
    try {
        event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    } catch (err) {
        console.error('Webhook signature error:', err.message);
        return res.status(400).send('Webhook Error: ' + err.message);
    }
    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        console.log('Paiement confirme pour le plan:', session.metadata && session.metadata.plan);
    }
    res.json({ received: true });
});

app.use(express.json());

app.get('/', (req, res) => {
    res.json({ status: 'ok', message: 'MTL Chat Backend is running' });
});

app.get('/ice-servers', async (req, res) => {
    try {
        const keyId = process.env.CF_TURN_KEY_ID;
        const apiToken = process.env.CF_TURN_API_TOKEN;
        if (!keyId || !apiToken) throw new Error('Cloudflare TURN non configure');
        const r = await fetch(`https://rtc.live.cloudflare.com/v1/turn/keys/${keyId}/credentials/generate-ice-servers`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${apiToken}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ ttl: 86400 })
        });
        if (!r.ok) throw new Error('Erreur Cloudflare ' + r.status);
        const data = await r.json();
        res.json(data.iceServers);
    } catch (err) {
        console.error('ice-servers error:', err.message);
        res.json([
            { urls: 'stun:stun.l.google.com:19302' },
            { urls: 'stun:stun1.l.google.com:19302' }
            ]);
    }
});

// ============== Jeton VIP signé (le statut VIP est décidé par le serveur) ==============
// Clé de signature : VIP_TOKEN_SECRET (à définir sur Render). Les nouveaux jetons sont signés
// avec elle. L'ancienne clé (dérivée de la clé Stripe) reste acceptée en lecture pour que
// les VIP déjà payés ne perdent pas leur accès au moment où tu ajoutes VIP_TOKEN_SECRET.
const LEGACY_VIP_SECRET = crypto.createHash('sha256')
    .update('mtlchat-vip:' + (process.env.STRIPE_SECRET_KEY || '')).digest('hex');
const VIP_SECRET = process.env.VIP_TOKEN_SECRET || LEGACY_VIP_SECRET;
const VIP_VERIFY_SECRETS = Array.from(new Set([VIP_SECRET, LEGACY_VIP_SECRET]));
if (!process.env.VIP_TOKEN_SECRET) console.warn('VIP_TOKEN_SECRET non defini : cle derivee de STRIPE_SECRET_KEY utilisee.');

function b64url(buf) { return Buffer.from(buf).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_'); }
function hmac(secret, body) { return b64url(crypto.createHmac('sha256', secret).update(body).digest()); }
function signVipToken(payload) {
    const body = b64url(JSON.stringify(payload));
    return body + '.' + hmac(VIP_SECRET, body);
}
function sigMatches(sig, expected) {
    return sig.length === expected.length && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
}
// Retourne la date d'expiration (ms) si le jeton est valide et non expiré, sinon 0.
function vipExpiryFromToken(token) {
    try {
        if (typeof token !== 'string' || token.indexOf('.') < 0) return 0;
        const [body, sig] = token.split('.');
        if (!body || !sig) return 0;
        if (!VIP_VERIFY_SECRETS.some((s) => sigMatches(sig, hmac(s, body)))) return 0;
        const data = JSON.parse(Buffer.from(body.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString());
        return (data.exp && data.exp > Date.now()) ? data.exp : 0;
    } catch (e) { return 0; }
}

const PLANS = {
    '1d': { label: '1 jour',  amountCents: 1199, days: 1 },
    '7d': { label: '7 jours', amountCents: 3499, days: 7 },
    '1m': { label: '1 mois',  amountCents: 5999, days: 30 }
};

app.post('/create-checkout-session', async (req, res) => {
  try {
    const planKey = req.body.plan;
    const uiMode = req.body.uiMode === 'embedded' ? 'embedded' : 'hosted';
    const plan = PLANS[planKey];
    if (!plan) return res.status(400).json({ error: 'Plan invalide' });

    const frontend = FRONTEND_URL;

    const params = {
      mode: 'payment',
      ui_mode: uiMode,
      line_items: [{
        price_data: {
          currency: 'cad',
          product_data: { name: 'MTL Chat VIP - ' + plan.label },
          unit_amount: plan.amountCents
        },
        quantity: 1
      }],
      metadata: { plan: planKey }
    };

    if (uiMode === 'embedded') {
      params.return_url = frontend + '/?session_id={CHECKOUT_SESSION_ID}';
    } else {
      params.success_url = frontend + '/?session_id={CHECKOUT_SESSION_ID}';
      params.cancel_url = frontend + '/?vip=cancel';
    }

    const session = await stripe.checkout.sessions.create(params);

    if (uiMode === 'embedded') {
      return res.json({ clientSecret: session.client_secret });
    }
    return res.json({ url: session.url, id: session.id });
  } catch (err) {
    console.error('create-checkout-session error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get('/verify-session', async (req, res) => {
    try {
        const { session_id } = req.query;
        if (!session_id) return res.status(400).json({ error: 'session_id manquant' });
        const session = await stripe.checkout.sessions.retrieve(session_id);
        if (session.payment_status === 'paid') {
            const planKey = session.metadata && session.metadata.plan;
            const plan = PLANS[planKey];
            if (!plan) return res.json({ paid: false });
            // L'expiration part de la date du paiement : réutiliser le même session_id ne prolonge rien.
            const expiresAt = session.created * 1000 + plan.days * 24 * 60 * 60 * 1000;
            const token = signVipToken({ sid: session.id, plan: planKey, exp: expiresAt });
            return res.json({ paid: true, plan: planKey, days: plan.days, expiresAt, token, active: expiresAt > Date.now() });
        }
        res.json({ paid: false });
    } catch (err) {
        console.error('verify-session error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// Vérifie un jeton VIP stocké côté navigateur.
app.post('/vip-status', (req, res) => {
    const exp = vipExpiryFromToken(req.body && req.body.token);
    res.json({ vip: exp > 0, expiresAt: exp });
});

// ============== Socket.IO : mise en relation + relais WebRTC ==============
// Protocole (identique à avant pour le frontend) :
//   client -> serveur : 'find-partner' (profil)  -> commencer / « Suivant »
//                       'signal' { signal, matchId? }, 'chat-message', 'leave-room'
//   serveur -> client : 'matched' { initiator, partnerProfile, matchId }, 'signal',
//                       'partner-left', 'chat-message', 'online-count'
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: '*', methods: ['GET', 'POST'] },
    // Détecte un téléphone verrouillé / un réseau coupé en ~20 s (au lieu de ~45 s par défaut)
    // pour ne pas laisser quelqu'un jumelé avec un « fantôme ».
    pingInterval: 10000,
    pingTimeout: 10000,
    // Le profil envoyé à « Commencer » contient la photo (image en base64). Avec la limite par
    // défaut de Socket.IO (1 Mo), une photo de téléphone faisait couper la connexion.
    maxHttpBufferSize: 6e6
});

// Après « Suivant » (ou un départ), on évite de remettre les deux mêmes personnes ensemble
// pendant ce délai. S'il n'y a vraiment personne d'autre, ils se retrouvent après ce délai.
// Réglable sur Render avec la variable REMATCH_COOLDOWN_MS (en millisecondes).
const REMATCH_COOLDOWN_MS = Number(process.env.REMATCH_COOLDOWN_MS) || 10000;
const SWEEP_INTERVAL_MS = 1000;
const CHAT_MAX_CHARS = 500;

const waiting = new Map();     // socket.id -> socket (ordre d'insertion = ordre d'arrivée dans la file)
const partnerOf = new Map();   // socket.id -> socket.id du partenaire
const matchIdOf = new Map();   // socket.id -> identifiant de la mise en relation en cours
const profileOf = new Map();   // socket.id -> profil public (jamais le jeton VIP)
const recentPairs = new Map(); // "idA|idB" -> date (ms) avant laquelle on ne les remet pas ensemble

function pairKey(a, b) { return a < b ? a + '|' + b : b + '|' + a; }
function inCooldown(a, b) {
    const until = recentPairs.get(pairKey(a, b));
    return !!until && until > Date.now();
}

// Accepte 'F'/'M' comme avant, plus les variantes françaises ('femme', 'homme', 'H'...).
function normGender(g) {
    const v = String(g || '').trim().toLowerCase();
    return ['f', 'femme', 'femmes', 'fille', 'female', 'woman'].includes(v) ? 'F' : 'M';
}
function normFilter(f) {
    const v = String(f || '').trim().toLowerCase();
    if (['f', 'femme', 'femmes', 'fille', 'filles', 'female', 'woman', 'women'].includes(v)) return 'F';
    if (['m', 'h', 'homme', 'hommes', 'gars', 'male', 'man', 'men'].includes(v)) return 'M';
    return 'random';
}

// Profil public transmis au partenaire : seulement les champs affichés par le site, nettoyés.
// Le site insère le nom, la ville et la photo dans la page (innerHTML) : on retire les
// caractères qui permettraient d'y injecter du code, et on n'accepte qu'une vraie image.
const NAME_MAX_CHARS = 30;
const LOCATION_MAX_CHARS = 60;
const PHOTO_MAX_CHARS = 700000; // ~500 Ko d'image ; au-delà, le partenaire voit l'initiale
const PHOTO_RE = /^data:image\/(?:jpeg|jpg|png|webp|gif);base64,[A-Za-z0-9+/]+={0,2}$/;
// Connexion Google : la photo est un lien vers les serveurs d'images de Google.
const GOOGLE_PHOTO_RE = /^https:\/\/lh[0-9]+\.googleusercontent\.com\/[A-Za-z0-9_\-\/=.~%]+$/;

function cleanText(v, max, fallback) {
    if (typeof v !== 'string') return fallback;
    const s = v.replace(/[\u0000-\u001f\u007f<>"'`\\]/g, '').replace(/\s+/g, ' ').trim().slice(0, max);
    return s || fallback;
}
function cleanPhoto(v) {
    if (typeof v !== 'string') return null;
    if (v.length <= 2000 && GOOGLE_PHOTO_RE.test(v)) return v;
    return (v.length <= PHOTO_MAX_CHARS && PHOTO_RE.test(v)) ? v : null;
}
function publicProfile(raw, isVip) {
    const p = (raw && typeof raw === 'object') ? raw : {};
    const country = String(p.country || '').trim().toUpperCase();
    return {
        gender: normGender(p.gender),
        filter: isVip ? normFilter(p.filter) : 'random',
        name: cleanText(p.name, NAME_MAX_CHARS, 'Anonyme'),
        location: cleanText(p.location, LOCATION_MAX_CHARS, 'Montréal, QC'),
        country: /^[A-Z]{2}$/.test(country) ? country : 'CA',
        photo: cleanPhoto(p.photo)
    };
}

// Le filtre de genre (F / M) est réservé aux VIP ; 'random' accepte tout le monde.
function accepts(a, b) { return a.filter === 'random' || a.filter === b.gender; }
function compatible(idA, idB) {
    const a = profileOf.get(idA), b = profileOf.get(idB);
    return !!a && !!b && accepts(a, b) && accepts(b, a);
}
function canPair(a, b) {
    return a.id !== b.id && a.connected && b.connected &&
        !partnerOf.has(a.id) && !partnerOf.has(b.id) &&
        compatible(a.id, b.id) && !inCooldown(a.id, b.id);
}

function pair(initiator, other) {
    waiting.delete(initiator.id);
    waiting.delete(other.id);
    const matchId = crypto.randomBytes(8).toString('hex');
    partnerOf.set(initiator.id, other.id);
    partnerOf.set(other.id, initiator.id);
    matchIdOf.set(initiator.id, matchId);
    matchIdOf.set(other.id, matchId);
    // Un seul initiateur : c'est lui qui crée l'offre WebRTC.
    initiator.emit('matched', { initiator: true, partnerProfile: profileOf.get(other.id) || {}, matchId });
    other.emit('matched', { initiator: false, partnerProfile: profileOf.get(initiator.id) || {}, matchId });
}

// Cherche un partenaire dans la file (le plus ancien compatible d'abord), sinon met en attente.
function tryMatch(socket) {
    if (!socket.connected || partnerOf.has(socket.id)) return;
    for (const other of waiting.values()) {
        if (canPair(socket, other)) { pair(socket, other); return; }
    }
    // S'il attendait déjà (double clic, changement de filtre), il garde sa place.
    if (!waiting.has(socket.id)) waiting.set(socket.id, socket);
}

function leaveQueue(socket) { waiting.delete(socket.id); }

function breakPair(socket, notify) {
    const partnerId = partnerOf.get(socket.id);
    if (!partnerId) return;
    partnerOf.delete(socket.id);
    partnerOf.delete(partnerId);
    matchIdOf.delete(socket.id);
    matchIdOf.delete(partnerId);
    recentPairs.set(pairKey(socket.id, partnerId), Date.now() + REMATCH_COOLDOWN_MS);
    if (notify) {
        const partnerSock = io.sockets.sockets.get(partnerId);
        if (partnerSock) partnerSock.emit('partner-left');
    }
}

// Filet de sécurité : toutes les secondes, on jumelle les personnes en attente qui peuvent
// l'être (ex. fin du délai anti-retour) et on nettoie les entrées périmées.
function sweep() {
    const now = Date.now();
    for (const [key, until] of recentPairs) if (until <= now) recentPairs.delete(key);
    for (const [id, s] of waiting) if (!s.connected || partnerOf.has(id)) waiting.delete(id);
    if (waiting.size < 2) return;
    const list = Array.from(waiting.values());
    for (let i = 0; i < list.length; i++) {
        const a = list[i];
        if (!waiting.has(a.id)) continue;
        for (let j = i + 1; j < list.length; j++) {
            const b = list[j];
            if (waiting.has(b.id) && canPair(a, b)) { pair(b, a); break; }
        }
    }
}
setInterval(() => { try { sweep(); } catch (e) { console.error('sweep error:', e); } }, SWEEP_INTERVAL_MS).unref();

// Nombre de personnes en ligne : regroupé (max 2 fois/s) pour ne pas inonder tout le monde.
let countTimer = null;
function broadcastCount() {
    if (countTimer) return;
    countTimer = setTimeout(() => { countTimer = null; io.emit('online-count', io.engine.clientsCount); }, 500);
}

function clampChat(msg) {
    if (typeof msg === 'string') return msg.slice(0, CHAT_MAX_CHARS);
    if (msg && typeof msg === 'object') {
        const m = Object.assign({}, msg);
        if (typeof m.text === 'string') m.text = m.text.slice(0, CHAT_MAX_CHARS);
        if (typeof m.message === 'string') m.message = m.message.slice(0, CHAT_MAX_CHARS);
        return m;
    }
    return msg;
}

// Petit état de santé pour vérifier le serveur : /stats
app.get('/stats', (req, res) => {
    res.json({ online: io.engine.clientsCount, waiting: waiting.size, pairs: partnerOf.size / 2 });
});

io.on('connection', (socket) => {
    // Une erreur dans un gestionnaire ne doit jamais faire tomber le serveur pour tout le monde.
    const on = (ev, fn) => socket.on(ev, (...args) => {
        try { fn(...args); } catch (e) { console.error(ev + ' error:', e); }
    });

    socket.emit('online-count', io.engine.clientsCount);
    broadcastCount();

    // Commencer ou « Suivant »
    on('find-partner', (profile) => {
        const isVip = vipExpiryFromToken(profile && profile.vipToken) > 0;
        // Seuls les champs publics nettoyés sont gardés (jamais le jeton VIP ni autre chose).
        profileOf.set(socket.id, publicProfile(profile, isVip));
        breakPair(socket, true); // libère l'ancien partenaire (il reçoit 'partner-left')
        tryMatch(socket);
    });

    // Le frontend envoie { signal: { type, sdp/candidate } } (+ matchId facultatif). On transmet
    // au partenaire l'objet 'signal' déballé, car son handler lit signal.type / .sdp / .candidate.
    on('signal', (data) => {
        const partnerId = partnerOf.get(socket.id);
        if (!partnerId) return;
        // Signal d'une ancienne connexion (après « Suivant ») : on l'ignore.
        if (data && data.matchId && data.matchId !== matchIdOf.get(socket.id)) return;
        const partnerSock = io.sockets.sockets.get(partnerId);
        if (!partnerSock) return;
        const payload = (data && data.signal !== undefined) ? data.signal : data;
        partnerSock.emit('signal', payload);
    });

    on('chat-message', (msg) => {
        const partnerId = partnerOf.get(socket.id);
        if (!partnerId) return;
        const partnerSock = io.sockets.sockets.get(partnerId);
        if (partnerSock) partnerSock.emit('chat-message', clampChat(msg));
    });

    on('leave-room', () => { breakPair(socket, true); leaveQueue(socket); });

    socket.on('disconnect', () => {
        breakPair(socket, true);
        leaveQueue(socket);
        profileOf.delete(socket.id);
        broadcastCount();
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log('MTL Chat Backend (Stripe + Socket.IO) en ecoute sur le port ' + PORT);
});
