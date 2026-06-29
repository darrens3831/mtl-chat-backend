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

const app = express();
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

const ALLOWED_ORIGIN = process.env.FRONTEND_URL || '*';
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

    const frontend = process.env.FRONTEND_URL || ALLOWED_ORIGIN;

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
            return res.json({ paid: true, plan: planKey, days: plan ? plan.days : 0 });
        }
        res.json({ paid: false });
    } catch (err) {
        console.error('verify-session error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// ============== Socket.IO : mise en relation + relais WebRTC ==============
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*', methods: ['GET', 'POST'] } });

let waiting = [];
const partnerOf = {};
const profileOf = {};

function broadcastCount() { io.emit('online-count', io.engine.clientsCount); }
function leaveQueue(socket) { waiting = waiting.filter(s => s.id !== socket.id); }

function breakPair(socket, notify) {
    const partnerId = partnerOf[socket.id];
    if (partnerId) {
        delete partnerOf[partnerId];
        delete partnerOf[socket.id];
        if (notify) {
            const partnerSock = io.sockets.sockets.get(partnerId);
            if (partnerSock) partnerSock.emit('partner-left');
        }
    }
}

function tryMatch(socket) {
    leaveQueue(socket);
    const other = waiting.find(s => s.id !== socket.id && s.connected);
    if (other) {
        leaveQueue(other);
        partnerOf[socket.id] = other.id;
        partnerOf[other.id] = socket.id;
        socket.emit('matched', { initiator: true,  partnerProfile: profileOf[other.id]  || {} });
        other.emit('matched',  { initiator: false, partnerProfile: profileOf[socket.id] || {} });
    } else {
        waiting.push(socket);
    }
}

io.on('connection', (socket) => {
    broadcastCount();

    socket.on('find-partner', (profile) => {
        profileOf[socket.id] = profile || {};
        breakPair(socket, true);
        tryMatch(socket);
    });

    // Le frontend envoie { signal: { type, sdp/candidate } }. On transmet au
    // partenaire l'objet interne 'signal' non emballe, car son handler lit
    // directement signal.type / signal.sdp / signal.candidate.
    socket.on('signal', (data) => {
        const partnerId = partnerOf[socket.id];
        if (!partnerId) return;
        const partnerSock = io.sockets.sockets.get(partnerId);
        if (!partnerSock) return;
        const payload = (data && data.signal !== undefined) ? data.signal : data;
        partnerSock.emit('signal', payload);
    });

    socket.on('chat-message', (msg) => {
        const partnerId = partnerOf[socket.id];
        if (partnerId) {
            const partnerSock = io.sockets.sockets.get(partnerId);
            if (partnerSock) partnerSock.emit('chat-message', msg);
        }
    });

    socket.on('leave-room', () => { breakPair(socket, true); leaveQueue(socket); });

    socket.on('disconnect', () => {
        breakPair(socket, true);
        leaveQueue(socket);
        delete profileOf[socket.id];
        broadcastCount();
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log('MTL Chat Backend (Stripe + Socket.IO) en ecoute sur le port ' + PORT);
});
