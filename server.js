// server.js — Backend de paiement pour MTL Chat (Stripe)
// ---------------------------------------------------------
// Ce serveur fait 2 choses :
// 1. Crée une session de paiement Stripe quand un visiteur clique "Payer"
// 2. Vérifie auprès de Stripe (avec ta clé secrète) que le paiement est bien confirmé
//    avant de dire au site "active le VIP" — jamais le navigateur seul ne décide ça.

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const Stripe = require('stripe');

const app = express();
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// Mets ici l'adresse de ton site une fois en ligne (ex: https://mtlchat.com)
// Pendant les tests, tu peux laisser "*" mais il faudra le restreindre en production.
app.use(cors({ origin: '*' }));
app.use(express.json());

// ---------- Route racine (health check pour Render) ----------
app.get('/', (req, res) => {
    res.json({ status: 'ok', message: 'MTL Chat Backend is running' });
});

// ---------- Définition des 3 plans VIP (doit correspondre à mtl-chat.html) ----------
const PLANS = {
    '1d': { label: '1 jour',   amountCents: 1199, days: 1  },
    '7d': { label: '7 jours',  amountCents: 3499, days: 7  },
    '1m': { label: '1 mois',   amountCents: 5999, days: 30 }
};

// ---------- 1) Créer une session de paiement Stripe ----------
// Le front-end appelle cette route quand l'utilisateur clique "Payer"
app.post('/create-checkout-session', async (req, res) => {
    try {
          const { plan } = req.body;
          const planInfo = PLANS[plan];
          if (!planInfo) return res.status(400).json({ error: 'Plan invalide' });

      const session = await stripe.checkout.sessions.create({
              mode: 'payment',
              payment_method_types: ['card'],
              line_items: [{
                        price_data: {
                                    currency: 'cad',
                                    product_data: { name: `MTL Chat VIP — ${planInfo.label}` },
                                    unit_amount: planInfo.amountCents
                        },
                        quantity: 1
              }],
              metadata: { plan }, // on garde le plan choisi pour le retrouver après paiement
              success_url: `${process.env.FRONTEND_URL}/?session_id={CHECKOUT_SESSION_ID}&vip=success`,
              cancel_url:  `${process.env.FRONTEND_URL}/?vip=cancel`
      });

      res.json({ url: session.url });
    } catch (err) {
          console.error(err);
          res.status(500).json({ error: 'Impossible de créer la session de paiement' });
    }
});

// ---------- 2) Vérifier qu'un paiement a vraiment été payé ----------
// Le front-end appelle cette route au retour de Stripe (avec ?session_id=...)
// pour savoir s'il peut activer le VIP. La vérification se fait ICI, côté serveur,
// jamais dans le navigateur (sinon n'importe qui pourrait tricher).
app.get('/verify-session', async (req, res) => {
    try {
          const { session_id } = req.query;
          if (!session_id) return res.status(400).json({ error: 'session_id manquant' });

      const session = await stripe.checkout.sessions.retrieve(session_id);

      if (session.payment_status === 'paid') {
              const plan = session.metadata.plan;
              const planInfo = PLANS[plan];
              const days = planInfo ? planInfo.days : 1;
              const expiresAt = Date.now() + days * 24 * 60 * 60 * 1000;
              res.json({ paid: true, plan, expiresAt });
      } else {
              res.json({ paid: false });
      }
    } catch (err) {
          console.error(err);
          res.status(500).json({ error: 'Impossible de vérifier le paiement' });
    }
});

// ---------- 3) Webhook Stripe (optionnel mais recommandé) ----------
app.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

           try {
                 event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
           } catch (err) {
                 console.error('Signature webhook invalide:', err.message);
                 return res.sendStatus(400);
           }

           if (event.type === 'checkout.session.completed') {
                 const session = event.data.object;
                 console.log(`✅ Paiement confirmé pour le plan: ${session.metadata.plan}`);
                 // Ici, dans une vraie version, tu mettrais à jour une base de données
      // (ex: marquer l'utilisateur comme VIP jusqu'à telle date).
           }

           res.json({ received: true });
});

const PORT = process.env.PORT || 4242;
app.listen(PORT, () => console.log(`✅ Serveur MTL Chat backend démarré sur le port ${PORT}`));
