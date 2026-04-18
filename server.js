const express = require('express');
const fetch = require('node-fetch');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// PayGate.to checkout endpoint
app.post('/api/checkout', async (req, res) => {
  const { items, total } = req.body;

  const PAYGATE_API_KEY  = process.env.PAYGATE_API_KEY  || '';
  const PAYGATE_STORE_ID = process.env.PAYGATE_STORE_ID || '';

  if (!PAYGATE_API_KEY || !PAYGATE_STORE_ID) {
    return res.status(500).json({ error: 'PayGate credentials not configured.' });
  }

  try {
    const response = await fetch('https://paygate.to/api/v1/invoices', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${PAYGATE_API_KEY}`
      },
      body: JSON.stringify({
        store_id:    PAYGATE_STORE_ID,
        amount:      total.toFixed(2),
        currency:    'USD',
        description: 'FutureBioChem Research Peptides',
        items:       items.map(i => ({
          name:     i.name,
          quantity: i.qty,
          price:    i.price
        })),
        redirect_url: `http://localhost:${PORT}/thank-you`,
        cancel_url:   `http://localhost:${PORT}/`
      })
    });

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json({ error: data.message || 'PayGate error' });
    }

    res.json({ invoiceUrl: data.invoice_url || data.url });
  } catch (err) {
    console.error('Checkout error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Catch-all — serve the SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`FutureBioChem running at http://localhost:${PORT}`);
});
