const express = require('express');
const router = express.Router();

// Fake user store
const users = [
  { id: 1, user: 'admin', role: 'admin', email: 'admin@example.com', ssn: '111-11-1111', creditCard: '4111111111111111' },
  { id: 2, user: 'alice', role: 'user',  email: 'alice@example.com', ssn: '222-22-2222', creditCard: '4222222222222222' },
  { id: 3, user: 'bob',   role: 'user',  email: 'bob@example.com',   ssn: '333-33-3333', creditCard: '4333333333333333' },
];

// GET /users/:id — IDOR: no ownership check
router.get('/:id', (req, res) => {
  const user = users.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'not found' });
  // Intentional IDOR: returns full record including PII to any caller
  return res.json(user);
});

// PUT /users/:id — mass assignment: accepts any field including role
router.put('/:id', (req, res) => {
  const idx = users.findIndex(u => u.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'not found' });
  // Intentional mass assignment: spreads all request body fields onto user object
  users[idx] = { ...users[idx], ...req.body };
  return res.json(users[idx]);
});

module.exports = router;
