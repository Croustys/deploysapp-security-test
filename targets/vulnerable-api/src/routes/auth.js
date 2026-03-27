const express = require('express');
const jwt = require('jsonwebtoken');
const router = express.Router();

// Intentional vulnerability: weak secret read from env (JWT_SECRET=secret123)
const JWT_SECRET = process.env.JWT_SECRET || 'secret123';

// POST /auth/login
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  // Intentional: hardcoded credentials, no rate limiting
  if (username === 'admin' && password === 'admin123') {
    // Intentional: no expiry, weak secret, algorithm not enforced
    const token = jwt.sign({ user: username, role: 'admin' }, JWT_SECRET);
    return res.json({ token });
  }
  if (username === 'user' && password === 'user123') {
    const token = jwt.sign({ user: username, role: 'user' }, JWT_SECRET);
    return res.json({ token });
  }
  return res.status(401).json({ error: 'invalid credentials' });
});

module.exports = router;
