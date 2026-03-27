/**
 * Vulnerable Node.js/Express API — intentionally insecure for security testing.
 * DO NOT deploy this to any real environment.
 */
const express = require('express');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Import routes
const authRoutes = require('./routes/auth');
const usersRoutes = require('./routes/users');
const adminRoutes = require('./routes/admin');
const debugRoutes = require('./routes/debug');

app.get('/health', (req, res) => res.json({ status: 'ok' }));
app.get('/', (req, res) => res.json({
  service: 'vulnerable-api',
  endpoints: [
    'POST /auth/login    (weak JWT)',
    'GET  /users/:id     (IDOR, mass assignment)',
    'GET  /admin         (missing authz)',
    'GET  /debug/env     (env var leakage)',
    'GET  /debug/info    (version info)',
  ]
}));

app.use('/auth', authRoutes);
app.use('/users', usersRoutes);
app.use('/admin', adminRoutes);
app.use('/debug', debugRoutes);

// Intentional: global error handler exposes stack traces
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log(`vulnerable-api listening on :${PORT}`));
