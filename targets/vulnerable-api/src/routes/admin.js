const express = require('express');
const router = express.Router();

// GET /admin — intentional: missing authorization check entirely
router.get('/', (req, res) => {
  return res.json({
    message: 'admin panel — no auth required',
    users: ['admin', 'alice', 'bob'],
    db_password: process.env.DB_PASS,
    jwt_secret: process.env.JWT_SECRET,
    config: {
      node_env: process.env.NODE_ENV,
      debug_enabled: process.env.DEBUG_ENABLED,
    }
  });
});

module.exports = router;
