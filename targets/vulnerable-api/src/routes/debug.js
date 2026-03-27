const express = require('express');
const router = express.Router();

// GET /debug/env — exposes all environment variables
router.get('/env', (req, res) => {
  return res.json(process.env);
});

// GET /debug/info — exposes runtime versions and package info
router.get('/info', (req, res) => {
  return res.json({
    node: process.version,
    platform: process.platform,
    arch: process.arch,
    uptime: process.uptime(),
    memoryUsage: process.memoryUsage(),
    cwd: process.cwd(),
    // Intentional: exposes package.json dependencies
    packages: require('../../package.json').dependencies,
  });
});

// GET /debug/health
router.get('/health', (req, res) => res.json({ status: 'ok' }));

module.exports = router;
