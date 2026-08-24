// Sanitized variants that must NOT produce taint findings.
const express = require('express');
const db = require('./db');
const app = express();

app.get('/user', (req, res) => {
  const id = parseInt(req.query.id, 10);
  const sql = "SELECT * FROM users WHERE id = " + id;
  db.query(sql);
});

app.get('/file', (req, res) => {
  const name = path.basename(req.query.name);
  fs.readFileSync(name);
});
