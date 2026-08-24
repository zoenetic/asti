const express = require('express');
const db = require('./db');
const { exec } = require('child_process');
const app = express();

app.get('/user', (req, res) => {
  const id = req.query.id;
  const sql = "SELECT * FROM users WHERE id = " + id;
  db.query(sql, (e, rows) => res.json(rows));
});

app.get('/safe', (req, res) => {
  const id = parseInt(req.query.id);
  db.query("SELECT * FROM users WHERE id = " + id);
});

function buildCmd(name) {
  return "ping " + name;
}

app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec(buildCmd(host));
});

const password = "hunter2secret";
eval(req.query.code);
