const db = require('./db');

function direct(req) {
  db.query("SELECT * FROM users WHERE id = " + req.query.id); // crit:expect js.sql-injection
}

function viaVariable(req) {
  const id = req.body.id;
  // crit:expect js.sql-injection
  db.query(`SELECT * FROM users WHERE id = ${id}`);
}

function sanitized(req) {
  const id = parseInt(req.query.id);
  db.query("SELECT * FROM users WHERE id = " + id); // crit:expect-not js.sql-injection
}

function constantOnly() {
  const id = 42;
  db.query("SELECT * FROM users WHERE id = " + id); // crit:expect-not js.sql-injection
}
