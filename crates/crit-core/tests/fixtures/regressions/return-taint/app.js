// Regression: cross-function tainted RETURN must be detected even when the
// caller has parameters. In 0.1 the synthetic param taint of `req` masked
// the summary-derived source taint of getB()'s return value.
function getB(req) {
  return req.query.b;
}

function handler(req) {
  const n = getB(req);
  db.query("SELECT * FROM t WHERE b = " + n);
}
