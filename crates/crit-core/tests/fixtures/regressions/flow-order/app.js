// Regression: the sink reads `v` BEFORE the tainted assignment; a
// flow-order-aware engine must not report, and must never emit a trace that
// runs backwards in time.
function flowOrder(req) {
  let v = "constant";
  db.query("SELECT * FROM t WHERE a = " + v);
  v = req.query.a;
  return v;
}
