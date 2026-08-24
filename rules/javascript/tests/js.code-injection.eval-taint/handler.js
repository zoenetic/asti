function handler(req) {
  const code = req.query.cb;
  eval(code); // crit:expect js.code-injection.eval-taint
}

function fromArgv() {
  Function(process.argv[2]); // crit:expect js.code-injection.eval-taint
}

function constantCode() {
  const code = "1 + 1";
  eval(code); // crit:expect-not js.code-injection.eval-taint
}

function sanitizedCode(req) {
  const n = Number(req.query.n);
  eval(n); // crit:expect-not js.code-injection.eval-taint
}
