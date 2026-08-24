// The `vm` module is an importable code-execution sink; aliased imports are
// only caught by identity resolution.
import { runInNewContext as evalCode } from 'vm';
import { compileFunction } from 'vm';

function run(req) {
  evalCode(req.query.code); // crit:expect js.code-injection.eval-taint
}

function compile(req) {
  compileFunction(req.body.src); // crit:expect js.code-injection.eval-taint
}

function safeConstant() {
  evalCode("1 + 1"); // crit:expect-not js.code-injection.eval-taint
}

function sanitized(req) {
  const n = Number(req.query.n);
  evalCode(n); // crit:expect-not js.code-injection.eval-taint
}
