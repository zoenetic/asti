function run(code) {
  eval(code); // crit:expect js.code-injection.eval
}

function makeFn(body) {
  const f = Function(body); // crit:expect js.code-injection.eval
  return f;
}

function lookalikes(code) {
  evaluate(code); // crit:expect-not js.code-injection.eval
  interpreter.eval(code); // crit:expect-not js.code-injection.eval
}
