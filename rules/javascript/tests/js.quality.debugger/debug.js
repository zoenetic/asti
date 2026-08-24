function investigate(state) {
  debugger; // crit:expect js.quality.debugger
  return state;
}

function stepThrough(x) {
  debugger; // crit:expect js.quality.debugger
  return x + 1;
}

function clean(state) {
  // a comment mentioning debugger is fine
  return state; // crit:expect-not js.quality.debugger
}

function alsoClean(y) {
  const debuggerName = "not a statement"; // crit:expect-not js.quality.debugger
  return y;
}
