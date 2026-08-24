// Aliased/namespaced imports that the name-based text query cannot match —
// only identity resolution catches these.
import { exec as run } from 'child_process';
import { spawn as launch } from 'child_process';

function viaAlias(req) {
  run("ls " + req.query.dir); // crit:expect js.command-injection
}

function viaAliasSpawn(req) {
  launch("ping " + req.query.host); // crit:expect js.command-injection
}

function unrelatedName(req) {
  const run2 = (x) => x;
  run2(req.query.x); // crit:expect-not js.command-injection
}

function sanitizedAlias(req) {
  const n = parseInt(req.query.n);
  run("head -n " + n); // crit:expect-not js.command-injection
}
