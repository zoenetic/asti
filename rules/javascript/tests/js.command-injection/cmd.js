const cp = require('child_process');
const { exec } = require('child_process');

function listDir(req) {
  exec("ls " + req.query.dir); // crit:expect js.command-injection
}

function viaVariable(req) {
  const dir = req.body.dir;
  // crit:expect js.command-injection
  cp.execSync(`ls ${dir}`);
}

function fixedCommand() {
  exec("ls -la /var/log"); // crit:expect-not js.command-injection
}

function sanitizedArg(req) {
  const count = parseInt(req.query.count);
  exec("head -n " + count); // crit:expect-not js.command-injection
}
