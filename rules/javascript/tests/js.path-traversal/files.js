const fs = require('fs');
const path = require('path');

function readUpload(req, cb) {
  fs.readFile("/data/" + req.query.name, cb); // crit:expect js.path-traversal
}

function writeUpload(req, cb) {
  const target = req.body.path;
  // crit:expect js.path-traversal
  fs.writeFileSync(target, "content");
}

function basenamed(req, cb) {
  const name = path.basename(req.query.name);
  fs.readFile("/data/" + name, cb); // crit:expect-not js.path-traversal
}

function fixedPath(cb) {
  fs.readFileSync("/etc/app.conf"); // crit:expect-not js.path-traversal
}
