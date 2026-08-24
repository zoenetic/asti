function render(el) {
  const q = location.search;
  // crit:expect js.xss.dom
  el.innerHTML = q;
}

function writeDoc() {
  document.write(location.hash); // crit:expect js.xss.dom
}

function safeText(el) {
  const q = location.search;
  el.textContent = q; // crit:expect-not js.xss.dom
}

function constantHtml(el) {
  el.innerHTML = "<b>static</b>"; // crit:expect-not js.xss.dom
}
