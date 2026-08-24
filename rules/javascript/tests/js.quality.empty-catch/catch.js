function swallow() {
  try { risky(); } catch (e) {} // crit:expect js.quality.empty-catch
}

function swallowNoBinding() {
  try { risky(); } catch {} // crit:expect js.quality.empty-catch
}

function handled() {
  try { risky(); } catch (e) { report(e); } // crit:expect-not js.quality.empty-catch
}

function rethrows() {
  try { risky(); } catch (e) { throw e; } // crit:expect-not js.quality.empty-catch
}
