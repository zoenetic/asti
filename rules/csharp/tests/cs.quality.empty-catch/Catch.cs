class CatchTests {
  void Swallow() {
    try { Risky(); } catch (Exception e) {} // crit:expect cs.quality.empty-catch
  }
  void SwallowBare() {
    try { Risky(); } catch {} // crit:expect cs.quality.empty-catch
  }
  void Handled() {
    try { Risky(); } catch (Exception e) { Log(e); } // crit:expect-not cs.quality.empty-catch
  }
  void Rethrows() {
    try { Risky(); } catch (Exception e) { throw; } // crit:expect-not cs.quality.empty-catch
  }
}
