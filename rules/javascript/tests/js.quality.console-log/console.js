function boot(config) {
  console.log("booting", config); // crit:expect js.quality.console-log
  console.debug("config detail"); // crit:expect js.quality.console-log
  console.error("kept: error reporting"); // crit:expect-not js.quality.console-log
  logger.log("structured logging is fine"); // crit:expect-not js.quality.console-log
}
