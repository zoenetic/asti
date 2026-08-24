program CatchAllExceptTest;
begin
  try DoSomething; except LogWhatever; end; // crit:expect pas.quality.catch-all-except
  try DoOther; except HandleError; end; // crit:expect pas.quality.catch-all-except
  try DoSomething; except on E: Exception do Log(E.Message); end; // crit:expect-not pas.quality.catch-all-except
  try DoSomething; finally Cleanup; end; // crit:expect-not pas.quality.catch-all-except
end.
