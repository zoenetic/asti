program EmptyExceptTest;
begin
  try DoSomething; except end; // crit:expect pas.quality.empty-except
  try DoOther; except end; // crit:expect pas.quality.empty-except
  try DoSomething; except on E: Exception do Log(E.Message); end; // crit:expect-not pas.quality.empty-except
  try DoSomething; except LogWhatever; end; // crit:expect-not pas.quality.empty-except
end.
