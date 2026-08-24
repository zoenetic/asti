program WithTests;
begin
  with Customer do Name := 'x'; // crit:expect pas.quality.with-statement
  with Order do begin Total := 0; end; // crit:expect pas.quality.with-statement
  Customer.Name := 'y'; // crit:expect-not pas.quality.with-statement
  Order.Total := 0; // crit:expect-not pas.quality.with-statement
end.
