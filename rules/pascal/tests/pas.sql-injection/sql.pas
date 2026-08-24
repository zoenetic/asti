program SqlTests;
var q: String;
begin
  q := 'SELECT * FROM t WHERE id=' + ParamStr(1);
  Query1.SQL.Text := q; // crit:expect pas.sql-injection
  ExecuteDirect('SELECT * FROM t WHERE x=' + ParamStr(2)); // crit:expect pas.sql-injection
  Query2.SQL.Text := 'SELECT * FROM t WHERE active=1'; // crit:expect-not pas.sql-injection
  ExecuteDirect('SELECT 1'); // crit:expect-not pas.sql-injection
end.
