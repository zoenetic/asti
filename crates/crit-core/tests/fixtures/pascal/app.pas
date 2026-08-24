program T;
var q: String;
begin
  q := 'SELECT * FROM t WHERE id=' + ParamStr(1);
  Query1.SQL.Text := q;
  Query1.ExecSQL;
  WinExec(PChar('cmd /c ' + q), 0);
end.
