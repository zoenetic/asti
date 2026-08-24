program TlsTest;
begin
  IdSSL.SSLOptions.VerifyMode := [sslvrfNone]; // crit:expect pas.insecure-tls
  Handler.VerifyCert := False; // crit:expect pas.insecure-tls
  IdSSL.SSLOptions.VerifyMode := [sslvrfPeer, sslvrfFailIfNoPeerCert]; // crit:expect-not pas.insecure-tls
  Handler.VerifyCert := True; // crit:expect-not pas.insecure-tls
end.
