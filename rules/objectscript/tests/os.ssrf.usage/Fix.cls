Class Test.SsrfUsage Extends %CSP.Page
{

ClassMethod Vulnerable() As %Status
{
    set host = %request.Get("host")
    set req = ##class(%Net.HttpRequest).%New()
    // crit:expect os.ssrf.usage
    set req.Server = host
    // crit:expect os.ssrf.usage
    set req.Location = host
    quit $$$OK
}

ClassMethod Safe() As %Status
{
    set req = ##class(%Net.HttpRequest).%New()
    // crit:expect-not os.ssrf.usage
    set req.Server = "api.partner.example.com"
    // crit:expect-not os.ssrf.usage
    set req.Location = "/status"
    quit $$$OK
}

}
