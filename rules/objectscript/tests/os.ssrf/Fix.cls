Class Test.Ssrf Extends %CSP.Page
{

ClassMethod Vulnerable() As %Status
{
    set host = %request.Get("host")
    set url = %request.Get("url")
    set req = ##class(%Net.HttpRequest).%New()
    // crit:expect os.ssrf
    set req.Server = host
    // crit:expect os.ssrf
    do req.Get(url)
    quit $$$OK
}

ClassMethod Safe() As %Status
{
    set req = ##class(%Net.HttpRequest).%New()
    // crit:expect-not os.ssrf
    set req.Server = "api.partner.example.com"
    // crit:expect-not os.ssrf
    do req.Get("/status")
    quit $$$OK
}

}
