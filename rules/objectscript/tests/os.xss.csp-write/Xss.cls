Class Test.Xss Extends %CSP.Page
{

ClassMethod Vulnerable() As %Status
{
    set name = %request.Get("name")
    // crit:expect os.xss.csp-write
    write "<div>" _ name _ "</div>"
    // crit:expect os.xss.csp-write
    write name
    quit $$$OK
}

ClassMethod Safe() As %Status
{
    set name = %request.Get("name")
    // crit:expect-not os.xss.csp-write
    write "<div>" _ ##class(%CSP.Page).EscapeHTML(name) _ "</div>"
    // crit:expect-not os.xss.csp-write
    write "<div>static content</div>"
    quit $$$OK
}

}
