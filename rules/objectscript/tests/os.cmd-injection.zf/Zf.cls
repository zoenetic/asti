Class Test.Zf Extends %CSP.Page
{

ClassMethod Vulnerable() As %Status
{
    set name = %request.Get("name")
    // crit:expect os.cmd-injection.zf
    set out = $ZF(-100, "", "ping", name)
    // crit:expect os.cmd-injection.zf
    set x = $ZF(-1, "ls " _ name)
    quit $$$OK
}

ClassMethod Safe() As %Status
{
    // crit:expect-not os.cmd-injection.zf
    set out = $ZF(-100, "", "ping", "localhost")
    // crit:expect-not os.cmd-injection.zf
    set x = $ZF(-1, "ls -la")
    quit $$$OK
}

}
