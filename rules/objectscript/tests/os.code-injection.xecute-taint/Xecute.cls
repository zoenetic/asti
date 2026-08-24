Class Test.XecuteTaint Extends %CSP.Page
{

ClassMethod Vulnerable() As %Status
{
    set name = %request.Get("name")
    set cmd = %request.Data("cmd", 1)
    // crit:expect os.code-injection.xecute-taint
    xecute ("write " _ name)
    // crit:expect os.code-injection.xecute-taint
    xecute cmd
    quit $$$OK
}

ClassMethod Safe() As %Status
{
    // crit:expect-not os.code-injection.xecute-taint
    xecute ("write 1")
    // crit:expect-not os.code-injection.xecute-taint
    xecute "do ^Report"
    quit $$$OK
}

}
