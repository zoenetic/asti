Class Test.Xecute Extends %RegisteredObject
{

ClassMethod Run() As %Status
{
    // crit:expect os.code-injection.xecute
    xecute ("write " _ x)
    // crit:expect os.code-injection.xecute
    xecute "do ^Report"
    // crit:expect-not os.code-injection.xecute
    do ^Report
    // crit:expect-not os.code-injection.xecute
    set y = 1
    quit $$$OK
}

}
