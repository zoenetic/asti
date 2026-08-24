Class Test.Ztrap Extends %RegisteredObject
{

ClassMethod Legacy() As %Status
{
    // crit:expect os.quality.deprecated-ztrap
    ztrap "ERR"
    // crit:expect os.quality.deprecated-ztrap
    ztrap:x=1 "ERR2"
    // crit:expect-not os.quality.deprecated-ztrap
    do ^Handler
    // crit:expect-not os.quality.deprecated-ztrap
    quit $$$OK
}

}
