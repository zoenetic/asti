Class Test.Catch Extends %RegisteredObject
{

ClassMethod SwallowNamed() As %Status
{
    try {
        do ^Risky
    // crit:expect os.quality.empty-catch
    } catch ex {}
    quit $$$OK
}

ClassMethod SwallowBare() As %Status
{
    try {
        do ^Risky
    // crit:expect os.quality.empty-catch
    } catch {}
    quit $$$OK
}

ClassMethod Handled() As %Status
{
    try {
        do ^Risky
    // crit:expect-not os.quality.empty-catch
    } catch ex { do ^Log(ex) }
    quit $$$OK
}

ClassMethod Rethrows() As %Status
{
    try {
        do ^Risky
    // crit:expect-not os.quality.empty-catch
    } catch ex { throw ex }
    quit $$$OK
}

}
