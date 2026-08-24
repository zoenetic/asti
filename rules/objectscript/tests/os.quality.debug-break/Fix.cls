Class Test.DebugBreak Extends %RegisteredObject
{

ClassMethod Run() As %Status
{
    // crit:expect os.quality.debug-break
    break
    // crit:expect os.quality.debug-break
    break
    // crit:expect-not os.quality.debug-break
    break 0
    // crit:expect-not os.quality.debug-break
    break 1
    quit $$$OK
}

}
