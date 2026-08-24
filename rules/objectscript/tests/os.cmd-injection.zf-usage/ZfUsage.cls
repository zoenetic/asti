Class Test.ZfUsage Extends %RegisteredObject
{

ClassMethod Run() As %Status
{
    // crit:expect os.cmd-injection.zf-usage
    set a = $ZF(-1, "ls")
    // crit:expect os.cmd-injection.zf-usage
    set b = $ZF(-100, "", "ping")
    // crit:expect-not os.cmd-injection.zf-usage
    set c = $ZF(1, x)
    // crit:expect-not os.cmd-injection.zf-usage
    set d = $LENGTH(x)
    quit $$$OK
}

}
