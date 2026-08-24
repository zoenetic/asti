Class Test.DebugZwrite Extends %RegisteredObject
{

ClassMethod Run() As %Status
{
    set x = 1
    // crit:expect os.quality.debug-zwrite
    zwrite x
    // crit:expect os.quality.debug-zwrite
    zw x
    // crit:expect-not os.quality.debug-zwrite
    write "result: ", x, !
    // crit:expect-not os.quality.debug-zwrite
    write x, !
    quit $$$OK
}

}
