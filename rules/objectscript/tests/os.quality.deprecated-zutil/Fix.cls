Class Test.DeprecatedZutil Extends %RegisteredObject
{

ClassMethod Run() As %Status
{
    // crit:expect os.quality.deprecated-zutil
    set x = $ZUTIL(4)
    // crit:expect os.quality.deprecated-zutil
    do $ZU(68, 40, 1)
    // crit:expect-not os.quality.deprecated-zutil
    set d = $ZDATE(60000)
    // crit:expect-not os.quality.deprecated-zutil
    set p = $PIECE("a^b", "^", 1)
    quit $$$OK
}

}
