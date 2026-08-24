Class Test.Goto Extends %RegisteredObject
{

ClassMethod Run() As %Status
{
    // crit:expect os.quality.goto
    goto Label
    // crit:expect os.quality.goto
    goto:x=1 Other
    // crit:expect-not os.quality.goto
    do ^Sub
    // crit:expect-not os.quality.goto
    quit $$$OK
}

}
