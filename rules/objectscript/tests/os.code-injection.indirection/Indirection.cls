Class Test.Indirection Extends %RegisteredObject
{

ClassMethod Run() As %Status
{
    // crit:expect os.code-injection.indirection
    set val = @varName
    // crit:expect os.code-injection.indirection
    do @routineRef
    // crit:expect-not os.code-injection.indirection
    set val = normalVar
    // crit:expect-not os.code-injection.indirection
    do ^Routine
    quit $$$OK
}

}
