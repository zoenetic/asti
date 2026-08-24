Class Test.Secret Extends %RegisteredObject
{

ClassMethod Run() As %Status
{
    // crit:expect os.hardcoded-secret
    set password = "supersecretvalue"
    // crit:expect os.hardcoded-secret
    set apiKey = "abcdef0123456789"
    // crit:expect-not os.hardcoded-secret
    set username = "administrator"
    // crit:expect-not os.hardcoded-secret
    set secret = "abc"
    quit $$$OK
}

}
