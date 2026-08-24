Class Test.HardcodedCredentialSysfunc Extends %RegisteredObject
{

ClassMethod Run() As %Status
{
    set user = ..GetUser()
    set pass = ..GetPassword()

    // crit:expect os.hardcoded-credential.sysfunc
    do $System.Security.Login("svcuser", "secret99")
    // crit:expect os.hardcoded-credential.sysfunc
    do $System.Security.Login("admin", "password123")

    // crit:expect-not os.hardcoded-credential.sysfunc
    do $System.Security.Login(user, pass)
    // crit:expect-not os.hardcoded-credential.sysfunc
    do $System.Security.Login(user, ..GetPassword())
    quit $$$OK
}

}
