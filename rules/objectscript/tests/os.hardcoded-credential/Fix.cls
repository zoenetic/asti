Class Test.HardcodedCredential Extends %RegisteredObject
{

ClassMethod Run() As %Status
{
    set user = ..GetUser()
    set pass = ..GetPassword()

    // crit:expect os.hardcoded-credential
    set ok1 = ##class(%SYSTEM.Security).Login("admin", "password123")
    // crit:expect os.hardcoded-credential
    set ok2 = ##class(MyApp.Auth).Login("svcuser", "secret99")

    // crit:expect-not os.hardcoded-credential
    set ok3 = ##class(%SYSTEM.Security).Login(user, pass)
    // crit:expect-not os.hardcoded-credential
    set ok4 = ##class(MyApp.Auth).Login(user, pass)
    quit $$$OK
}

}
