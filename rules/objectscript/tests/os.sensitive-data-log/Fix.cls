Class Test.SensitiveDataLog Extends %RegisteredObject
{

ClassMethod Run() As %Status
{
    set token = "payload"
    set password = "payload"
    set username = "alice"

    // crit:expect os.sensitive-data-log
    set ^AuditLog(id) = token
    // crit:expect os.sensitive-data-log
    set ^DebugLog(id) = password

    // crit:expect-not os.sensitive-data-log
    set ^AuditLog(id) = username
    // crit:expect-not os.sensitive-data-log
    set ^AppData(id) = token
    quit $$$OK
}

}
