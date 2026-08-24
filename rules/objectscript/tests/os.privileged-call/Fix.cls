Class Test.PrivilegedCall Extends %RegisteredObject
{

ClassMethod Run() As %Status
{
    set data = "payload"

    // crit:expect os.privileged-call
    set zx = $ZU(4, pid)
    // crit:expect os.privileged-call
    do ##class(%SYSTEM.Process).SetZEOF(1)

    // crit:expect-not os.privileged-call
    set part = $Piece(data, ",", 1)
    // crit:expect-not os.privileged-call
    set ver = ##class(%SYSTEM.Version).GetVersion()
    quit $$$OK
}

}
