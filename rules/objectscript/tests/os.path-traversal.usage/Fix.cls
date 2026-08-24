Class Test.PathTraversalUsage Extends %CSP.Page
{

ClassMethod Vulnerable() As %Status
{
    set fn = %request.Get("file")
    set stream = ##class(%Stream.FileCharacter).%New()
    // crit:expect os.path-traversal.usage
    do stream.LinkToFile(fn)
    // crit:expect os.path-traversal.usage
    set exists = ##class(%File).Exists(fn)
    quit $$$OK
}

ClassMethod Safe() As %Status
{
    // crit:expect-not os.path-traversal.usage
    set exists = ##class(%File).Exists("/opt/app/data/fixed.txt")
    // crit:expect-not os.path-traversal.usage
    open "/opt/app/logs/app.log":("R"):5
    quit $$$OK
}

}
