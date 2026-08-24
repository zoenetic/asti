Class Test.PathTraversal Extends %CSP.Page
{

ClassMethod Vulnerable() As %Status
{
    set fn = %request.Get("file")
    set stream = ##class(%Stream.FileCharacter).%New()
    // crit:expect os.path-traversal
    do stream.LinkToFile(fn)
    // crit:expect os.path-traversal
    set exists = ##class(%File).Exists(fn)
    quit $$$OK
}

ClassMethod Safe() As %Status
{
    set fn2 = %request.Get("file")
    set clean = ##class(%File).NormalizeFilename(fn2)
    // crit:expect-not os.path-traversal
    open clean:("R"):5
    // crit:expect-not os.path-traversal
    set exists = ##class(%File).Exists("/opt/app/data/fixed.txt")
    quit $$$OK
}

}
