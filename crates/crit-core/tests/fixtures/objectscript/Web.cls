Class Demo.Web Extends %CSP.Page
{

ClassMethod OnPage() As %Status
{
    set id = %request.Get("id")
    set name = %request.Data("name", 1)
    set sql = "SELECT Name FROM Person WHERE ID = " _ id
    set stmt = ##class(%SQL.Statement).%New()
    set rc = stmt.%Prepare(sql)
    set rs = ##class(%SQL.Statement).%ExecDirect(, sql)
    xecute ("write " _ name)
    set out = $ZF(-100, "", "ping", name)
    set x = $ZF(-1, "ls " _ name)
    write "<div>" _ name _ "</div>"
    &sql(SELECT Name INTO :n FROM Person WHERE ID = :id)
    kill ^TempData(id)
    quit $$$OK
}

}
