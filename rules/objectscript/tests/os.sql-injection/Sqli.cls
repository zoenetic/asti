Class Test.Sqli Extends %CSP.Page
{

ClassMethod Vulnerable() As %Status
{
    set id = %request.Get("id")
    set sql = "SELECT Name FROM Person WHERE ID = " _ id
    set stmt = ##class(%SQL.Statement).%New()
    // crit:expect os.sql-injection
    do stmt.%Prepare(sql)
    // crit:expect os.sql-injection
    set rs = ##class(%SQL.Statement).%ExecDirect(, "SELECT * FROM Person WHERE ID = " _ id)
    quit $$$OK
}

ClassMethod Safe() As %Status
{
    set stmt = ##class(%SQL.Statement).%New()
    // crit:expect-not os.sql-injection
    do stmt.%Prepare("SELECT Name FROM Person")
    // crit:expect-not os.sql-injection
    set rs = ##class(%SQL.Statement).%ExecDirect(, "SELECT 1")
    quit $$$OK
}

}
