/* Juliet-shaped multi-file variant (not from the real suite): the sink lives
 * in a different file from the source (see _81a). */
using System.Data.SqlClient;

namespace crit.benchmark
{
    class CWE89_SQL_Injection__Console_81_bad
    {
        public void Action(string data)
        {
            /* POTENTIAL FLAW: tainted data (from the _81a source) reaches SQL */
            SqlCommand cmd = new SqlCommand("SELECT * FROM users WHERE name = '" + data + "'");
            cmd.ExecuteReader();
        }
    }

    class CWE89_SQL_Injection__Console_81_good
    {
        public void Action(string data)
        {
            /* FIX: parameterized */
            SqlCommand cmd = new SqlCommand("SELECT * FROM users WHERE name = @n");
            cmd.Parameters.AddWithValue("@n", data);
            cmd.ExecuteReader();
        }
    }
}
