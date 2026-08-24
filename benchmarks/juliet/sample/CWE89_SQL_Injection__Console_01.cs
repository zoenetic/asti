/* Juliet-shaped sample (not from the real suite) used to validate the scorer.
 * Structure mirrors Juliet C#: a Bad() method with the flaw and Good* methods
 * with the fix, so the scorer's TP/FP/FN/TN attribution can be checked. */
using System;
using System.Data.SqlClient;

namespace crit.benchmark
{
    class CWE89_SQL_Injection__Console_01
    {
        public void Bad()
        {
            string data = Console.ReadLine();
            /* POTENTIAL FLAW: user input concatenated into SQL */
            SqlCommand cmd = new SqlCommand("SELECT * FROM users WHERE name = '" + data + "'");
            cmd.ExecuteReader();
        }

        public void GoodG2B()
        {
            string data = "fixedName";
            /* FIX: constant, no user input */
            SqlCommand cmd = new SqlCommand("SELECT * FROM users WHERE name = '" + data + "'");
            cmd.ExecuteReader();
        }

        public void GoodB2G()
        {
            string data = Console.ReadLine();
            /* FIX: parameterized query */
            SqlCommand cmd = new SqlCommand("SELECT * FROM users WHERE name = @n");
            cmd.Parameters.AddWithValue("@n", data);
            cmd.ExecuteReader();
        }
    }
}
