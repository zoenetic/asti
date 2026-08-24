/* Juliet-shaped multi-file variant (not from the real suite): the tainted
 * source is here, the sink is in the _81b file. crit's cross-file taint does
 * not yet resolve this shape (a tainted arg into an instance method on a
 * freshly constructed object in another file), so this testcase is an expected
 * false negative — the scorer records it in the flow-variant bucket. */
using System;

namespace crit.benchmark
{
    class CWE89_SQL_Injection__Console_81_base
    {
        public void Bad()
        {
            string data = Console.ReadLine();
            var helper = new CWE89_SQL_Injection__Console_81_bad();
            helper.Action(data);
        }

        public void GoodG2B()
        {
            string data = "fixedName";
            var helper = new CWE89_SQL_Injection__Console_81_good();
            helper.Action(data);
        }
    }
}
