class XssTests {
  void Direct() {
    var q = Request.QueryString["q"];
    Response.Write("<p>" + q + "</p>"); // crit:expect cs.xss.response-write
  }
  void ViaParams() {
    Response.Write(Request.Params["q"]); // crit:expect cs.xss.response-write
  }
  void Encoded() {
    var q = Request.QueryString["q"];
    Response.Write(HttpUtility.HtmlEncode(q)); // crit:expect-not cs.xss.response-write
  }
  void Static() {
    Response.Write("<p>hello</p>"); // crit:expect-not cs.xss.response-write
  }
}
