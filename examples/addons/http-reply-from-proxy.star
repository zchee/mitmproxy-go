"""Reply to a selected URL without contacting its origin."""

def request(flow):
    if flow.request.pretty_url == "http://example.com/path":
        flow.response = http.Response.make(200, b"Hello World", {"Content-Type": "text/html"})
