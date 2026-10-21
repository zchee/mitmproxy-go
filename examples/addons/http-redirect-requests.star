"""Redirect example.org requests to mitmproxy.org."""

def request(flow):
    # pretty_host includes the Host header used in transparent mode.
    if flow.request.pretty_host == "example.org":
        flow.request.host = "mitmproxy.org"
