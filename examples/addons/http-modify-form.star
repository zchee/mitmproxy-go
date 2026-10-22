"""Extend an existing form or replace a non-form request body."""

def request(flow):
    if flow.request.urlencoded_form:
        flow.request.urlencoded_form["mitmproxy"] = "rocks"
    else:
        flow.request.urlencoded_form = [("foo", "bar")]
