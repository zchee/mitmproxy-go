"""Set a query parameter while preserving the remaining request URL."""

def request(flow):
    flow.request.query["mitmproxy"] = "rocks"
