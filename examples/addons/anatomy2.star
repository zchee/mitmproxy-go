"""Add a request header using a module-level hook."""

def request(flow):
    flow.request.headers["myheader"] = "value"
