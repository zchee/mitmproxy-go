"""Add a monotonically increasing count header to responses."""

state = {"num": 0}

def response(flow):
    state["num"] += 1
    flow.response.headers["count"] = str(state["num"])
