"""Register addheader and count responses when the option is enabled."""

state = {"num": 0}

def on_load(loader):
    loader.add_option("addheader", "bool", False, "Add a count header to responses")

def response(flow):
    if ctx.options.addheader:
        state["num"] += 1
        flow.response.headers["count"] = str(state["num"])
