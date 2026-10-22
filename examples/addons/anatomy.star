"""Count requests using mutable module state."""

state = {"num": 0}

def request(flow):
    state["num"] += 1
    ctx.log.info("We've seen %d flows" % state["num"])
