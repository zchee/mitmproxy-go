"""Register a counter command and call it for each request."""

state = {"num": 0}

def inc():
    state["num"] += 1
    ctx.log.info("num = %d" % state["num"])

def on_load(loader):
    loader.add_command("myaddon.inc", inc, help="Increment and log the request counter.")

def request(flow):
    ctx.master.commands.call("myaddon.inc")
