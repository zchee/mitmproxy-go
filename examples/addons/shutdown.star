"""Request proxy shutdown when a selected URL is received."""

def request(flow):
    if flow.request.pretty_url == "http://example.com/path":
        ctx.log.info("Shutting down everything...")
        ctx.master.shutdown()
