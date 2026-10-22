"""Run the upstream thread-based hook without blocking other requests."""

def _request(flow):
    ctx.log.info("handle request: %s%s" % (flow.request.host, flow.request.path))
    ctx.sleep(5)
    ctx.log.info("start  request: %s%s" % (flow.request.host, flow.request.path))

request = concurrent(_request)
