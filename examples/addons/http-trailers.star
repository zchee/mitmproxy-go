"""Observe HTTP trailers and inject them on /inject_trailers."""

def request(flow):
    if flow.request.trailers:
        ctx.log.info("HTTP Trailers detected! Request contains: %s" % flow.request.trailers)
    if flow.request.path != "/inject_trailers" or flow.request.is_http10:
        return
    if flow.request.is_http11:
        if not flow.request.content:
            return
        flow.request.headers["transfer-encoding"] = "chunked"
    flow.request.headers["trailer"] = "x-my-injected-trailer-header"
    flow.request.trailers = http.Headers([(b"x-my-injected-trailer-header", b"foobar")])
    ctx.log.info("Injected a new request trailer... x-my-injected-trailer-header")

def response(flow):
    if flow.response.trailers:
        ctx.log.info("HTTP Trailers detected! Response contains: %s" % flow.response.trailers)
    if flow.request.path != "/inject_trailers" or flow.request.is_http10:
        return
    if flow.request.is_http11:
        if not flow.response.content:
            return
        flow.response.headers["transfer-encoding"] = "chunked"
    flow.response.headers["trailer"] = "x-my-injected-trailer-header"
    flow.response.trailers = http.Headers([(b"x-my-injected-trailer-header", b"foobar")])
    ctx.log.info("Injected a new response trailer... x-my-injected-trailer-header")
