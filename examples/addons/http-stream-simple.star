"""Stream every response without buffering its complete body."""

def responseheaders(flow):
    flow.response.stream = True
