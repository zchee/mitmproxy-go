"""Replace a Hello prefix and drop WebSocket messages containing FOOBAR."""

def websocket_message(flow):
    message = flow.websocket.messages[-1]
    if message.from_client:
        ctx.log.info("Client sent a message: %r" % message.content)
    else:
        ctx.log.info("Server sent a message: %r" % message.content)
    if byteops.startswith(message.content, b"Hello"):
        message.content = b"HAPPY" + message.content[5:]
    if b"FOOBAR" in message.content:
        message.drop()
