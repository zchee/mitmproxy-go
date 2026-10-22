"""Replace foo with bar inside each observed TCP chunk."""

def tcp_message(flow):
    # TCP receive boundaries are arbitrary; this does not match across chunks.
    message = flow.messages[-1]
    message.content = byteops.replace(message.content, b"foo", b"bar")
    ctx.log.info("tcp_message[from_client=%s, content=%r]" % (message.from_client, message.content))
