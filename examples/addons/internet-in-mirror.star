"""Mirror rendered pages by inserting a style without decoding body bytes."""

def response(flow):
    if flow.response and flow.response.content:
        flow.response.content = byteops.replace(
            flow.response.content,
            b"</head>",
            b"<style>body {transform: scaleX(-1);}</style></head>",
        )
