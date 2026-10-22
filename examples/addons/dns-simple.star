"""Spoof IPv6 localhost, NXDOMAIN and empty-answer DNS responses."""

def dns_request(flow):
    question = flow.request.question
    if question and question.type == dns.types.AAAA:
        ctx.log.info("Spoofing IPv6 records for %s..." % question.name)
        if question.name == "example.com":
            flow.response = flow.request.succeed([
                dns.ResourceRecord.AAAA("example.com", "::1"),
            ])
        elif question.name == "example.org":
            flow.response = flow.request.fail(dns.response_codes.NXDOMAIN)
        else:
            flow.response = flow.request.succeed([])
