"""Spoof IPv6 localhost, NXDOMAIN and empty-answer DNS responses."""

def dns_request(flow):
    question = flow.request.question
    if question and question.type == dns.types.AAAA:
        ctx.log.info("Spoofing IPv6 records for %s..." % question.name)
        if question.name == "example.com":
            flow.response = flow.request.succeed([
                dns.ResourceRecord(
                    name="example.com",
                    type=dns.types.AAAA,
                    class_=dns.classes.IN,
                    ttl=dns.ResourceRecord.DEFAULT_TTL,
                    data=b"\x00" * 15 + b"\x01",
                ),
            ])
        elif question.name == "example.org":
            flow.response = flow.request.fail(dns.response_codes.NXDOMAIN)
        else:
            flow.response = flow.request.succeed([])
