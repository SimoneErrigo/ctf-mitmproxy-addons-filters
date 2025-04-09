import re
from mitmproxy import tcp, ctx

URL = "http://127.0.0.1:8081"


def tcp_message(flow: tcp.TCPFlow):
    regex_expression_replace = re.compile(br"hardcoded", re.IGNORECASE)

    message = flow.messages[-1]
    content = message.content

    # If the content contains "hardcoded", replace it with "nice try"
    if regex_expression_replace.search(content):
        ctx.log.info(f"Replacing content: {regex_expression_replace.pattern}")
        message.content = regex_expression_replace.sub(b"nice try", content)
        return