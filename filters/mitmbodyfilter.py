import re

def request(flow):
    """
    This is executed before forwarding the request to the server.
    If the request body matches the regex, it adds (or modifies)
    a "flag" header with the value "FLAG IN".
    """
    if flow.request.text is not None:
        if re.search(r'[A-Z0-9]{31}=', flow.request.text):
            flow.request.headers["flag"] = "FLAG IN"

def response(flow):
    """
    This is executed after the server has responded.
    If the response body matches the regex, it adds (or modifies)
    a "flag" header with the value "FLAG OUT".
    """
    if flow.response.text is not None:
        if re.search(r'[A-Z0-9]{31}=', flow.response.text):
            flow.response.headers["flag"] = "FLAG OUT"