from mitmproxy import http
from mitmproxy import ctx
import re
import urllib.parse


def request(flow: http.HTTPFlow):

    regex_sql = re.compile(r"union|group_concat", re.IGNORECASE) # SQL injection
    regex_user_agent = re.compile(r"curl|wget", re.IGNORECASE) # malicious user agent header
    path_traversal_regex = re.compile(r"\.\./") # path traversal
    url_encoded_path_traversal_regex = re.compile(r"%2e%2e%2f") # urlencoded path traversal
    server_side_template_injection_regex = re.compile(r"\{[^}]*\}\}") # jinja2 SSTI
    xml_external_entity_injection_regex = re.compile(r"<!ENTITY\s+[^ ]+\s+SYSTEM\s+\"[^ ]+\"\s*>") # XML external entity injection

    request = flow.request # request is an object of type http.HTTPRequest
    headers = request.headers # headers contains the headers of the request
    path = request.path # contains the path of the request
    url = request.url # contains the full url of the request
    body = request.text # contains the body of the request

    # if the body contains "union" or "group_concat" then replace it with "nice try"
    # if regex_sql.search(body):
    #   body = regex_sql.sub("nice try", body)
    #   flow.request.text = body
    #   ctx.log.info("Request modified: SQL injection detected and replaced with 'nice try")

    # if the body contains "union" or "group_concat" then block the requests
    if regex_sql.search(body):
        ctx.log.info("Request blocked: SQL injection detected")
        flow.response = http.Response.make(
            403,
            b"", # 403 forbidden
            {"Content-Type": "text/plain"}
        )
        return

    # if the request contains a malicious user agent then block the request
    if regex_user_agent.search(headers.get("User-Agent", "")):
        ctx.log.warn("Request blocked: malicious user agent")
        flow.response = http.Response.make(
            403,
            b"Blocked", # "403 and "blocked" appears"
            {"Content-Type": "text/plain"}
        )
        return
    
    # if the path contains "../" or "%2e%2e%2f" then block the request
    # can be written in a better way
    if path_traversal_regex.search(path) or url_encoded_path_traversal_regex.search(path):
        ctx.log.warn("Request blocked: path traversal")
        flow.response = http.Response.make(
            403,
            b"Blocked",  # "403 and "blocked" appears"
            {"Content-Type": "text/plain"}
        )
        return
    
    # server_side_template_injection_regex.search(body) does not work because the body is urlencoded
    # so we need to decode it first
    # if the body contains "{{something}}" then block the request
    if server_side_template_injection_regex.search(urllib.parse.unquote(body)):
        ctx.log.warn("Request blocked: server side template injection")
        flow.response = http.Response.make(
            403,
            b"Blocked",  # "403 and "blocked" appears"
            {"Content-Type": "text/plain"}
        )
        return

    # if the body contains "<!ENTITY name SYSTEM something> then block the request
    if xml_external_entity_injection_regex.search(urllib.parse.unquote(body)):
        ctx.log.warn("Request blocked: xml external entity injection")
        flow.response = http.Response.make(
            403,
            b"Blocked",  # "403 and "blocked" appears"
            {"Content-Type": "text/plain"}
        )
        return