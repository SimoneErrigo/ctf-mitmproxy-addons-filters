import re
import urllib.parse

sqli_pattern = re.compile(r"""
    (?xi)                    
    (?:                      
      \bunion(?:\s+all)?\s+select\b      # union [all] select
      | \bselect\b[\s\S]{1,100}?\bfrom\b # select ... from (fino a 100 char)
      | \b(?:drop|delete)\s+(?:table|from)\b  # drop table / delete from
      | \binsert\s+into\b         # insert into
      | \bupdate\s+\w+\s+set\b    # update X set
      | \bgroup_concat\s*\(       # group_concat(
      | \border\s+by\s+\d+\b      # order by 1, order by 2, etc.
      | \bsleep\s*\(\s*\d+\s*\)   # sleep(1), sleep (1000)
      | \bbenchmark\s*\(\s*\d+\s*,\s*.+?\)  # benchmark(1000, ...)
    )                           
""", re.VERBOSE | re.IGNORECASE)

def request(flow):
    """
    This is executed before forwarding the request to the server.
    If the request body matches the regex, it adds (or modifies)
    a "SQLI" header with the value "SQLI IN"
    """
    b = flow.request.text
    u = flow.request.url
    # consider also checking headers
    if sqli_pattern.search(urllib.parse.unquote(b)) or sqli_pattern.search(urllib.parse.unquote(u)):
        flow.request.headers["SQLI"] = "SQLI IN"