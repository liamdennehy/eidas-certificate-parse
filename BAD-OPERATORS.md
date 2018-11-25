# Bad Scheme Operators

This is a summary of various issues with SchemeOperators' TrustedList
services...

- DK: 500 responses (intermittent)
- DE: No Last-Modified
- DE: Discriminates against PHP, curl Agents:

```http
  HTTP/1.1 200 OK
  Connection: close
  Cache-Control: no-cache
  Content-Type: text/html; charset=iso-8859-1
  Pragma: no-cache
  Content-Length: 187

<html><head><title>Request Rejected</title></head><body>The requested URL was rejected. Please consult with your administrator.<br><br>Your support ID is: 230680958440152677</body></html>
```

- HU: Network unreachable

```sh
~ $ wget -O - http://www.nmhh.hu/tl/pub/HU_TL.xml
--2018-11-25 12:23:34--  http://www.nmhh.hu/tl/pub/HU_TL.xml
Resolving www.nmhh.hu... 84.206.44.219
Connecting to www.nmhh.hu|84.206.44.219|:80... failed: Network is unreachable.
```

  Also:

```html
<html><body><h1>502 Parent proxy unreacheable</h1><p><a href='http://cntlm.sf.net/'>Cntlm</a> proxy failed to complete the request.</p></body></html>
```
- UK: Lag in update after expiry for three days, leaving the TSL in limbo
- Some services (TBC): Last-Modified meaningless
