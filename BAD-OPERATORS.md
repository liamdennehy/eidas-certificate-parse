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

- DE: Changes their MimeType namespace from ``ns3:MimeType`` to ``ns4:MimeType``
- DE: Changed signature type to new algorithm not supported by most popular PHP XMLSig library:

```
<dsig:SignatureMethod Algorithm="http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1">
```

- EL: LOTL name `EL: EETT` doesn't match TL name `EL: Hellenic Telecommunications and Post Commission, EETT`

- HU: Network unreachable

```sh
~ $ wget -O - http://www.nmhh.hu/tl/pub/HU_TL.xml
--2018-11-25 12:23:34--  http://www.nmhh.hu/tl/pub/HU_TL.xml
Resolving www.nmhh.hu... 84.206.44.219
Connecting to www.nmhh.hu|84.206.44.219|:80... failed: Network is unreachable.
```

Then totally changes their XML namespace (only operator to use a namespace):

Before:

```
<?xml version="1.0" encoding="UTF-8"?><TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" xmlns:ns2="http://www.w3.org/2000/09/xmldsig#" xmlns:ns3="http://uri.etsi.org/02231/v2/additionaltypes#" xmlns:ns4="http://uri.etsi.org/01903/v1.3.2#" xmlns:ns5="http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#" xmlns:ns6="http://uri.etsi.org/01903/v1.4.1#" Id="TrustServiceStatusList-1" TSLTag="http://uri.etsi.org/19612/TSLTag">
    <SchemeInformation>
        <TSLVersionIdentifier>5</TSLVersionIdentifier>
        <TSLSequenceNumber>46</TSLSequenceNumber>
```

After:
```
<?xml version="1.0" encoding="UTF-8"?>
<!--

*******************************************************************************
        Application: TL
        API:         A2-Polysys CryptoSigno Interop JAVA API v2.5.0 b150
        Date:        2018.11.26. 14:04:46.727 CET [2018-11-26T13:04:46Z]
*******************************************************************************
-->
<tsl:TrustServiceStatusList xmlns:ns2="http://www.w3.org/2000/09/xmldsig#" xmlns:ns3="http://uri.etsi.org/02231/v2/additionaltypes#" xmlns:ns4="http://uri.etsi.org/01903/v1.3.2#" xmlns:ns5="ht
tp://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#" xmlns:ns6="http://uri.etsi.org/01903/v1.4.1#" xmlns:tsl="http://uri.etsi.org/02231/v2#" Id="TrustServiceStatusList-1" TSL
Tag="http://uri.etsi.org/19612/TSLTag">
<!--

*******************************************************************************
        Application: TL 4.2.2.18.10.02
        API:         A2 TSL API v3.3.0 b20181002
        Date:        2018.11.26. 14:04:41.746 CET [2018-11-26T13:04:41Z]
*******************************************************************************
-->
<tsl:SchemeInformation>
<tsl:TSLVersionIdentifier>5</tsl:TSLVersionIdentifier>
<tsl:TSLSequenceNumber>47</tsl:TSLSequenceNumber>
```


  Also:

```html
<html><body><h1>502 Parent proxy unreacheable</h1><p><a href='http://cntlm.sf.net/'>Cntlm</a> proxy failed to complete the request.</p></body></html>
```
- UK: Lag in update after expiry for three days, leaving the TSL in limbo
- Some services (TBC): Last-Modified meaningless
