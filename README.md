# eIDAS Certificate Parser and Trusted List tools

This library is intended to enhance the usability of
eIDAS certificates.

eIDAS Qualified Certificates especially are difficult to
handle, as they are generally not issued by a CA your
browser/OS recognises, and not all CAs (Trust Service
Providers) are authorised to issue all kinds of certificates.

The European Commission is the ultimate authority for Trust
Services in the Single Market, and publishes a Trusted List
of Lists (TLOL), which point to Trusted Lists maintained by
organisations in each Member State. The TLOL includes the
Digital Identities (certificates) used to digitally sign
both the TLOL and the individual Trusted Lists.

Each Trusted List then describes the registered Trust Service
Providers each authority supervises, the services they are
authorised to provide, and the history of the authorisation
of each provider. This allows for historic queries
(e.g. was a provider authorised to provide the specific type
of Trust Service at the time this certificate was issued) as
well as current queries (Can I trust this certificate now?).

Please Indicate your interest in this library by watching on
[Packagist](https://packagist.org/packages/liamdennehy/eidas-certificate)
(the little star on the heading)
or adding feature requests, bug reports
or use cases on [Github](https://github.com/liamdennehy/eidas-certificate-parse/issues).

With thanks to [Travis-CI] for the free build and testing service!

[![Build Status](https://travis-ci.com/liamdennehy/eidas-certificate-parse.svg?branch=master)](https://travis-ci.com/liamdennehy/eidas-certificate-parse)