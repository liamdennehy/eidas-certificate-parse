<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\ExtensionInterface;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\Finding;
use eIDASCertificate\ParseException;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
class OCSPNoCheck implements ExtensionInterface
{
    private $binary;
    private $findings = [];
    private $isCritical;

    const type = 'ocspNoCheck';
    const oid = '1.3.6.1.5.5.7.48.1.5';
    const uri = 'https://tools.ietf.org/html/rfc2560#section-4.2.2.2.1';

    public function __construct($extensionDER, $isCritical = false)
    {
        if (UnspecifiedType::fromDER($extensionDER)->tag() <> 5) {
            throw new ParseException("Malformed OCSPNoCheck Extension: ".base64_encode($extensionDER), 1);
        }
        $this->isCritical = $isCritical;
        $this->findings[] = new Finding(
            self::type,
            'info',
            "This certificate is exempt from status checks when used to sign OCSP Responses"
        );
        $this->binary = $extensionDER;
    }

    public function getType()
    {
        return self::type;
    }

    public function getURI()
    {
        return self::uri;
    }

    public function getBinary()
    {
        return $this->binary;
    }

    public function getDescription()
    {
        return 'This an OCSPNoCheck extension';
    }

    public function getFindings()
    {
        return $this->findings;
    }

    public function getIsCritical()
    {
        return $this->isCritical;
    }

    public function setCertificate(X509Certificate $cert)
    {
        null;
    }

    public function getAttributes()
    {
        return [];
    }
}
