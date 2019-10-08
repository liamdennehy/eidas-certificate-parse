<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\Certificate\ExtensionInterface;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\Finding;

/**
 *
 */
class PreCertPoison implements ExtensionInterface
{
    private $binary;
    private $findings = [];
    private $isCritical;

    const type = 'preCertPoison';
    const oid = '1.3.6.1.4.1.11129.2.4.3';
    const uri = 'https://tools.ietf.org/html/rfc6962#section-3.1';

    public function __construct($extensionDER, $isCritical = false)
    {
        $this->isCritical = $isCritical;
        $this->findings[] = new Finding(
            self::type,
            'warning',
            "This is a precert, so should not be seen in production"
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
        return "The is a PrecertPoison extension";
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
        return ['isPrecert' => true];
    }
}
