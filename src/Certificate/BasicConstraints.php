<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\ExtensionInterface;
use eIDASCertificate\ExtensionException;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\OID;
use eIDASCertificate\Finding;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
class BasicConstraints implements ExtensionInterface
{
    private $binary;
    private $pathLength;
    private $isCA;
    private $findings = [];
    private $isCritical;

    const type = 'basicConstraints';
    const oid = '2.5.29.19';
    const uri = 'https://tools.ietf.org/html/rfc5280#section-4.2.1.9';

    public function __construct($extensionDER, $isCritical = false)
    {
        $this->isCritical = $isCritical;
        if (bin2hex(substr($extensionDER, 0, 5)) == '3006010101') {
            // Some CAs incorrectly encode isCA as TRUE as 0x01, parser expects 0xFF
            $this->findings[] = new Finding(
                self::type,
                $isCritical ? 'critical' : 'warning',
                "isCA not correctly encoded in ASN1, expectedd 0xff found 0x".
              bin2hex($extensionDER[4])
            );
            $extensionDER[4] = chr(0xFF);
        }
        $basicConstraints = UnspecifiedType::fromDER($extensionDER)->asSequence();
        if ($basicConstraints->has(0) && $basicConstraints->at(0)->isType(1)) {
            if ($basicConstraints->at(0)->asBoolean()->value() == true) {
                $this->isCA = true;
                if ($basicConstraints->has(1)) {
                    $this->pathLength = $basicConstraints->at(1)->asInteger()->intNumber();
                }
            }
        } else {
            $this->isCA = false;
        }
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

    public function isCA()
    {
        return $this->isCA;
    }

    public function getPathLength()
    {
        return $this->pathLength;
    }

    public function getBinary()
    {
        return $this->binary;
    }

    public function getDescription()
    {
        return "This is a BasicConstraints extension";
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
        $attrs = ['isCA' => $this->isCA];
        if (!empty($this->pathLength)) {
            $attrs['pathLength'] = $this->pathLength;
        }
        return $attrs;
    }
}
