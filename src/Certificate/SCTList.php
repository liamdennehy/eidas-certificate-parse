<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\ExtensionInterface;
use eIDASCertificate\ParseException;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\Finding;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
class SCTList implements ExtensionInterface
{
    private $binary;
    private $findings = [];
    private $isCritical;
    private $list;

    const type = 'sctList';
    const oid = '1.3.6.1.4.1.11129.2.4.2';
    const uri = 'https://tools.ietf.org/html/rfc6962#section-3.3';

    public function __construct($extensionDER, $isCritical = false)
    {
        $this->isCritical = $isCritical;
        $struct = UnspecifiedType::fromDER($extensionDER)->asOctetString()->string();
        $length = unpack('nlength', substr($struct, 0, 2))['length'];
        if (strlen($struct) < ($length + 2)) {
            $this->findings[] = new Finding(
                self::type,
                $isCritical ? 'critical' : 'warning',
                'Malformed SCT extension (not enough bytes): '.
                    base64_encode($extensionDER)
            );
        } elseif (strlen($struct) > ($length + 2)) {
            $this->findings[] = new Finding(
                self::type,
                $isCritical ? 'critical' : 'warning',
                'Malformed SCT extension (too many bytes): '.
                    base64_encode($extensionDER)
            );
        } else {
            $this->findings[] = new Finding(
                self::type,
                $isCritical ? 'critical' : 'warning',
                "Signed Certificate Timestamp extension not yet supported"
            );
            $this->binary = $extensionDER;
        }
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
        return "This is a Signed Certificate Timestamp list extension";
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
        return null;
        // return ['isPrecert' => true];
    }
}
