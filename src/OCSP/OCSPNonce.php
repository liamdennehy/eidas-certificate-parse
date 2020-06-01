<?php

namespace eIDASCertificate\OCSP;

use ASN1\Type\UnspecifiedType;
use eIDASCertificate\ExtensionInterface;
use eIDASCertificate\ASN1Interface;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\ObjectIdentifier;
use ASN1\Type\Primitive\OctetString;
use eIDASCertificate\Certificate\X509Certificate;

class OCSPNonce implements ExtensionInterface, ASN1Interface
{
    private $binary;
    private $nonce;
    private $findings = [];
    private $isCritical;

    const type = 'ocspNonce';
    const oid = '1.3.6.1.5.5.7.48.1.2';
    const uri = 'https://tools.ietf.org/html/rfc6960#section-4.4.1';

    public function __construct($extensionDER, $isCritical = false)
    {
        $this->isCritical = $isCritical;
        $this->nonce = UnspecifiedType::fromDER($extensionDER)->asOctetString()->string();
    }

    public static function fromValue($nonce)
    {
        return new OCSPNonce((new OctetString($nonce))->toDER());
    }
    public function getType()
    {
        return self::type;
    }

    public function getURI()
    {
        return self::uri;
    }

    public function getNonce()
    {
        // var_dump($this->nonce);
        return $this->nonce;
    }

    public function getDescription()
    {
        return "This is an OCSPNonce extension";
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
        // Not useful for ocspNonce
    }
    public function getAttributes()
    {
        return
          [
            'nonce' => $this->getNonce(),
          ];
    }

    public function getASN1()
    {
        return new Sequence(
            new ObjectIdentifier(self::oid),
            new OctetString(
                (new OctetString($this->nonce))->toDER()
            )
        );
    }

    public function getBinary()
    {
        return $this->getASN1()->toDER();
    }
}
