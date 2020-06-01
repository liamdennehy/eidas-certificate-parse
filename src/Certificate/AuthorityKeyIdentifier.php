<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\ExtensionInterface;
use eIDASCertificate\Certificate\CertificateException;
use eIDASCertificate\Finding;
use eIDASCertificate\Certificate\X509Certificate;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
class AuthorityKeyIdentifier implements ExtensionInterface
{
    private $binary;
    private $keyIdentifier;
    private $findings = [];
    private $isCritical;

    const type = 'authorityKeyIdentifier';
    const oid = '2.5.29.35';
    const uri = 'https://tools.ietf.org/html/rfc5280#section-4.2.1.1';

    public function __construct($extensionDER, $isCritical = false)
    {
        $this->isCritical = $isCritical;
        $seq = UnspecifiedType::fromDER($extensionDER)->asSequence();
        foreach ($seq->elements() as $akiElement) {
            switch ($akiElement->tag()) {
            case chr(0x80):
              $this->keyIdentifier = $akiElement->asImplicit(0x04)->asOctetString()->string();
              break;
            case 1:
            case 2:
              // TODO: Handle complex AKIs
              // https://tools.ietf.org/html/rfc5280#section-4.2.1.1
              break;
            default:
              $this->findings[] = new Finding(
                  self::type,
                  'error',
                  "Unrecognised AuthorityKeyIdentifier ".
                  $akiElement->tag().
                  " Format: ".
                  base64_encode($akiElement->toDER())
              );
              break;
          }
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

    public function getBinary()
    {
        return $this->binary;
    }

    public function getKeyId()
    {
        return $this->keyIdentifier;
    }

    public function getDescription()
    {
        return "This is an AuthorityKeyIdentifier extension";
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
        return
          [
            'issuer' => [
              'aki' => base64_encode($this->keyIdentifier),
            ]
          ];
    }
}
