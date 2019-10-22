<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\Certificate\ExtensionInterface;
use eIDASCertificate\CertificateException;
use eIDASCertificate\ParseException;
use eIDASCertificate\Finding;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\OID;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
class SubjectAltName implements ExtensionInterface
{
    private $binary;
    private $dnsNames = [];
    private $URIs = [];
    private $rfc822Names = [];
    private $scUPNs = [];
    private $otherNames = [];
    private $sanString = '';
    private $findings = [];

    const type = 'subjectAltName';
    const oid = '2.5.29.17';
    const uri = 'https://tools.ietf.org/html/rfc5280#section-4.2.1.6';

    public function __construct($extensionDER, $isCritical = false)
    {
        $this->isCritical = $isCritical;
        $SANs = UnspecifiedType::fromDER($extensionDER)->asSequence();
        foreach ($SANs->elements() as $value) {
            switch ($value->tag()) {
            case 0:
              $other = $value->implicit(16)->asSequence();
              $oid = $other->at(0)->asObjectIdentifier()->oid();
              $name = OID::getName($oid);
              switch ($name) {
                case 'msSmartCardUPN':
                  $this->scUPNs[] = $other->at(1)->implicit(12)->string();
                  break;

                default:
                  $this->otherNames[] = [
                    'oid' => $oid,
                    'name' => $name,
                    'value' => base64_encode($other->at(1)->toDER())
                  ];
                  $this->findings[] = new Finding(
                      self::type,
                      'warning',
                      "Unrecognised subjectAltName extension: ".
                    base64_encode($extensionDER)
                  );
                  break;
              }

              break;
            case 1:
              $this->rfc822Names[] = $value->implicit(22)->asIA5String()->string();
              break;
            case 2:
              $this->dnsNames[] = $value->implicit(22)->asIA5String()->string();
              break;
            case 6:
              $this->URIs[] = $value->implicit(22)->asIA5String()->string();
              break;

              default:
                $this->findings[] = new Finding(
                    self::type,
                    'warning',
                    "Unrecognised subjectAltName extension: ".
                  base64_encode($extensionDER)
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

    public function getSAN()
    {
        // return $this->keyIdentifier;
    }

    public function getDescription()
    {
        return "This is a subjectAltName extension";
    }

    public function getDNSNames()
    {
        return $this->dnsNames;
    }

    public function getURIs()
    {
        return $this->URIs;
    }

    public function getSmartCardUPNs()
    {
        return $this->scUPNs;
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
        $attr = [];
        if (!empty($this->rfc822Names)) {
            $attr['email'] = $this->rfc822Names;
        }
        if (!empty($this->dnsNames)) {
            $attr['DNS'] = $this->dnsNames;
        }
        if (!empty($this->URIs)) {
            $attr['URI'] = $this->URIs;
        }
        if (!empty($this->scUPNs)) {
            $attr['SmartCardUPN'] = $this->scUPNs;
        }
        if (!empty($this->otherNames)) {
            $attr['other'] = $this->otherNames;
        }
        return ['subject' => ['altNames' => $attr]];
    }
}
