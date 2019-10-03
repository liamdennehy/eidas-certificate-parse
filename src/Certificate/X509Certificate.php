<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\CertificateException;
use eIDASCertificate\ParseException;
use eIDASCertificate\DigitalIdentity\DigitalIdInterface;
use eIDASCertificate\OID;
use eIDASCertificate\Finding;
use eIDASCertificate\QCStatements;
use eIDASCertificate\TSPService\TSPServiceException;
use ASN1\Type\UnspecifiedType;
use phpseclib\File\X509;

/**
 *
 */
class X509Certificate implements DigitalIdInterface, RFC5280ProfileInterface
{
    private $x509;
    private $crtResource;
    private $crtBinary;
    private $parsed;
    private $extensions = [];
    private $keyUsage;
    private $crl;
    private $serialNumber;
    private $publicKey;
    private $issuers = [];
    private $attributes = [];
    private $issuerExpanded = [];
    private $subjectExpanded = [];
    private $findings = [];
    private $tspServiceAttributes;
    private $subjectName;

    public function __construct($candidate)
    {
        $this->x509 = new X509();
        $this->crtBinary = X509Certificate::emit($candidate);
        $this->crtResource = $this->x509->loadX509($this->crtBinary);
        $crtASN1 = UnspecifiedType::fromDER($this->crtBinary)->asSequence();
        $tbsCertificate = $crtASN1->at(0)->asSequence();
        $signatureAlgorithm = $crtASN1->at(1)->asSequence();
        $signatureValue = $crtASN1->at(2)->asBitString()->string();
        switch ($tbsCertificate->at(0)->typeClass()) {
          case 0:
            $crtVersion = $tbsCertificate->at(0)->asInteger()->intNumber();
            break;
          case 2:
            $crtVersion = $tbsCertificate->at(0)->asTagged()->explicit()->number();
            break;

          default:
            throw new CertificateException("Trying to get version tag as ".$tbsCertificate->at(0)->typeClass() . " " . base64_encode($tbsCertificate->toDER()), 1);

            break;
        }

        if ($crtVersion == 2) {
            $dates = $tbsCertificate->at(4)->asSequence();
            $this->notBefore = self::WrangleDate($dates->at(0));
            $this->notAfter = self::WrangleDate($dates->at(1));
            ;
            if ($tbsCertificate->has(7)) {
                $extensionsDER = $tbsCertificate->at(7)->asTagged()->explicit()->toDER();
                $extensions = new Extensions(
                    $extensionsDER
                );
                $this->findings = $extensions->getFindings();
                $this->extensions = $extensions->getExtensions();
            }
            $subjectPublicKeyInfo = $tbsCertificate->at(6)->asSequence();
            $subjectPublicKeyInfoTypeOID =
              $subjectPublicKeyInfo->at(0)->asSequence()->at(0)->asObjectIdentifier()->oid();
            $subjectPublicKeyInfoTypeName = OID::getName($subjectPublicKeyInfoTypeOID);
            switch ($subjectPublicKeyInfoTypeName) {
              case 'rsaEncryption':
              case 'ecPublicKey':
              case 'RSASSA-PSS':
                $this->publicKey = $tbsCertificate->at(6)->toDER();
                break;
              default:
                throw new CertificateException(
                    "Unrecognised Public Key Type OID $subjectPublicKeyInfoTypeOID ($subjectPublicKeyInfoTypeName)",
                    1
                );

                break;
            }
            $this->issuer = $tbsCertificate->at(3)->asSequence()->toDER();
            $this->subject = $tbsCertificate->at(5)->asSequence()->toDER();
        } else {
            return null;
            throw new CertificateException("Only X.509 v3 certificates are supported: ".base64_encode($this->crtBinary), 1);
        }
        $this->serialNumber = $tbsCertificate->at(1)->asInteger()->number();
    }

    public static function emit($candidate)
    {
        if (!is_string($candidate)) {
            throw new \Exception("X509Certificate requires string-ish input", 1);
        } else {
            $candidate = trim($candidate);
            $crtPEM = explode("\n", $candidate);
            if ($crtPEM[0] == "-----BEGIN CERTIFICATE-----") {
                unset($crtPEM[sizeof($crtPEM)-1]);
                unset($crtPEM[0]);
                $crtDER = base64_decode(implode('', $crtPEM));
            } elseif (substr($candidate, 0, 3) == 'MII') {
                $crtDER = base64_decode($candidate);
            } else {
                try {
                    $crtDER = UnspecifiedType::fromDER($candidate)->asSequence()->toDER();
                } catch (\Exception $e) {
                    throw new CertificateException("Cannot wrangle input into a certificate format", 1);
                }
            }
        }
        return $crtDER;
    }

    public static function WrangleDate($asn1Object)
    {
        switch ($asn1Object->tag()) {
        case 23:
          return $asn1Object->asUTCTime()->datetime();
          break;
        case 24:
          return $asn1Object->asGeneralizedTime()->datetime();
          break;

        default:
          throw new CertificateException(
              "Cannot process date from tag ".$asn1Object->tag().": ".
              base64_encode($asn1Object->toDER()),
              1
          );
          break;
      }
    }

    public static function base64ToPEM($certificateString)
    {
        // Handle line-wrapped presentations of base64
        $certificateString = base64_encode(
            base64_decode($certificateString)
        );
        return "-----BEGIN CERTIFICATE-----\n" .
        chunk_split($certificateString, 64, "\n") .
        "-----END CERTIFICATE-----\n";
    }

    public function getBinary()
    {
        return $this->crtBinary;
    }

    public function getIdentifier($algo = 'sha256')
    {
        return hash($algo, $this->crtBinary);
    }

    public function getKeyUsage()
    {
        return $this->keyUsage;
    }

    public function getDates()
    {
        return [
          $this->notBefore,
          $this->notAfter
        ];
    }

    public function isCurrent()
    {
        return $this->isCurrentAt(new DateTime);
    }

    public function isCurrentAt($dateTime = null)
    {
        if (empty($dateTime)) {
            $dateTime = new \DateTime; // now
        };
        // $dates = $this->getDates();
        return (
          $this->isStartedAt($dateTime) &&
          $this->isNotFinishedAt($dateTime)
        );
    }

    public function isStartedAt($dateTime = null)
    {
        if (empty($dateTime)) {
            $dateTime = new \DateTime; // now
        };
        return (
          $this->notBefore < $dateTime
        );
    }

    public function isNotFinishedAt($dateTime = null)
    {
        if (empty($dateTime)) {
            $dateTime = new \DateTime; // now
        };
        return (
          $this->notAfter > $dateTime
        );
    }

    public function hasExtensions()
    {
        return (! empty($this->extensions));
    }

    public function hasQCStatements()
    {
        if ($this->hasExtensions()) {
            return array_key_exists('qcStatements', $this->extensions);
        }
    }

    protected function getQCStatements()
    {
        if ($this->hasQCStatements()) {
            return $this->getExtensions()['qcStatements']->getStatements();
        }
        return $this->qcStatements;
    }

    public function getQCStatementNames()
    {
        return $this->getExtensions()['qcStatements']->getStatementNames();
    }

    public function toDER()
    {
        return $this->crtBinary;
    }

    protected function getExtensions()
    {
        return $this->extensions;
    }

    public function getExtensionNames()
    {
        return array_keys($this->extensions);
    }

    public function getAuthorityKeyIdentifier()
    {
        if (! empty($this->extensions) && array_key_exists('authorityKeyIdentifier', $this->extensions)) {
            return $this->extensions['authorityKeyIdentifier']->getKeyId();
        } else {
            return false;
        }
    }

    public function getSubjectKeyIdentifier()
    {
        if (! empty($this->extensions) && array_key_exists('subjectKeyIdentifier', $this->extensions)) {
            return $this->extensions['subjectKeyIdentifier']->getKeyId();
        } else {
            return false;
        }
    }

    public function getCDPs()
    {
        if (! empty($this->extensions) && array_key_exists('crlDistributionPoints', $this->extensions)) {
            return $this->extensions['crlDistributionPoints']->getCDPs();
        } else {
            return [];
        }
    }

    public function forPurpose($name)
    {
        if (! empty($this->extensions) && array_key_exists('extendedKeyUsage', $this->extensions)) {
            if ($this->extensions['crlDistributionPoints']->forPurpose($purpose)) {
                return true;
            }
        }
    }

    public function withCRL($crlDER)
    {
        $this->crl = new CertificateRevocationList($crlDER);
    }

    public function isRevoked()
    {
        return $this->crl->isRevoked($this->serialNumber);
    }

    public function getCRL()
    {
        if (! empty($this->crl)) {
            return $this->crl;
        } else {
            return null;
        }
    }

    public function getSerial()
    {
        return $this->serialNumber;
    }

    public function getPublicKey()
    {
        return $this->publicKey;
    }

    public function toPEM()
    {
        return self::base64ToPEM(base64_encode($this->crtBinary));
    }

    public function getSubjectName()
    {
        // TODO: Produce a string even if oids are duplicated
        foreach ($this->x509->getDN(true) as $key => $value) {
            $subject[] = $key.'='.$value;
        }

        return '/'.implode('/', $subject);
    }

    public function getIssuerName()
    {
        foreach ($this->x509->getIssuerDN(true) as $key => $value) {
            $issuer[] = $key.'='.$value;
        }

        return '/'.implode('/', $issuer);
    }

    public function getSubjectExpanded()
    {
        if (empty($this->subjectExpanded)) {
            $subjectDN = UnspecifiedType::fromDER($this->subject)->asSequence();
            foreach ($subjectDN as $DNPart) {
                $this->subjectExpanded[] = self::getDNPartExpanded($DNPart);
            }
        }
        return $this->subjectExpanded;
    }

    public function getIssuerExpanded()
    {
        if (empty($this->issuerExpanded)) {
            $issuerDN = UnspecifiedType::fromDER($this->issuer)->asSequence();
            foreach ($issuerDN as $DNPart) {
                $this->issuerExpanded[] = self::getDNPartExpanded($DNPart);
            }
        }
        return $this->issuerExpanded;
    }

    public function getDNPartExpanded($dnPart)
    {
        $dnElement = $dnPart->asSet()->at(0)->asSequence();
        $oid = $dnElement->at(0)->asObjectIdentifier()->oid();
        $oidName = OID::getName($oid);
        $identifier = $dnElement->at(1)->tag();
        switch ($identifier) {
          case 12:
            $dnPartExpanded['oid'] = "$oidName ($oid)";
            $dnPartExpanded['value'] = $dnElement->at(1)->asUTF8String()->string();
            break;
          case 19:
            $dnPartExpanded['oid'] = "$oidName ($oid)";
            $dnPartExpanded['value'] = $dnElement->at(1)->asPrintableString()->string();
            break;
          case 22:
            $dnPartExpanded['oid'] = "$oidName ($oid)";
            $dnPartExpanded['value'] = $dnElement->at(1)->asIA5String()->string();
            break;
          case 16:
            $elements = [];
            foreach ($dnElement->at(1)->asSequence()->elements() as $element) {
                $elementTag = $element->tag();
                switch ($elementTag) {
                case 12:
                  $elements[] = $element->asUTF8String()->string();
                  break;

                default:
                  throw new ParseException(
                      "Unknown DN component element type ".
                    $elementTag.
                    ": ".
                    base64_encode($element->toDER()),
                      1
                  );
                  break;
              }
            }
            $dnPartExpanded['oid'] = "$oidName ($oid)";
            $dnPartExpanded['value'] = $elements;
            break;

          default:
            throw new ParseException(
                "Unknown DN component type ".
                $identifier.
                ": ".
                base64_encode($dnElement->toDER()),
                1
            );

            break;
        }
        if ($oidName == 'unknown') {
            throw new ParseException(
                "Unknown OID $oid in DN: ".
                base64_encode($dnElement->toDER()),
                1
            );
        }
        return $dnPartExpanded;
    }

    public function getType()
    {
        return 'X509Certificate';
    }

    public function getAttributes()
    {
        if (! array_key_exists('Subject', $this->attributes)) {
            $this->attributes["subjectDN"] = $this->getSubjectName();
            $issuerDN = [];
            foreach ($this->x509->getIssuerDN(true) as $key => $value) {
                $issuerDN[] = $key.'='.$value;
            }
            $this->attributes["issuerDN"] = '/'.implode('/', $issuerDN);
            $this->attributes["fingerprint"] = $this->getIdentifier();
            if (!empty($this->getSubjectKeyIdentifier())) {
                $this->attributes["skiHex"] = bin2hex($this->getSubjectKeyIdentifier());
                $this->attributes["skiBase64"] = base64_encode($this->getSubjectKeyIdentifier());
            }
            if (!empty($this->getAuthorityKeyIdentifier())) {
                $this->attributes["akiHex"] = bin2hex($this->getAuthorityKeyIdentifier());
                $this->attributes["akiBase64"] = base64_encode($this->getAuthorityKeyIdentifier());
            }
            $this->attributes["subjectExpanded"] = $this->getSubjectExpanded();
            $this->attributes["issuerExpanded"] = $this->getIssuerExpanded();
            if (!empty($this->issuers)) {
                foreach ($this->issuers as $id => $issuer) {
                    $this->attributes["issuerCerts"][$id] = $issuer->getAttributes();
                }
            };
            if (!empty($this->tspServiceAttributes)) {
                $this->attributes["tspService"] = $this->tspServiceAttributes;
            }
            if ($this->hasExtensions()) {
                if (!empty($this->getIssuerURIs())) {
                    $this->attributes["caIssuers"] = $this->getIssuerURIs();
                }
                if (!empty($this->getCDPs())) {
                    $this->attributes["crlDistributionPoints"] = $this->getCDPs();
                }
                if (!empty($this->getOCSPURIs())) {
                    $this->attributes["ocsp"] = $this->getOCSPURIs();
                }
                foreach ($this->extensions as $name => $extension) {
                    switch ($extension->getType()) {
                      case 'preCertPoison':
                        $this->attributes["isPrecert"] = true;
                        break;

                      case 'unknown':
                        $this->attributes["unRecognizedExtensions"][$extension->getOID()] = base64_encode($extension->getBinary());
                        break;
                    }
                }
            }
            if (!empty($this->findings)) {
                $findings = [];
                foreach ($this->findings as $findingObject) {
                    $finding = $findingObject->getFinding();
                    $findings[$finding['severity']] = [
                  'component' => $finding['component'],
                  'message' => $finding['message']
                ];
                }
                $this->attributes['findings'] = $findings;
            }
        }

        return $this->attributes;
    }

    public function withIssuer($candidate)
    {
        if (is_object($candidate) && is_a($candidate, 'eIDASCertificate\Certificate\X509Certificate')) {
            $issuer = $candidate;
        } else {
            $issuer = new X509Certificate($candidate);
        }
        if (array_key_exists($issuer->getIdentifier(), $this->issuers)) {
            $this->issuers[$issuer->getIdentifier()] = $issuer;
            return $issuer;
        }

        if (!($this->getIssuerName() === $issuer->getSubjectName())) {
            throw new CertificateException("Subject name mismatch between certificate and issuer", 1);
        } elseif ($issuer->getSubjectKeyIdentifier() <> $this->getAuthorityKeyIdentifier()) {
            throw new CertificateException("Key Identifier mismatch between certificate and issuer", 1);
        }

        // http://phpseclib.sourceforge.net/x509/2.0/examples.html
        $x509Verifier = new X509;
        $x509Verifier->loadX509($this->toDER());
        $x509Verifier->loadCA($issuer->toDER());
        if ($x509Verifier->validateSignature()) {
            $this->issuers[$issuer->getIdentifier()] = $issuer;
            return $issuer;
        } else {
            return false;
        }
    }

    public function getIssuers()
    {
        return $this->issuers;
    }

    public function setTrustedList($trustedList)
    {
        $this->attributes['TrustedList'] = $trustedList->getAttributes();
    }

    public function isCA()
    {
        if (array_key_exists('basicConstraints', $this->extensions)) {
            if ($this->extensions['basicConstraints']->isCA() === true) {
                return true;
            }
        }
        return false;
    }

    public function getPathLength()
    {
        if (
          ! $this->isCA() ||
          ! array_key_exists('basicConstraints', $this->extensions)
        ) {
            return false;
        } else {
            return $this->extensions['basicConstraints']->getPathLength();
        }
    }

    public function getIssuerURIs()
    {
        $uris = [];
        if (array_key_exists('authorityInfoAccess', $this->extensions)) {
            $uris = $this->extensions['authorityInfoAccess']->getCAIssuers();
        }
        return $uris;
    }

    public function getOCSPURIs()
    {
        $uris = [];
        if (array_key_exists('authorityInfoAccess', $this->extensions)) {
            $uris = $this->extensions['authorityInfoAccess']->getOCSP();
        }
        return $uris;
    }

    public function setTSPService($tspServiceAttributes)
    {
        if ($tspServiceAttributes['skiHex'] === bin2hex($this->getSubjectKeyIdentifier())) {
            $this->tspServiceAttributes = $tspServiceAttributes;
        } else {
            throw new TSPServiceException("TSP Service '$tspServiceAttributes' SKI mismatch with this certificate", 1);
        }
    }

    public function getFindings()
    {
        return $this->findings;
    }
}
