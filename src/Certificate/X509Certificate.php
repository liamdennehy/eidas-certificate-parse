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
    private $extensions;
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
    private $notBefore;
    private $notAfter;

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
                $this->extensions = new Extensions(
                    $extensionsDER
                );
                $this->findings = array_merge($this->findings, $this->extensions->getFindings());
                // $this->extensions = $extensions->getExtensions();
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
          'notBefore' => $this->notBefore,
          'notAfter' => $this->notAfter
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
        return (! empty($this->extensions->getExtensions()));
    }

    public function hasQCStatements()
    {
        if ($this->hasExtensions()) {
            return $this->extensions->hasQCStatements();
        }
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
        return $this->extensions->getExtensions();
    }

    public function getExtensionNames()
    {
        return array_keys($this->getExtensions());
    }

    public function getAuthorityKeyIdentifier()
    {
        if (!empty($this->extensions)) {
            return $this->extensions->getAKI();
        } else {
            return false;
        }
    }

    public function getSubjectKeyIdentifier()
    {
        if (!empty($this->extensions)) {
            return $this->extensions->getSKI();
        } else {
            return false;
        }
    }

    public function getCDPs()
    {
        if (!empty($this->extensions)) {
            return $this->extensions->getCDPs();
        } else {
            return false;
        }
    }

    public function forPurpose($name)
    {
        if (! empty($this->getExtensions()) && array_key_exists('extendedKeyUsage', $this->getExtensions())) {
            if ($this->getExtensions()['crlDistributionPoints']->forPurpose($purpose)) {
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

    public function getSubjectDN()
    {
        $dn = "";
        foreach ($this->getSubjectExpanded() as $dnPart) {
            $dn .= '/'.$dnPart['shortName'].'='.$dnPart['value'];
        }
        return $dn;
    }

    public function getIssuerDN()
    {
        $dn = "";
        foreach ($this->getIssuerExpanded() as $dnPart) {
            $dn .= '/'.$dnPart['shortName'].'='.$dnPart['value'];
        }
        return $dn;
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
        $dnPartExpanded['name'] = $oidName;
        $dnPartExpanded['shortName'] = OID::getShortName($oidName);
        $dnPartExpanded['oid'] = $oid;
        $identifier = $dnElement->at(1)->tag();
        switch ($identifier) {
          case 12:
            $dnPartExpanded['value'] = $dnElement->at(1)->asUTF8String()->string();
            break;
          case 19:
            $dnPartExpanded['value'] = $dnElement->at(1)->asPrintableString()->string();
            break;
          case 20:
            $dnPartExpanded['value'] = $dnElement->at(1)->asT61String()->string();
            break;
          case 22:
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
                case 19:
                  $elements[] = $element->asPrintableString()->string();
                  break;
                case 20:
                  $elements[] = $element->asT61String()->string();
                  break;
                case 22:
                  $elements[] = $element->asIA5String()->string();
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
        if (! array_key_exists('subject', $this->attributes)) {
            $this->attributes['subject']['DN'] = $this->getSubjectDN();
            $issuerDN = [];
            foreach ($this->x509->getIssuerDN(true) as $key => $value) {
                if (!is_array($value)) {
                    $value = [$value];
                }
                foreach ($value as $entry) {
                    $issuerDN[] = $key.'='.$entry;
                }
            }
            $this->attributes['issuer']['DN'] = '/'.implode('/', $issuerDN);
            $this->attributes["notBefore"] = (int)$this->notBefore->format('U');
            $this->attributes["notAfter"] = (int)($this->notAfter->format('U'));
            $this->attributes["fingerprint"] = $this->getIdentifier();
            $this->attributes['subject']['expandedDN'] = $this->getSubjectExpanded();
            $this->attributes['issuer']['expandedDN'] = $this->getIssuerExpanded();
            if (!empty($this->issuers)) {
                foreach ($this->issuers as $id => $issuer) {
                    $this->attributes['issuer']['certificates'][] = $issuer->getAttributes();
                }
            };
            if (!empty($this->tspServiceAttributes)) {
                $this->attributes["tspService"] = $this->tspServiceAttributes;
            }
            if (!empty($this->findings)) {
                $findings = [];
                foreach ($this->findings as $findingObject) {
                    $finding = $findingObject->getFinding();
                    $severity = $finding['severity'];
                    $component = $finding['component'];
                    $findings[$severity][$component][] = [
                        $finding['message']
                    ];
                }
                $this->attributes['findings'] = $findings;
            }
            foreach ($this->getExtensions() as $extension) {
                $extension->setCertificate($this);
                $extensionAttributes = $extension->getAttributes();
                foreach (array_keys($extensionAttributes) as $key) {
                    if (!array_key_exists($key, $this->attributes)) {
                        $this->attributes[$key] = [];
                    }
                    if (is_array($extensionAttributes[$key])) {
                        $this->attributes[$key] = array_merge(
                            $this->attributes[$key],
                            $extensionAttributes[$key]
                        );
                    } else {
                        $this->attributes[$key] = $extensionAttributes[$key];
                    }
                }
            }

            // switch ($extension->getType()) {
                // case 'keyUsage':
                // case 'extKeyUsage':
                  // if (!array_key_exists('keyPurposes', $extensionAttributes)) {
              //         $extensionAttributes['keyPurposes'] = [];
              //     }
              //     $extensionAttributes['keyPurposes'] = array_merge(
              //         $extensionAttributes['keyPurposes'],
              //         $extension->getAttributes()['keyPurposes']
              //     );
              //     break;
              //   case 'unknown':
              //     if (!array_key_exists('unRecognizedExtensions', $extensionAttributes)) {
              //         $extensionAttributes['unRecognizedExtensions'] = [];
              //     }
              //     $extensionAttributes['unRecognizedExtensions'] = array_merge(
              //         $extensionAttributes['unRecognizedExtensions'],
              //         $extension->getAttributes()['unRecognizedExtensions']
              //     );
              //     break;
              //
              //   default:
              //     $extensionAttributes = array_merge($extensionAttributes, $extension->getAttributes());
              //     break;
            //   }
            // }
            // $this->attributes = array_merge($this->attributes, $extensionAttributes);
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

        if (!($this->getIssuerDN() === $issuer->getSubjectDN())) {
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
        if (!empty($this->extensions)) {
            return $this->extensions->isCA();
        } else {
            return false;
        }
    }

    public function getPathLength()
    {
        if (!empty($this->extensions)) {
            return $this->extensions->getPathLength();
        } else {
            return false;
        }
    }

    public function getIssuerURIs()
    {
        if (!empty($this->extensions)) {
            return $this->extensions->getIssuerURIs();
        } else {
            return false;
        }
    }

    public function getOCSPURIs()
    {
        if (!empty($this->extensions)) {
            return $this->extensions->getOCSPURIs();
        } else {
            return false;
        }
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

    public function getExtensionsBinary()
    {
        return $this->extensions->getBinary();
    }
}
