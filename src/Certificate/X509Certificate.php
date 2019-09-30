<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\CertificateException;
use eIDASCertificate\ParseException;
use eIDASCertificate\DigitalIdentity\DigitalIdInterface;
use eIDASCertificate\OID;
use eIDASCertificate\QCStatements;
use ASN1\Type\UnspecifiedType;
use phpseclib\File\X509;

/**
 *
 */
class X509Certificate implements DigitalIdInterface, RFC5280ProfileInterface
{
    private $crtResource;
    private $crtBinary;
    private $parsed;
    private $extensions = [];
    private $keyUsage;
    private $crl;
    private $serialNumber;
    private $publicKey;
    private $issuerCert;
    private $issuer;
    private $attributes = [];
    private $issuerExpanded = [];
    private $subjectExpanded = [];

    public function __construct($candidate)
    {
        $this->crtResource = X509Certificate::emit($candidate);
        openssl_x509_export($this->crtResource, $crtPEM);
        $crtPEM = explode("\n", $crtPEM);
        unset($crtPEM[sizeof($crtPEM)-1]);
        unset($crtPEM[0]);
        $this->crtBinary = base64_decode(implode("", $crtPEM));
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
        if (empty($candidate)) {
            return false;
        };
        try {
            if (substr($candidate, 0, 3) == 'MII') {
                $candidate = X509Certificate::base64ToPEM($candidate);
            } elseif (substr(base64_encode($candidate), 0, 3) == 'MII') {
                $candidate = X509Certificate::base64ToPEM(base64_encode($candidate));
            };
        } catch (\Exception $e) {
            // No-op, probably already X.509 Resource
        };
        $certificate = openssl_x509_read($candidate);
        if ($certificate) {
            return $certificate;
        } else {
            throw new CertificateException("Cannot recognise certificate", 1);
        }
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

    public function getDN()
    {
        return openssl_x509_parse($this->crtResource)['name'];
    }

    public function getIDentifier()
    {
        return $this->getHash('sha256');
    }

    public function getHash($algo = 'sha256')
    {
        return openssl_x509_fingerprint($this->crtResource, $algo);
    }

    public static function parse($crt)
    {
        $crtParsed = openssl_x509_parse($crt);
        return $crtParsed;
    }

    public function getParsed()
    {
        return openssl_x509_parse($this->crtResource);
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
        openssl_x509_export($this->crtResource, $pem);
        return $pem;
    }

    public function getSubjectParsed()
    {
        return $this->getParsed()['subject'];
    }

    public function getSubjectName()
    {
        return $this->getParsed()['name'];
    }

    public function getIssuerParsed()
    {
        return $this->getParsed()['issuer'];
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
            foreach ($this->getParsed()['issuer'] as $key => $value) {
                $issuerDN[] = $key.'='.$value;
            }
            $this->attributes["issuerDN"] = implode('/', $issuerDN);
            $this->attributes["fingerprint"] = $this->getIDentifier();
            $this->attributes["SKIHex"] = bin2hex($this->getSubjectKeyIdentifier());
            $this->attributes["SKIBase64"] = base64_encode($this->getSubjectKeyIdentifier());
            $this->attributes["AKIHex"] = bin2hex($this->getAuthorityKeyIdentifier());
            $this->attributes["AKIBase64"] = base64_encode($this->getAuthorityKeyIdentifier());
            $this->attributes["Subject"] = $this->getSubjectExpanded();
            $this->attributes["Issuer"] = $this->getIssuerExpanded();
            if (!empty($this->issuerCert)) {
                $this->attributes["IssuerCert"] = $this->issuerCert->gatAttributes();
            };
        }

        return $this->attributes;
    }

    public function withIssuer($candidate)
    {
        if (is_a($candidate, 'eIDASCertificate\Certificate\X509Certificate')) {
            $issuer = $candidate;
        } else {
            $issuer = new X509Certificate($candidate);
        }
        if (!empty(array_diff($issuer->getSubjectParsed(), $this->getIssuerParsed()))) {
            throw new CertificateException("Subject name mismatch between certificate and issuer", 1);
        } elseif ($issuer->getSubjectKeyIdentifier() <> $this->getAuthorityKeyIdentifier()) {
            throw new CertificateException("Key Identifier mismatch between certificate and issuer", 1);
        }

        $x509Verifier = new X509;
        $x509Verifier->loadX509($this->toPEM());
        $x509Verifier->loadCA($issuer->toPEM());
        if ($x509Verifier->validateSignature()) {
            $this->issuer = $issuer;
            return $issuer;
        } else {
            return false;
        }
    }

    public function getIssuer()
    {
        return $this->issuer;
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
}
