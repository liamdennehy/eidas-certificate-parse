<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\CertificateException;
use eIDASCertificate\ParseException;
use eIDASCertificate\AttributeInterface;
use eIDASCertificate\Finding;
use eIDASCertificate\OID;
use eIDASCertificate\Extensions;
use eIDASCertificate\QCStatements;
use eIDASCertificate\ASN1Interface;
use eIDASCertificate\AlgorithmIdentifier;
use eIDASCertificate\DistinguishedName;
use eIDASCertificate\DigitalIdentity\DigitalIdInterface;
use eIDASCertificate\TSPService\TSPServiceException;
use ASN1\Type\UnspecifiedType;
use phpseclib\File\X509;

/**
 *
 */
class X509Certificate implements
    DigitalIdInterface,
    RFC5280ProfileInterface,
    AttributeInterface,
    ASN1Interface
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
    private $signature;
    private $signatureAlgrothimIdentifier;
    public function __construct($candidate)
    {
        $this->crtBinary = X509Certificate::emit($candidate);
        $crtASN1 = UnspecifiedType::fromDER($this->crtBinary)->asSequence();
        $tbsCertificate = $crtASN1->at(0)->asSequence();
        $this->signatureAlgorithmIdentifier = AlgorithmIdentifier::fromDER($crtASN1->at(1)->asSequence()->toDER());
        $signatureValue = $crtASN1->at(2)->asBitString()->string();
        $idx = 0;
        if ($tbsCertificate->hasTagged(0)) {
            $crtVersion = $tbsCertificate->getTagged(0)->asExplicit()->asInteger()->intNumber();
            $idx++;
            // } else {
        //   $version = 1;
        //   throw new CertificateException("Only X.509 v3 certificates are supported: ".base64_encode($this->crtBinary), 1);
        //   return null;
        //
        }
        $this->serialNumber = gmp_strval($tbsCertificate->at($idx++)->asInteger()->number(), 16);
        $this->signature = $tbsCertificate->at($idx++)->asSequence();
        $this->issuer = new DistinguishedName($tbsCertificate->at($idx++));
        $dates = $tbsCertificate->at($idx++)->asSequence();
        $this->notBefore = self::WrangleDate($dates->at(0));
        $this->notAfter = self::WrangleDate($dates->at(1));
        $this->subject = new DistinguishedName($tbsCertificate->at($idx++));
        $subjectPublicKeyInfo = $tbsCertificate->at($idx++)->asSequence();
        $subjectPublicKeyInfoTypeOID =
          $subjectPublicKeyInfo->at(0)->asSequence()->at(0)->asObjectIdentifier()->oid();
        $subjectPublicKeyInfoTypeName = OID::getName($subjectPublicKeyInfoTypeOID);
        switch ($subjectPublicKeyInfoTypeName) {
          case 'rsaEncryption':
          case 'ecPublicKey':
          case 'RSASSA-PSS':
            $this->publicKey = $subjectPublicKeyInfo->toDER();
            break;
          default:
            throw new CertificateException(
                "Unrecognised Public Key Type OID $subjectPublicKeyInfoTypeOID ($subjectPublicKeyInfoTypeName)",
                1
            );

            break;
        }
        if ($tbsCertificate->hasTagged(1)) {
            throw new CertificateException(
                "Cannot understand issuerUniqueID (".base64_encode($tbsCertificate->getTagged(1)).")",
                1
            );
        }
        if ($tbsCertificate->hasTagged(2)) {
            throw new CertificateException(
                "Cannot understand subjectUniqueID (".base64_encode($tbsCertificate->getTagged(2)).")",
                1
            );
        }
        if ($tbsCertificate->hasTagged(3)) {
            $extensionsDER = $tbsCertificate->getTagged(3)->asExplicit()->asSequence()->toDER();
            $this->extensions = new Extensions(
                $extensionsDER
            );
            $this->findings = array_merge($this->findings, $this->extensions->getFindings());
        }
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

    public function getSerialNumber()
    {
        return $this->serialNumber;
    }

    public function getPublicKey()
    {
        return(base64_encode($this->publicKey));
    }

    public function getPublicKeyPEM()
    {
        return
            "-----BEGIN PUBLIC KEY-----\n".
            chunk_split($this->getPublicKey(), 64, "\n").
            '-----END PUBLIC KEY-----';
        return $this->publicKey;
    }

    public function toPEM()
    {
        return self::base64ToPEM(base64_encode($this->crtBinary));
    }

    public function getSubjectASN1()
    {
        return $this->subject->getASN1();
    }

    public function getSubjectDN()
    {
        return $this->subject->getDN();
    }

    public function getIssuerASN1()
    {
        return $this->issuer->getASN1();
    }

    public function getIssuerDN()
    {
        return $this->issuer->getDN();
    }

    public function getSubjectNameHash($algo = 'sha256')
    {
        return $this->subject->getHash($algo);
    }

    public function getIssuerNameHash($algo = 'sha256')
    {
        return $this->issuer->getHash($algo);
    }

    public function getSubjectExpanded()
    {
        return $this->subject->getExpanded();
    }

    public function getIssuerExpanded()
    {
        return $this->issuer->getExpanded();
    }

    public function getType()
    {
        return 'X509Certificate';
    }

    public function getAttributes()
    {
        if (! array_key_exists('subject', $this->attributes)) {
            $subjectDN = $this->getSubjectDN();
            $this->attributes['subject']['DN'] = $subjectDN;
            $this->attributes['subject']['expandedDN'] = $this->getSubjectExpanded();
            $issuerDN = $this->issuer->getDN();
            $this->attributes['issuer']['serialNumber'] = $this->serialNumber;
            $this->attributes['issuer']['DN'] = $issuerDN;
            $this->attributes['issuer']['expandedDN'] = $this->getIssuerExpanded();
            if (!empty($this->issuers)) {
                foreach ($this->issuers as $id => $issuer) {
                    $this->attributes['issuer']['certificates'][] = $issuer->getAttributes();
                }
            };
            if ($subjectDN == $issuerDN) {
                $this->attributes['issuer']['isSelf'] = true;
            } else {
                $this->attributes['issuer']['isSelf'] = false;
            }
            $this->attributes["notBefore"] = (int)$this->notBefore->format('U');
            $this->attributes["notAfter"] = (int)($this->notAfter->format('U'));
            $this->attributes["fingerprint"] = $this->getIdentifier();
            if (!empty($this->tspServiceAttributes)) {
                $this->attributes["tspService"] = $this->tspServiceAttributes;
            }
            $this->attributes['publicKey']['key'] =
            $this->getPublicKey();
            if ($this->hasExtensions()) {
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
            }
            if (!empty($this->findings)) {
                $findings = [];
                foreach ($this->findings as $findingObject) {
                    $finding = $findingObject->getFinding();
                    $severity = $finding['severity'];
                    $component = $finding['component'];
                    $findings[$severity][$component][] =
                        $finding['message']
                    ;
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

    public function getSignatureAlgorithmIdentifier()
    {
        return $this->signatureAlgorithmIdentifier;
    }

    public function getSignatureAlgorithmName()
    {
        return $this->signatureAlgorithmIdentifier->getalgorithmName();
    }

    public function getSignatureAlgorithmParameters()
    {
        return $this->signatureAlgorithmIdentifier->getParameters();
    }

    public function getASN1()
    {
        throw new \Exception("getASN1 not implemented", 1);
    }

    public function getSubjectPublicKeyHash($algo = 'sha256')
    {
        return hash(
            $algo,
            UnspecifiedType::fromDER($this->publicKey)
                ->asSequence()
                ->at(1)
                ->asBitString()
                ->string(),
            true
        );
    }
}
