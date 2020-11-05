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
use eIDASCertificate\Algorithm\AlgorithmIdentifier;
use eIDASCertificate\DistinguishedName;
use eIDASCertificate\DigitalIdentity\DigitalIdInterface;
use eIDASCertificate\TSPService\TSPServiceException;
use eIDASCertificate\OCSP\CertID;
use ASN1\Type\Tagged\ExplicitlyTaggedType;
use ASN1\Type\UnspecifiedType;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\BitString;
use ASN1\Type\Primitive\Integer;
use ASN1\Type\Primitive\GeneralizedTime;
use ASN1\Type\Primitive\UTCTime;
use phpseclib\File\X509;
use phpseclib3\File\X509 as phpseclib3X509;

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
    private $parsed;
    private $extensions;
    private $keyUsage;
    private $crl;
    private $x509Version;
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
    private $tbsSignature;
    private $signatureAlgorithmIdentifier;
    public function __construct($candidate)
    {
        $candidatePEM = X509Certificate::emit($candidate);
        $crtASN1 = UnspecifiedType::fromDER($candidatePEM)->asSequence();
        $tbsCertificate = $crtASN1->at(0)->asSequence();
        $this->signatureAlgorithmIdentifier = AlgorithmIdentifier::fromSequence($crtASN1->at(1)->asSequence());
        $this->signature = $crtASN1->at(2)->asBitString()->string();
        $idx = 0;
        if ($tbsCertificate->hasTagged(0)) {
            $this->x509Version = $tbsCertificate->getTagged(0)->asExplicit()->asInteger()->intNumber() + 1;
            $idx++;
        } else {
            $this->x509Version = 1;
        }
        $serialHex = gmp_strval($tbsCertificate->at($idx++)->asInteger()->number(), 16);
        if (strlen($serialHex) % 2 !== 0) {
            $serialHex = '0' . $serialHex;
        }
        $this->serialNumber = hex2bin($serialHex);
        // TODO: Emit finding if tbsCert signature and signatureAlgorithm do not match
        $this->tbsSignature = AlgorithmIdentifier::fromSequence($tbsCertificate->at($idx++)->asSequence());
        $this->issuer = new DistinguishedName($tbsCertificate->at($idx++));
        $dates = $tbsCertificate->at($idx++)->asSequence();
        $this->notBefore = self::getDateFromElement($dates->at(0));
        $this->notAfter = self::getDateFromElement($dates->at(1));
        $this->subject = new DistinguishedName($tbsCertificate->at($idx++));
        $subjectPublicKeyInfo = $tbsCertificate->at($idx++)->asSequence();
        $subjectPublicKeyInfoTypeOID =
          $subjectPublicKeyInfo->at(0)->asSequence()->at(0)->asObjectIdentifier()->oid();
        $subjectPublicKeyInfoTypeName = OID::getName($subjectPublicKeyInfoTypeOID);
        switch ($subjectPublicKeyInfoTypeName) {
          case 'rsaEncryption':
          case 'ecPublicKey':
          case 'RSASSA-PSS':
            $this->publicKey = $subjectPublicKeyInfo;
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
            $this->extensions = new Extensions(
                $tbsCertificate->getTagged(3)->asExplicit()->asSequence()
            );
            $this->findings = array_merge($this->findings, $this->extensions->getFindings());
        }
    }

    public static function getDateFromElement($element)
    {
        switch ($element->tag()) {
          case 23:
            return $element->asUTCTime();
            break;
          case 24:
            return $element->asGeneralizedTime();
            break;
          default:
              throw new \Exception("Error Processing Date ".$element->tag(), 1);

            break;
        }
    }
    public static function emit($candidate)
    {
        if (is_object($candidate) && get_class($candidate) == 'eIDASCertificate\Certificate\X509Certificate') {
            return $candidate->getBinary();
        }
        if (!is_string($candidate)) {
            throw new \Exception("X509Certificate requires string-ish input or existing X509Certificate object", 1);
        }

        $candidate = trim($candidate);
        $crtPEM = explode("\n", str_replace("\r", "", $candidate));
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
                throw new CertificateException("Cannot wrangle input into a certificate format: ".$e->getMessage(), 1);
            }
        }
        return $crtDER;
    }

    public static function WrangleDate($asn1Object)
    {
        switch ($asn1Object->tag()) {
        case 23:
          return [$asn1Object->asUTCTime()->datetime(),23];
          break;
        case 24:
          return [$asn1Object->asGeneralizedTime()->datetime(),24];
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

    public function getTBSCert()
    {
        $tbsCert = [];
        if ($this->x509Version !== 1) {
            $tbsCert[] = new ExplicitlyTaggedType(0, new Integer($this->x509Version - 1));
        }
        $tbsCert[] = new Integer(gmp_strval(gmp_init('0x'.bin2hex($this->serialNumber)), 10));
        $tbsCert[] = $this->tbsSignature->getASN1();
        $tbsCert[] = $this->issuer->getASN1();
        $tbsCert[] = new Sequence($this->notBefore, $this->notAfter);
        $tbsCert[] = $this->subject->getASN1();
        $tbsCert[] = $this->publicKey;
        if (! empty($this->extensions)) {
            $tbsCert[] = new ExplicitlyTaggedType(3, $this->extensions->getASN1());
        }
        return new Sequence(...$tbsCert);
    }

    public function getSignature()
    {
        return $this->signature;
    }

    public function getBinary()
    {
        return (new Sequence(
            $this->getTBSCert(),
            $this->signatureAlgorithmIdentifier->getASN1(),
            new BitString($this->signature)
        ))->toDER();
    }

    public function getBinaryOld()
    {
        return $this->crtBinary;
    }

    public function getIdentifier($algo = 'sha256')
    {
        return hash($algo, $this->getBinary());
    }

    public function getKeyUsage()
    {
        return $this->keyUsage;
    }

    public function getDates()
    {
        return [
          'notBefore' => $this->getNotBefore(),
          'notAfter' => $this->getNotAfter()
        ];
    }

    public function isCurrent()
    {
        return $this->isCurrentAt(new DateTime);
    }

    public function isCurrentAt($dateTime = null)
    {
        if (empty($dateTime)) {
            (int)($dateTime = new \DateTime)->format('U'); // now
        };
        return (
          $this->isStartedAt($dateTime) &&
          $this->isNotFinishedAt($dateTime)
        );
    }

    public function isStartedAt($unixTime = null)
    {
        if (empty($unixTime)) {
            $unixTime = (int)(new \DateTime)->format('U'); // now
        };
        return (
          $this->getNotBefore() < $unixTime
        );
    }

    public function isNotFinishedAt($unixTime = null)
    {
        if (empty($unixTime)) {
            $unixTime = (int)(new \DateTime)->format('U'); // now
        };
        return (
          $this->getNotAfter() > $unixTime
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
        return $this->getBinary();
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
        return bin2hex($this->serialNumber);
    }

    public function getPublicKeyDER()
    {
        return($this->publicKey->toDER());
    }

    public function getPublicKeyPEM()
    {
        return
            "-----BEGIN PUBLIC KEY-----\n".
            chunk_split(base64_encode($this->getPublicKeyDER()), 64, "\n").
            '-----END PUBLIC KEY-----';
    }

    public function toPEM($withIssuers = false)
    {
        $pem = self::base64ToPEM(base64_encode($this->getBinary()));
        if ($withIssuers) {
            foreach ($this->getIssuers() as $issuer) {
                $pem = $issuer->toPEM(true).$pem;
            }
        }
        return $pem;
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

    public function getIssuerPublicKeyHash($algo = 'sha256')
    {
        if (! $this->hasIssuers()) {
            throw new \Exception("No Issuer Certificate registered", 1);
        }
        $issuerPKH = null;
        foreach ($this->issuers as $issuer) {
            if (empty($issuerPKH)) {
                $issuerPKH = $issuer->getSubjectPublicKeyHash($algo);
            } elseif ($issuerPKH !== $issuer->getSubjectPublicKeyHash()) {
                throw new \Exception("Multiple Key Hashes found (should be impossible)", 1);
            }
        }
        return $issuerPKH;
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

    public function getNotBefore()
    {
        return (int)$this->notBefore->dateTime()->format('U');
    }

    public function getNotAfter()
    {
        return (int)$this->notAfter->dateTime()->format('U');
    }

    public function getAttributes()
    {
        if (! array_key_exists('subject', $this->attributes)) {
            $this->attributes['x509Version'] = $this->x509Version;
            $subjectDN = $this->getSubjectDN();
            $this->attributes['subject']['DN'] = $subjectDN;
            $this->attributes['subject']['expandedDN'] = $this->getSubjectExpanded();
            $issuerDN = $this->issuer->getDN();
            $this->attributes['issuer']['serialNumber'] = bin2hex($this->serialNumber);
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
            };
            $this->attributes["signatureAlgorithm"] = $this->getSignatureAlgorithmName();
            $this->attributes["notBefore"] = $this->getNotBefore();
            $this->attributes["notAfter"] = $this->getNotAfter();
            $this->attributes["fingerprint"] = $this->getIdentifier();
            if (!empty($this->tspServiceAttributes)) {
                $this->attributes["tspService"] = $this->tspServiceAttributes;
            }
            $this->attributes['publicKey']['key'] =
            base64_encode($this->getPublicKeyDER());
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

    public function withoutIssuer($issuerId)
    {
        unset($this->issuers[$issuerId]);
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

        if (explode('-', $this->getSignatureAlgorithmName())[0] == 'ecdsa') {
            $x509Verifier = new phpseclib3X509;
        // $x509Verifier->loadX509($this->toDER());
            // $x509Verifier->loadCA($issuer->toDER());
            // $validatedSignature = $x509Verifier->validateSignature();
            //
            //
            // throw new \Exception("Error Processing Request", 1);
        } else {
            // http://phpseclib.sourceforge.net/x509/2.0/examples.html
            $x509Verifier = new X509;
        }

        $x509Verifier->loadX509($this->toDER());
        $x509Verifier->loadCA($issuer->toDER());


        if ($x509Verifier->validateSignature()) {
            $this->issuers[$issuer->getIdentifier()] = $issuer;
            return $issuer;
        } else {
            return false;
        }
    }

    public function hasIssuers()
    {
        return (! empty($this->issuers));
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
            \str_replace('-', '', $algo),
            $this->publicKey
                ->at(1)
                ->asBitString()
                ->string(),
            true
        );
    }

    public function getCertId($algo = 'sha256', $issuerId = null)
    {
        if (! $this->hasIssuers()) {
            return null;
        }
        if (sizeof($this->getIssuers()) == 1) {
            $issuer = current($this->getIssuers());
        } elseif (! empty($issuerId) && array_key_exists($issuerId, $this->getIssuers())) {
            $issuer = $this->getIssuers()[$issuerId];
        } else {
            return null;
        }
        return new CertID(
            $algo,
            $issuer->getSubjectNameHash($algo),
            $issuer->getSubjectPublicKeyHash($algo),
            $this->getSerialNumber()
        );
    }

    public function getCertIdIdentifier($algo = 'sha256', $issuerId = null)
    {
        return $this->getCertId($algo, $issuerId)->getIdentifier();
    }
}
