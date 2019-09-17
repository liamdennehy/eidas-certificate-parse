<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\CertificateException;
use eIDASCertificate\OID;
use eIDASCertificate\QCStatements;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
class X509Certificate implements DigitalIdInterface
{
    private $crtResource;
    private $crtBinary;
    private $parsed;
    private $extensions;
    private $keyUsage;
    private $crl;
    private $serialNumber;
    private $publicKey;

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
        $extensionsDER = $tbsCertificate->at(7)->asTagged()->explicit()->toDER();
        $subjectPublicKeyInfo = $tbsCertificate->at(6)->asSequence();
        $subjectPublicKeyInfoTypeOID =
          $subjectPublicKeyInfo->at(0)->asSequence()->at(0)->asObjectIdentifier()->oid();
        $subjectPublicKeyInfoTypeName = OID::getName($subjectPublicKeyInfoTypeOID);
        switch ($subjectPublicKeyInfoTypeName) {
          case 'rsaEncryption':
            $this->publicKey = $tbsCertificate->at(6)->toDER();
            break;
          default:
            throw new CertificateException(
                "Unrecognised Public Key Type OID $subjectPublicKeyInfoTypeOID ($subjectPublicKeyInfoTypeName)",
                1
            );

            break;
        }
        $this->parsed = X509Certificate::parse($this->crtResource);
        $crtVersion = $tbsCertificate->at(0)->asTagged()->explicit()->number();
        if ($crtVersion == 2) {
            if (array_key_exists('extensions', $this->parsed)) {
                $extensions = new Extensions(
                    $extensionsDER
                );
                $this->extensions = $extensions->getExtensions();
            }
        } else {
            throw new CertificateException("Only X.509 v3 certificates are supported", 1);
        }
        $this->serialNumber = $tbsCertificate->at(1)->asInteger()->number();
    }

    public static function emit($candidate)
    {
        if (is_null($candidate)) {
            return false;
        };
        try {
            if (substr($candidate, 0, 3) == 'MII') {
                $candidate = X509Certificate::base64ToPEM($candidate);
            };
        } catch (\Exception $e) {
            // No-op, probably already X.509 Resource
        };
        $certificate = openssl_x509_read($candidate);
        if ($certificate) {
            $this->crtResource = $certificate;
        } else {
            throw new CertificateException("Cannot recognise certificate", 1);
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

    public function getDN()
    {
        return openssl_x509_parse($this->crtResource)['name'];
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
        return $this->parsed;
    }

    public function getKeyUsage()
    {
        return $this->keyUsage;
    }

    public function getDates()
    {
        return [
          'notBefore' => date_create('@' .  $this->parsed['validFrom_time_t']),
          'notAfter' => date_create('@' .  $this->parsed['validTo_time_t'])
        ];
    }

    public function isValidAt($dateTime = null)
    {
        if (empty($dateTime)) {
            $dateTime = new \DateTime; // now
        };
        $dates = $this->getDates();
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
        $dates = $this->getDates();
        return (
        $dates['notBefore'] < $dateTime
      );
    }

    public function isNotFinishedAt($dateTime = null)
    {
        if (empty($dateTime)) {
            $dateTime = new \DateTime; // now
        };
        $dates = $this->getDates();
        return (
        $dates['notAfter'] > $dateTime
      );
    }

    public function hasExtensions()
    {
        return array_key_exists('extensions', $this->getParsed());
    }

    public function hasQCStatements()
    {
        if ($this->hasExtensions()) {
            return array_key_exists('qcStatements', $this->getParsed()['extensions']);
        }
    }

    public function getQCStatements()
    {
        return $this->qcStatements;
    }

    public function toDER()
    {
        return $this->crtBinary;
    }

    public function getExtensions()
    {
        return $this->extensions;
    }

    public function getAuthorityKeyIdentifier()
    {
        if (array_key_exists('authorityKeyIdentifier', $this->extensions)) {
            return $this->extensions['authorityKeyIdentifier']->getKeyId();
        } else {
            return false;
        }
    }

    public function getSubjectKeyIdentifier()
    {
        if (array_key_exists('subjectKeyIdentifier', $this->extensions)) {
            return $this->extensions['subjectKeyIdentifier']->getKeyId();
        } else {
            return false;
        }
    }

    public function getCDPs()
    {
        if (array_key_exists('crlDistributionPoints', $this->extensions)) {
            return $this->extensions['crlDistributionPoints']->getCDPs();
        } else {
            return [];
        }
    }

    public function forPurpose($name)
    {
        if (array_key_exists('extendedKeyUsage', $this->extensions)) {
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
        return $this->crl;
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

    public function getType()
    {
        return 'X509Certificate';
    }
}
