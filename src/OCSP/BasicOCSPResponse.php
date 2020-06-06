<?php

namespace eIDASCertificate\OCSP;

use ASN1\Type\UnspecifiedType;
use eIDASCertificate\ASN1Interface;
use eIDASCertificate\AttributeInterface;
use eIDASCertificate\OCSP\ResponseData;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\Algorithm\AlgorithmIdentifier;
use ASN1\Type\Tagged\ExplicitlyTaggedType;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\BitString;

// TODO: Signature Generation
class BasicOCSPResponse implements ASN1Interface, AttributeInterface
{
    private $tbsResponseData;
    private $signatureAlgorithm;
    private $signature;
    private $certs;
    private $responderCert;
    const x509Class = 'eIDASCertificate\Certificate\X509Certificate';

    public function __construct($tbsResponseData, $signatureAlgorithm = 'rsa-sha256', $signature = null, $certs = null)
    {
        $this->tbsResponseData = $tbsResponseData;
        if (is_string($signatureAlgorithm)) {
            $this->signatureAlgorithm = new AlgorithmIdentifier($signatureAlgorithm);
        } else {
            $this->signatureAlgorithm = $signatureAlgorithm;
        }
        $this->signature = $signature;
        if (! empty($certs)) {
            $this->setCertificates($certs);
        }
    }

    public function setCertificates($certs = null)
    {
        if (is_null($certs)) {
            $this->certs = null;
            return;
        }
        if (! is_array($certs)) {
            $certs = [$certs];
        }
        // avoid overwriting existing collection in case input is not valid
        $newCerts = [];
        foreach ($certs as $cert) {
            if (is_object($cert) && get_class($cert) == self::x509Class) {
                $newCerts[] = $cert;
            } else {
                try {
                    $newCerts[] = new X509Certificate($cert);
                } catch (\Exception $e) {
                    throw new \Exception("Input could not be recognised as certificate(s)", 1);
                }
            }
            $this->setResponder($newCerts[sizeof($newCerts)-1]);
        }
        $this->certs = $newCerts;
    }

    public static function fromSequence($seq)
    {
        $tbsResponseData = ResponseData::fromSequence($seq->at(0)->asSequence());
        $signatureAlgorithm = AlgorithmIdentifier::fromSequence($seq->at(1));
        $signature = $seq->at(2)->asBitString()->string();
        if ($seq->hasTagged(0)) {
            foreach ($seq->getTagged(0)->asExplicit()->asSequence()->elements() as $cert) {
                $certs[] = new X509Certificate($cert->toDER());
            }
        } else {
            $certs = null;
        }
        $response = new BasicOCSPResponse($tbsResponseData, $signatureAlgorithm, $signature, $certs);
        return $response;
    }

    public static function fromDER($der)
    {
        return self::fromSequence(UnspecifiedType::fromDER($der)->asSequence());
    }

    public function getBinary()
    {
        return $this->getASN1()->toDER();
    }

    public function getASN1()
    {
        $seq = new Sequence(
            $this->tbsResponseData->getASN1(),
            $this->signatureAlgorithm->getASN1(),
            new BitString($this->signature)
        );
        if (! empty($this->certs)) {
            foreach ($this->certs as $cert) {
                $certs[] = UnspecifiedType::fromDER($cert->getBinary())->asSequence();
            }
            $seq = $seq->withAppended(new ExplicitlyTaggedType(0, new Sequence(...$certs)));
        }

        return $seq;
    }

    public function hasCertificates()
    {
        return (! empty($this->certs));
    }

    public function getCertificates()
    {
        return $this->certs;
    }

    public function getAttributes()
    {
        $attr = $this->tbsResponseData->getAttributes();
        $attr['signatureAlgorithm'] = $this->signatureAlgorithm->getAlgorithmName();
        if (empty($this->signature)) {
            $attr['hasSignature'] = false;
        } else {
            $attr['hasSignature'] = true;
        }
        return $attr;
    }

    public function hasSignature()
    {
        return (! empty($this->signature));
    }

    public function getSignatureAlgorithmName()
    {
        return $this->signatureAlgorithm->getAlgorithmName();
    }

    public function getSignatureAlgorithmOID()
    {
        return $this->signatureAlgorithm->getAlgorithmOID();
    }

    public function getResponderIDType()
    {
        return $this->tbsResponseData->getResponderIDType();
    }

    public function getResponderID()
    {
        return $this->tbsResponseData->getResponderID();
    }

    public function getResponderIDPrintable()
    {
        return $this->tbsResponseData->getResponderIDPrintable();
    }

    public function setResponder($responderCert = null)
    {
        if (
            is_object($responderCert) &&
            get_class($responderCert) !== self::x509Class
        ) {
            throw new \Exception("Provided object is not a certificate", 1);
        } elseif (is_string($responderCert)) {
            try {
                $responderCert = new X509Certificate($responderCert);
            } catch (\Exception $e) {
                throw new \Exception("Responder should be a certificate object or string that represents a certificate", 1);
            }
        }
        switch ($this->getResponderIDType()) {
          case 'KeyHash':
            if ($this->getResponderID() !== $responderCert->getSubjectPublicKeyHash('sha1')) {
                return false;
            }
            break;
          case 'Name':
            if ($this->getResponderID()->getHash('sha1') !== $responderCert->getSubjectNameHash('sha1')) {
                return false;
            }
            break;
        }
        if ($this->isSignedBy($responderCert)) {
            $this->responderCert = $responderCert;
            return true;
        } else {
            return false;
        }
    }

    private function isSignedBy($signer)
    {
        if (empty($this->signature)) {
            return false;
        } else {
            $pubKey = $signer->getPublicKeyPEM();
            $algorithm = $this->signatureAlgorithm->getAlgorithm();
            return ($algorithm->verify(
                $this->tbsResponseData->getBinary(),
                $this->signature,
                $pubKey
            ));
        }
    }

    public function getResponder()
    {
        return $this->responderCert;
    }
}
