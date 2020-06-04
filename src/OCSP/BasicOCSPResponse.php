<?php

namespace eIDASCertificate\OCSP;

use ASN1\Type\UnspecifiedType;
use eIDASCertificate\ASN1Interface;
use eIDASCertificate\AttributeInterface;
use eIDASCertificate\OCSP\ResponseData;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\AlgorithmIdentifier;
use ASN1\Type\Tagged\ExplicitlyTaggedType;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\BitString;

class BasicOCSPResponse implements ASN1Interface, AttributeInterface
{
    private $tbsResponseData;
    private $signatureAlgorithm;
    private $signature;
    private $certs;

    public function __construct($tbsResponseData, $signatureAlgorithm = 'rsa-sha256', $signature = null)
    {
        $this->tbsResponseData = $tbsResponseData;
        if (is_string($signatureAlgorithm)) {
            $this->signatureAlgorithm = new AlgorithmIdentifier($signatureAlgorithm);
        } else {
            $this->signatureAlgorithm = $signatureAlgorithm;
        }
        $this->signature = $signature;
    }

    public function withCerts($certs = null)
    {
        $obj = clone $this;
        if (is_null($certs)) {
            $obj->certs = null;
        } elseif (is_array($certs)) {
            $obj->certs = $certs;
        } else {
            $obj->$certs = [$certs];
        }
        return $obj;
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
        $response = new BasicOCSPResponse($tbsResponseData, $signatureAlgorithm, $signature);
        $response = $response->withCerts($certs);
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
}
