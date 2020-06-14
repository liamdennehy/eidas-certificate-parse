<?php

namespace eIDASCertificate\OCSP;

use ASN1\Type\UnspecifiedType;
use eIDASCertificate\ASN1Interface;
use eIDASCertificate\AttributeInterface;
use eIDASCertificate\DistinguishedName;
use eIDASCertificate\Extensions;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Tagged\ImplicitlyTaggedType;
use ASN1\Type\Tagged\ExplicitlyTaggedType;
use ASN1\Type\Primitive\GeneralizedTime;
use ASN1\Type\Primitive\Integer;
use ASN1\Type\Primitive\OctetString;

class ResponseData implements ASN1Interface, AttributeInterface
{
    private $version;
    private $responderId;
    private $producedAt;
    private $singleResponses;
    private $extensions;

    public function __construct(
        $version,
        $responderId,
        $producedAt,
        $singleResponses,
        $extensions = null
    ) {
        $this->version = $version;
        $this->responderId = $responderId;
        $this->producedAt = $producedAt;
        $this->singleResponses = $singleResponses;
        $this->extensions = $extensions;
    }

    public static function fromDER($der)
    {
        return self::fromSequence(UnspecifiedType::fromDER($der)->asSequence());
    }

    public static function fromSequence($tbsResponseData)
    {
        $idx = 0;
        if ($tbsResponseData->at($idx)->tag() == 0) {
            $version = $tbsResponseData->at($idx)->asInteger()->integer();
            $tbsResponseData = $tbsResponseData->withoutElement($idx);
            $idx++;
            throw new \Exception("ResponData version $version not supported", 1);
        } else {
            $version = 1;
        }
        $responderId = $tbsResponseData->at($idx++);
        switch ($responderId->tag()) {
          case 1:
            $responderId = new DistinguishedName($responderId->asImplicit(16)->at(0));
            break;
          case 2:
            $responderId = $responderId->asImplicit(4)->string();
            break;
          default:
            throw new \Exception("Unkown ResponseID tag ".$responderId->tag(), 1);

            break;

        }
        $producedAt = $tbsResponseData->at($idx++)->asGeneralizedTime()->dateTime();
        $responses = $tbsResponseData->at($idx++)->asSequence();
        foreach ($responses->elements() as $responseElement) {
            $singleResponse = SingleResponse::fromSequence($responseElement->asSequence());
            $singleResponses[$singleResponse->getCertIdIdentifier()] = $singleResponse;
        }
        if ($tbsResponseData->has($idx) && $tbsResponseData->at($idx)->tag() == 1) {
            $extensions = new Extensions($tbsResponseData->at($idx++)->asExplicit()->asSequence());
        } else {
            $extensions = null;
        }
        return new ResponseData(
            $version,
            $responderId,
            $producedAt,
            $singleResponses,
            $extensions
        );
    }

    public function getBinary()
    {
        return $this->getASN1()->toDER();
    }

    public function getASN1($value='')
    {
        $asn1 = new Sequence();
        if ($this->version <> 1) {
            $asn1 = $asn1->withAppended(new ExplicitlyTaggedType(0, new Integer($this->version - 1)));
        };
        if (is_string($this->responderId)) {
            $asn1 = $asn1->withAppended(new ImplicitlyTaggedType(2, new Sequence(new OctetString($this->responderId))));
        } else {
            $asn1 = $asn1->withAppended(new ImplicitlyTaggedType(1, new Sequence($this->responderId->getASN1())));
        }
        $asn1 = $asn1->withAppended(new GeneralizedTime($this->producedAt));
        foreach ($this->singleResponses as $response) {
            $responses[] = $response->getASN1();
        }
        $asn1 = $asn1->withAppended(new Sequence(...$responses));
        if (! empty($this->extensions)) {
            $asn1 = $asn1->withAppended(new ExplicitlyTaggedType(1, $this->extensions->getASN1()));
        }
        return $asn1;
    }

    public function getAttributes()
    {
        $attr['producedAt'] = (int)($this->producedAt->format('U'));
        foreach ($this->singleResponses as $response) {
            $attr['responses'][] = $response->getAttributes();
        }
        if (! empty($this->extensions) && array_key_exists('ocspNonce', $this->extensions->getExtensions())) {
            $attr['nonce'] = bin2hex($this->extensions->getExtensions()['ocspNonce']->getAttributes()['nonce']);
        }
        if (is_string($this->responderId)) {
            $attr['producerKeyHash'] = bin2hex($this->responderId);
        } else {
            $attr['producerDN'] = $this->responderId->getDN();
        }
        return $attr;
    }

    public function getHash($algo = 'sha-256')
    {
        switch (strtolower($algo)) {
          case 'sha-1':
          case 'sha1':
            return hash('sha1', $this->getBinary(), true);
            break;
          case 'sha-256':
          case 'sha256':
            return hash('sha256', $this->getBinary(), true);
            break;
          case 'sha-384':
          case 'sha384':
            return hash('sha384', $this->getBinary(), true);
            break;
          case 'sha-512':
          case 'sha512':
            return hash('sha512', $this->getBinary(), true);
            break;

          default:
            throw new \Exception("Unsupported Hash Algorithm ".$algo, 1);
            break;
        }
    }

    public function getResponderIDType()
    {
        switch (is_string($this->responderId)) {
          case true:
            return "KeyHash";
            break;
          case false:
            return "Name";
            break;
        }
    }

    public function getResponderID()
    {
        return $this->responderId;
    }

    public function getResponderIDPrintable()
    {
        switch ($this->getResponderIDType()) {
          case 'KeyHash':
            return bin2hex($this->responderId);
            break;
          case 'Name':
            return $this->responderId->getDN();
            break;
        }
    }

    public function getResponderIDHash($algo = 'sha256')
    {
        switch ($this->getResponderIDType()) {
        case 'KeyHash':
          return $this->responderId;
          break;
        case 'Name':
          return $this->responderId->getHash($algo);
          break;
      }
    }

    public function setSigner($signer)
    {
        foreach ($this->singleResponses as $responseId => $singleResponse) {
            $this->singleResponses[$responseId] = $singleResponse->setSigner($signer);
        }
    }

    public function hasResponses()
    {
        return (! empty($this->singleResponses));
    }

    public function getCertIdIdentifiers($asHex = false)
    {
        if ($this->hasResponses()) {
            if ($asHex) {
                $vals = [];
                foreach ($this->singleResponses as $key => $value) {
                    $vals[] = bin2hex($key);
                }
                return $vals;
            } else {
                return array_keys($this->singleResponses);
            }
        } else {
            return null;
        }
    }

    public function getResponseIdentifier()
    {
        $ids = $this->getCertIdIdentifiers(false);
        asort($ids);
        return hash('sha256', implode('.', $ids), true);
    }
}
