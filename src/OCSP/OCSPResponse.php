<?php

namespace eIDASCertificate\OCSP;

use ASN1\Element;
use ASN1\Type\UnspecifiedType;
use ASN1\Type\Primitive\Enumerated;
use ASN1\Type\Primitive\ObjectIdentifier;
use ASN1\Type\Primitive\OctetString;
use eIDASCertificate\ASN1Interface;
use eIDASCertificate\AttributeInterface;
use eIDASCertificate\OID;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Tagged\ExplicitlyTaggedType;

class OCSPResponse implements ASN1Interface, AttributeInterface
{
    private $responseStatus;
    private $response;
    private $responseType;

    public function __construct(
        $responseStatus,
        $response = null,
        $responseType = '1.3.6.1.5.5.7.48.1.1'
    ) {
        $this->responseStatus = $responseStatus;
        $this->response = $response;
        if (! strpos($responseType, '.')) {
            $responseType = OID::getOID($responseType);
        }
        switch ($responseType) {
          case '1.3.6.1.5.5.7.48.1.1':
            $this->responseType = new ObjectIdentifier($responseType);
            break;

          default:
            throw new \Exception("ResponseType '".$responseType."' not recognised", 1);
            break;
        }
    }

    public static function fromDER($der)
    {
        return self::fromSequence(UnspecifiedType::fromDER($der)->asSequence());
    }

    public static function fromSequence($asn1)
    {
        $responseStatus = $asn1->at(0)->asEnumerated()->intNumber();
        if ($asn1->hasTagged(0)) {
            $rb = $asn1->getTagged(0)->asExplicit()->asSequence();
            $responseType = $rb->at(0)->asObjectIdentifier()->oid();
            switch ($responseType) {
            case OID::ocspBasic:
            $response = BasicOCSPResponse::fromSequence(
                UnspecifiedType::fromDER(
                    $rb->at(1)->asOctetString()->string()
                )->asSequence()
            );
              return new OCSPResponse($responseStatus, $response);
              break;

              default:
              throw new \Exception("Unknown responseType OID '$responseType'", 1);

              break;
            }
        } else {
            return new OCSPResponse($responseStatus);
        }
    }

    public function getBinary($value='')
    {
        return $this->getASN1()->toDER();
    }

    public function getASN1()
    {
        $seq = new Sequence(new Enumerated($this->responseStatus));
        if (! empty($this->response)) {
            $seq = $seq->withAppended(
                new ExplicitlyTaggedType(
                    0,
                    new Sequence(
                        $this->responseType,
                        new OctetString($this->response->getBinary())
                    )
                )
            );
        }
        return $seq;
    }

    public function getAttributes()
    {
        $attr = [
        'status' => $this->getStatus(),
        'statusReason' => $this->getStatusReason()
      ];
        if (! empty($this->response)) {
            $attr = array_merge(
                $attr,
                $this->response->getAttributes()
            );
        }
        return $attr;
    }

    public function getStatus()
    {
        return $this->responseStatus;
    }

    public function getStatusText()
    {
        // https://tools.ietf.org/html/rfc6960#section-4.2.1
        switch ($this->responseStatus) {
          case 0:
            return 'successful';
            break;
          case 1:
            return 'malformedRequest';
            break;
          case 2:
            return 'internalError';
            break;
          case 3:
            return 'tryLater';
            break;
          case 5:
            return 'sigRequired';
            break;
          case 6:
            return 'unauthorized';
            break;

          default:
            throw new \Exception("Not a valid OCSPResponse status: ".$this->responseStatus, 1);
            break;
        }
    }

    public function getStatusReason()
    {
        //https://tools.ietf.org/html/rfc6960#section-4.2.1
        switch ($this->responseStatus) {
          case 0:
            return 'Response has valid confirmations';
            break;
          case 1:
            return 'Illegal confirmation request';
            break;
          case 2:
            return 'Internal error in issuer';
            break;
          case 3:
            return 'Try again later';
            break;
          case 5:
            return 'Must sign the request';
            break;
          case 6:
            return 'Request unauthorized';
            break;

          default:
            throw new \Exception("Not a valid OCSPResponse status: ".$this->responseStatus, 1);
            break;
        }
    }

    public function hasSignature()
    {
        if ($this->hasResponse()) {
            return $this->response->hasSignature();
        } else {
            return false;
        }
    }

    public function hasResponse()
    {
        return (! empty($this->response));
    }

    public function getCertificates()
    {
        if ($this->hasCertificates()) {
            return $this->response->getCertificates();
        } else {
            return null;
        }
    }

    public function hasCertificates()
    {
        if ($this->hasResponse()) {
            return $this->response->hasCertificates();
        } else {
            return false;
        }
    }

    public function getSigningCert()
    {
        if ($this->hasResponse()) {
            return $this->response->getSigningCert();
        }
    }

    public function setResponder($certificate)
    {
        if ($this->hasSignature()) {
            return $this->response->setResponder($certificate);
        } else {
            return false;
        }
    }

    public function getSignatureAlgorithmOID()
    {
        if ($this->hasResponse()) {
            return $this->response->getSignatureAlgorithmOID();
        } else {
            return null;
        }
    }

    public function getSignatureAlgorithmName()
    {
        if ($this->hasResponse()) {
            return $this->response->getSignatureAlgorithmName();
        } else {
            return null;
        }
    }

    public function setSigner($signer)
    {
        $this->response->setSigner($signer);
    }

    public function getResponseIdentifier()
    {
        if ($this->hasResponse()) {
            return $this->response->getResponseIdentifier();
        } else {
            return false;
        }
    }
}
