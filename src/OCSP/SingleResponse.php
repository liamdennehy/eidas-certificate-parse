<?php

namespace eIDASCertificate\OCSP;

use ASN1\Type\UnspecifiedType;
use eIDASCertificate\ASN1Interface;
use eIDASCertificate\OCSP\CertID;
use eIDASCertificate\AttributeInterface;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Tagged\ExplicitlyTaggedType;
use ASN1\Type\Tagged\ImplicitlyTaggedType;
use ASN1\Type\Primitive\NullType;
use ASN1\Type\Primitive\GeneralizedTime;

class SingleResponse implements ASN1Interface, AttributeInterface
{
    private $certId;
    private $certStatus;
    private $thisUpdate;
    private $nextUpdate;
    private $extensions;

    public function __construct($certId, $certStatus, $thisUpdate, $nextUpdate = null, $singleExtensions = null)
    {
        $this->certId = $certId;
        $this->certStatus = $certStatus;
        $this->thisUpdate = $thisUpdate;
        $this->nextUpdate = $nextUpdate;
        $this->extensions = $singleExtensions;
    }

    public static function fromDER($der)
    {
        return self::fromSequence(UnspecifiedType::fromDER($der)->asSequence());
    }

    public static function fromSequence($asn1)
    {
        $idx = 0;
        $certId = certId::fromSequence($asn1->at($idx++)->asSequence());
        $certStatus = $asn1->at($idx++)->asTagged(0)->tag();
        $thisUpdate = $asn1->at($idx++)->asGeneralizedTime()->dateTime();
        if ($asn1->hasTagged(0)) {
            $nextUpdate = $asn1->at($idx++)->asExplicit(0)->asGeneralizedTime()->dateTime();
        } else {
            $nextUpdate = null;
        }
        if ($asn1->hasTagged(1)) {
            $extensions = new Extensions($asn1->at($idx++)->toDER());
        } else {
            $extensions = null;
        }
        return new SingleResponse(
            $certId,
            $certStatus,
            $thisUpdate,
            $nextUpdate,
            $extensions
        );
    }

    public function getBinary()
    {
        return $this->getASN1()->toDER();
    }

    public function getASN1()
    {
        $asn1 = new Sequence(
            $this->certId->getASN1(),
            new ImplicitlyTaggedType(0, new NullType()),
            new GeneralizedTime($this->thisUpdate)
        );
        if (! empty($this->nextUpdate)) {
            $asn1 = $asn1->withAppended(
                new ExplicitlyTaggedType(0, new GeneralizedTime($this->nextUpdate))
            );
        }
        if (! empty($this->extensions)) {
            $asn1 = $asn1->withAppended(
                $this->extensions->getASN1()
            );
        }
        return $asn1;
    }

    public function getAttributes()
    {
        return [
          'certIDs' => $this->certId->getAttributes()
        ];
    }
}
