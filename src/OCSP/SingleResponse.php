<?php

namespace eIDASCertificate\OCSP;

use ASN1\Type\UnspecifiedType;
use eIDASCertificate\ASN1Interface;
use eIDASCertificate\AttributeInterface;
use eIDASCertificate\OCSP\CertID;
use eIDASCertificate\Extensions;
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
        // TODO: CertStatus and RevokedInfo
        $certStatus = CertStatus::fromTagged($asn1->at($idx));
        // Implicit tag of status conflicts with explciit tags for remaining elements
        $asn1 = $asn1->withoutElement($idx);
        $thisUpdate = $asn1->at($idx++)->asGeneralizedTime()->dateTime();
        if ($asn1->hasTagged(0)) {
            $nextUpdate = $asn1->getTagged(0)->asExplicit()->asGeneralizedTime()->dateTime();
            $idx++;
        } else {
            $nextUpdate = null;
        }
        if ($asn1->hasTagged(1)) {
            $extensions = new Extensions($asn1->getTagged(1)->asExplicit()->toDER());
            $idx++;
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
            $this->certStatus->getASN1(),
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

    public function getCertID()
    {
        return $this->certId->getASN1();
    }

    public function getAttributes()
    {
        $attr = array_merge(
            $this->certId->getAttributes(),
            $this->certStatus->getAttributes()
        );
        $attr['thisUpdate'] = (int)$this->thisUpdate->format('U');
        if (! empty($this->nextUpdate)) {
            $attr['nextUpdate'] = (int)$this->nextUpdate->format('U');
        }
        if (! empty($this->extensions)) {
            $attr['extensions'] = $this->extensions->getAttributes();
        }
        return $attr;
    }

    public function getCertStatus()
    {
        return $this->certStatus;
    }

    public function setSigner($signer)
    {
        $new = clone $this;
        $new->certId->setSigner($signer);
        return $new;
    }
}
