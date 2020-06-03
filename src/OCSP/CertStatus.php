<?php

namespace eIDASCertificate\OCSP;

use ASN1\Type\UnspecifiedType;
use eIDASCertificate\ASN1Interface;
use eIDASCertificate\AttributeInterface;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Tagged\ImplicitlyTaggedType;
use ASN1\Type\Primitive\NullType;
use ASN1\Type\Primitive\GeneralizedTime;

class CertStatus implements ASN1Interface, AttributeInterface
{
    private $status;
    private $revokedDateTime;
    private $revokedReason;

    // TODO: Implment $revokedReason, need exemplar
    public function __construct($status, $revokedDateTime = null, $revokedReason = null)
    {
        $this->status = $status;
        $this->revokedDateTime = $revokedDateTime;
        $this->revokedReason = $revokedReason;
    }

    public static function fromDER($der)
    {
        return self::fromTagged(UnspecifiedType::fromDER($der));
    }

    public static function fromTagged($tagged)
    {
        switch ($tagged->tag()) {
          case 0:
            return new CertStatus(0);
            break;
          case 1:
            return new CertStatus(1, $tagged->asImplicit(16)->asSequence()->at(0)->asGeneralizedTime()->dateTime());
            break;
          case 2:
            return new CertStatus(2);
            break;
        }
    }

    public function getBinary()
    {
        return self::getASN1()->toDER();
    }

    public function getASN1()
    {
        switch ($this->status) {
        case 0:
          return new ImplicitlyTaggedType(0, new NullType());
          break;
        case 1:
          return new ImplicitlyTaggedType(1, new Sequence(new GeneralizedTime($this->revokedDateTime)));
          break;
        case 2:
          return new ImplicitlyTaggedType(2, new NullType());
          break;
      }
    }

    public function getStatus()
    {
        return self::getName($this->status);
    }

    public function getRevokedDateTime()
    {
        return $this->revokedDateTime;
    }

    public static function getName($value)
    {
        switch ($value) {
          case 0:
            return 'good';
            break;
          case 1:
            return 'revoked';
            break;
          case 2:
            return 'other';
            break;
        }
    }

    public function getAttributes()
    {
        $attr['status'] = $this->getStatus();
        if (! empty($this->revokedDateTime)) {
            $attr['revokedDateTime'] = $this->revokedDateTime->format('Y-m-d H:i:s');
        }
        return $attr;
    }
}
