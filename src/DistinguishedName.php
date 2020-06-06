<?php

namespace eIDASCertificate;

use eIDASCertificate\OID;
use ASN1\Type\Constructed\Sequence;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
class DistinguishedName implements ASN1Interface
{
    const UTF8String      = 12;
    const Sequence        = 16;
    const PrintableString = 19;
    const T61String       = 20;
    const IA5String       = 22;
    private $sequence;

    public function __construct($dnSequence)
    {
        $this->sequence = $dnSequence->asSequence();
    }

    public function getDN()
    {
        $dn = '';
        foreach ($this->sequence->elements() as $dnPart) {
            $expanded = self::getDNPartExpanded($dnPart);
            if (!is_array($expanded['value'])) {
                $dn .= '/'.$expanded['shortName'].'='.$expanded['value'];
            } else {
                foreach ($expanded['value'] as $value) {
                    $dn .= '/'.$expanded['shortName'].'='.$value;
                }
            }
        }
        return $dn;
    }

    public function getExpanded()
    {
        foreach ($this->sequence->elements() as $dnPart) {
            $dnExpanded[] = self::getDNPartExpanded($dnPart);
        }
        return $dnExpanded;
    }

    public static function getDNPartExpanded($dnPart)
    {
        $dnElement = $dnPart->asSet()->at(0)->asSequence();
        $oid = $dnElement->at(0)->asObjectIdentifier()->oid();
        $oidName = OID::getName($oid);
        $dnPartExpanded['name'] = $oidName;
        $dnPartExpanded['shortName'] = OID::getShortName($oidName);
        $dnPartExpanded['oid'] = $oid;
        $identifier = $dnElement->at(1)->tag();
        switch ($identifier) {
        case self::UTF8String:
          $dnPartExpanded['value'] = $dnElement->at(1)->asUTF8String()->string();
          break;
        case self::PrintableString:
          $dnPartExpanded['value'] = $dnElement->at(1)->asPrintableString()->string();
          break;
        case self::T61String:
          $dnPartExpanded['value'] = $dnElement->at(1)->asT61String()->string();
          break;
        case self::IA5String:
          $dnPartExpanded['value'] = $dnElement->at(1)->asIA5String()->string();
          break;
        case self::Sequence:
          $elements = [];
          foreach ($dnElement->at(1)->asSequence()->elements() as $element) {
              $elementTag = $element->tag();
              switch ($elementTag) {
              case self::UTF8String:
                $elements[] = $element->asUTF8String()->string();
                break;
              case self:PrintableString:
                $elements[] = $element->asPrintableString()->string();
                break;
              case self::T61String:
                $elements[] = $element->asT61String()->string();
                break;
              case self:IA5String:
                $elements[] = $element->asIA5String()->string();
                break;

              default:
                throw new ParseException(
                    "Unknown DN component element type ".
                  $elementTag.
                  ": ".
                  base64_encode($element->toDER()),
                    1
                );
                break;
            }
          }
          $dnPartExpanded['value'] = $elements;
          break;

        default:
          throw new ParseException(
              "Unknown DN component type ".
              $identifier.
              ": ".
              base64_encode($dnElement->toDER()),
              1
          );
          break;
        }
        if ($oidName == 'unknown') {
            throw new ParseException(
                "Unknown OID $oid in DN: ".
            base64_encode($dnElement->toDER()),
                1
            );
        }
        return $dnPartExpanded;
    }

    public function getHash($algo = 'sha256')
    {
        return hash($algo, $this->getASN1()->toDER(),true);
    }

    public function getBinary()
    {
        return $this->getASN1()->toDER();
    }

    public function getASN1()
    {
        return $this->sequence;
    }
}
