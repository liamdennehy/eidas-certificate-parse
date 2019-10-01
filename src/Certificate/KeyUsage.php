<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\Certificate\ExtensionInterface;
use eIDASCertificate\Certificate\ExtensionException;
use eIDASCertificate\OID;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
class KeyUsage implements ExtensionInterface
{
    private $binary;
    private $keyUsageBits;

    const type = 'keyUsage';
    const oid = '2.5.29.15';
    const uri = 'https://tools.ietf.org/html/rfc5280#section-4.2.1.3';

    public const digitalSignature   = 0;
    const nonRepudiation     = 1; // recent editions of X.509 have
    // renamed this bit to contentCommitment
    const contentCommitment  = 1;
    const keyEncipherment    = 2;
    const dataEncipherment   = 3;
    const keyAgreement       = 4;
    const keyCertSign        = 5;
    const cRLSign            = 6;
    const encipherOnly       = 7;
    const decipherOnly       = 8;

    public function __construct($extensionDER)
    {
        $bits = [];
        $keyUsage = UnspecifiedType::fromDER($extensionDER)->asBitString();
        $bit = 0;
        while ($bit < 9) {
            if ($bit < $keyUsage->numBits()) {
                $this->keyUsageBits[KeyUsage::getName($bit)] =
                    $keyUsage->testBit($bit) === true;
            } else {
                $this->keyUsageBits[KeyUsage::getName($bit)] =
                    false;
            }
            $bit++;
        }
        $this->binary = $extensionDER;
    }

    public static function getId($name)
    {
        switch ($name) {
          case 'digitalSignature':
            return 0;
            break;
          case 'nonRepudiation':
          case 'contentCommitment':
            return 1;
            break;
          case 'keyEncipherment':
            return 2;
            break;
          case 'dataEncipherment':
            return 3;
            break;
          case 'keyAgreement':
            return 4;
            break;
          case 'keyCertSign':
            return 5;
            break;
          case 'cRLSign':
            return 6;
            break;
          case 'encipherOnly':
            return 7;
            break;
          case 'decipherOnly':
            return 8;
            break;
          default:
            throw new ExtensionException("Unknown keyUsage '$name'", 1);
            break;
        }
    }

    public static function getName($bit)
    {
        switch ($bit) {
          case 0:
            return 'digitalSignature';
            break;
          case 1:
            return 'nonRepudiation';
            break;
          case 2:
            return 'keyEncipherment';
            break;
          case 3:
            return 'dataEncipherment';
            break;
          case 4:
            return 'keyAgreement';
            break;
          case 5:
            return 'keyCertSign';
            break;
          case 6:
            return 'cRLSign';
            break;
          case 7:
            return 'encipherOnly';
            break;
          case 8:
            return 'decipherOnly';
            break;
          default:
            throw new ExtensionException("Unknown keyUsage '$name'", 1);
            break;
        }
    }

    public function getKeyUsage()
    {
        return $this->keyUsageBits;
    }

    public function getType()
    {
        return self::type;
    }

    public function getURI()
    {
        return self::uri;
    }

    public function getBinary()
    {
        return $this->binary;
    }

    public function getDescription()
    {
        return "This is an KeyUsage extension";
    }
}
