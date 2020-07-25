<?php

// With BIG thanks to Let's Encrypt for a detailed walkthrough
// https://letsencrypt.org/2018/04/04/sct-encoding.html

namespace eIDASCertificate\Certificate;

use eIDASCertificate\ExtensionInterface;
use eIDASCertificate\ParseException;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\Finding;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
class SCTList implements ExtensionInterface
{
    private $binary;
    private $findings = [];
    private $isCritical;
    private $list;
    private $entries = [];

    const type = 'sctList';
    const oid = '1.3.6.1.4.1.11129.2.4.2';
    const uri = 'https://tools.ietf.org/html/rfc6962#section-3.3';

    public function __construct($extensionDER, $isCritical = false)
    {
        $this->isCritical = $isCritical;
        $struct = UnspecifiedType::fromDER($extensionDER)->asOctetString()->string();
        $length = unpack('nlength', substr($struct, 0, 2))['length'];
        if (strlen($struct) < ($length + 2)) {
            $this->findings[] = new Finding(
                self::type,
                $isCritical ? 'critical' : 'warning',
                'Malformed SCT extension (not enough bytes): '.
                    base64_encode($extensionDER)
            );
        } elseif (strlen($struct) > ($length + 2)) {
            $this->findings[] = new Finding(
                self::type,
                $isCritical ? 'critical' : 'warning',
                'Malformed SCT extension (too many bytes): '.
                    base64_encode($extensionDER)
            );
        } else {
            $offset = 2;
            while ($offset < $length) {
                $entryLength = unpack('nlen', substr($struct, $offset, 2))['len'];
                $offset = $offset + 2;
                $version = unpack('Cver', substr($struct, $offset++, 1))['ver'];
                $logId = substr($struct, $offset, 32);
                $offset = $offset + 32;
                $at = unpack('Jat', substr($struct, $offset, 8))['at'];
                $offset = $offset + 8;
                // No extensions in v1, always equals '0000' so we skip
                $offset = $offset + 2;
                $hash = self::getHashAlgorithmFromByte(substr($struct, $offset++, 1));
                $cipher = self::getCipherAlgorithmFromByte(substr($struct, $offset++, 1));
                if ($cipher !== 'ecdsa') {
                    $this->findings[] = new Finding(
                        self::type,
                        $isCritical ? 'critical' : 'warning',
                        "Unsupported SCT Signature Algorithm '$cipher-$hash': ".
                          base64_encode($extensionDER)
                    );
                    // Since the remaining structure depends on key format we
                    // cannot parse, so discard all entries (partials may be
                    // more harmful)
                    $this->entries = [];
                    break;
                }
                $sigLength = unpack('nlen', substr($struct, $offset, 2))['len'];
                $offset = $offset + 2;
                $signature = substr($struct, $offset, $sigLength);
                $offset = $offset + $sigLength;
                $this->entries[] = [
                  'version' => $version + 1,
                  'logId' => bin2hex($logId),
                  'at' => $at / 1000,
                  'extensions' => [],
                  'cipherspec' => $cipher.'-'.$hash,
                  'signature' => base64_encode($signature)
                ];
            }
            $this->binary = $extensionDER;
        }
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
        return "This is a Signed Certificate Timestamp list extension";
    }

    public function getFindings()
    {
        return $this->findings;
    }

    public function getIsCritical()
    {
        return $this->isCritical;
    }

    public function setCertificate(X509Certificate $cert)
    {
        null;
    }

    public function getAttributes()
    {
        if (!empty($this->entries)) {
            return [
            'issuer' => ['SCTList' => $this->entries]
          ];
        } else {
            return [];
        }
    }

    public static function getHashAlgorithmFromByte($byte)
    {
        switch ($byte) {
          case chr(00):
            return 'none';
            break;
          case chr(01):
            return 'md5';
            break;
          case chr(02):
            return 'sha1';
            break;
          case chr(03):
            return 'sha224';
            break;
          case chr(04):
            return 'sha256';
            break;
          case chr(05):
            return 'sha384';
            break;
          case chr(06):
            return 'sha512';
            break;
          default:
            return 'unknown';
            break;
        }
    }

    public static function getCipherAlgorithmFromByte($byte)
    {
        switch ($byte) {
          case chr(00):
            return 'anonymous';
            break;
          case chr(01):
            return 'rsa';
            break;
          case chr(02):
            return 'dsa';
            break;
          case chr(03):
            return 'ecdsa';
            break;
          default:
            return 'unknown';
            break;
        }
    }
}
