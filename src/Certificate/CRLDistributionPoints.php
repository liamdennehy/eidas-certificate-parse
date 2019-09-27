<?php

namespace eIDASCertificate\Certificate;

use eIDASCertificate\Certificate\ExtensionInterface;
use eIDASCertificate\Certificate\ExtensionException;
use eIDASCertificate\OID;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
class CRLDistributionPoints implements ExtensionInterface
{
    private $binary;
    private $cdpEntries;

    const type = 'crlDistributionPoints';
    const oid = '2.5.29.31';
    const uri = 'https://tools.ietf.org/html/rfc5280#section-4.2.1.13';

    public function __construct($extensionDER)
    {
        $this->cdpEntries = [];
        $sequence = UnspecifiedType::fromDER($extensionDER)->asSequence();
        foreach ($sequence->elements() as $cdpEntry) {
            $cdpEntryDER = $cdpEntry->asSequence()->at(0)->asTagged()->toDER();
            while (bin2hex($cdpEntryDER[0]) == "a0") {
                $cdpEntryDER[0] = chr(48);
                $cdpEntryDER = UnspecifiedType::fromDER($cdpEntryDER)->asSequence()->at(0)->toDER();
            };
            $cdpEntryDER[0] = chr(22);
            try {
                $cdpEntry = UnspecifiedType::fromDER($cdpEntryDER)->asIA5String()->string();
            } catch (\Exception $e) {
                // TODO: Handle DN of CDPs
                // throw new ExtensionException("Malformed Extension CDPs: ". base64_encode($extensionDER), 1);
            }

            $this->cdpEntries[] = $cdpEntry;
        }
        $this->binary = $extensionDER;
    }

    public function getCDPs()
    {
        return $this->cdpEntries;
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
}
