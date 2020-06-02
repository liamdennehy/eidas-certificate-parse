<?php

namespace eIDASCertificate;

use eIDASCertificate\Certificate;
use eIDASCertificate\Certificate\ExtensionException;
use eIDASCertificate\OID;
use eIDASCertificate\Finding;
use eIDASCertificate\ParseInterface;
use eIDASCertificate\ASN1Interface;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
class Extensions implements ParseInterface, ASN1Interface
{
    private $extensions = [];
    private $findings = [];
    private $binary;

    public function __construct($extensionsSequence)
    {
        if (is_string($extensionsSequence)) {
            throw new \Exception("Extension as Sequence Please!", 1);
        }
        $this->extensions = [];
        foreach ($extensionsSequence->elements() as $extension) {
            $extension = $extension->asSequence();
            $v3Extension = Extension::fromSequence($extension);
            if ($v3Extension) {
                if ($v3Extension->getType() == 'unknown') {
                    $extName = 'unknown-'.$v3Extension->getOID();
                } else {
                    $extName = $v3Extension->getType();
                }
                if (array_key_exists($extName, $this->extensions)) {
                    $this->findings[] = new Finding(
                        'extensions',
                        'error',
                        "Multiple Certificate Extensions of type " . $extName
                    );
                    unset($this->extensions[$extName]);
                    continue;
                }
                $this->findings = array_merge($v3Extension->getFindings(), $this->findings);
                $this->extensions[$extName] = $v3Extension;
            }
        }
        // TODO: Minimum set https://tools.ietf.org/html/rfc5280#section-4.2
        $this->binary = $extensionsSequence->toDER();
    }

    public static function fromDER($der)
    {
        return new Extensions(UnspecifiedType::fromDER($der)->asSequence());
    }

    public function setKeyUsage($keyUsageString)
    {
        $this->extensions['keyUsage'] = new KeyUsage($keyUsageString);
    }

    public function getExtensions()
    {
        return $this->extensions;
    }

    public function getFindings()
    {
        return $this->findings;
    }

    public function getDescriptions()
    {
        $descriptions = [];
        foreach ($$this->extensions as $name => $extension) {
            $descriptions[$name] = $extension->getDescription();
        }
    }

    // TODO: Assemble instead of store
    public function getASN1()
    {
        return UnspecifiedType::fromDER($this->getBinary());
    }

    public function getBinary()
    {
        return $this->binary;
    }

    public function getSKI()
    {
        if (array_key_exists('subjectKeyIdentifier', $this->extensions)) {
            return $this->extensions['subjectKeyIdentifier']->getKeyId();
        } else {
            return false;
        }
    }

    public function getAKI()
    {
        if (array_key_exists('authorityKeyIdentifier', $this->extensions)) {
            return $this->extensions['authorityKeyIdentifier']->getKeyId();
        } else {
            return false;
        }
    }

    public function getCDPs()
    {
        if (array_key_exists('crlDistributionPoints', $this->extensions)) {
            return $this->extensions['crlDistributionPoints']->getCDPs();
        } else {
            return false;
        }
    }

    public function isCA()
    {
        if (array_key_exists('basicConstraints', $this->extensions)) {
            return $this->extensions['basicConstraints']->isCA();
        } else {
            return false;
        }
    }

    public function getPathLength()
    {
        if (array_key_exists('basicConstraints', $this->extensions)) {
            return $this->extensions['basicConstraints']->getPathLength();
        } else {
            return false;
        }
    }

    public function getIssuerURIs()
    {
        if (array_key_exists('authorityInfoAccess', $this->extensions)) {
            return $this->extensions['authorityInfoAccess']->getIssuerURIs();
        } else {
            return false;
        }
    }

    public function getOCSPURIs()
    {
        if (array_key_exists('authorityInfoAccess', $this->extensions)) {
            return $this->extensions['authorityInfoAccess']->getOCSPURIs();
        } else {
            return false;
        }
    }

    public function hasQCStatements()
    {
        return array_key_exists('qcStatements', $this->extensions);
    }
}
