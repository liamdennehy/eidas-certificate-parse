<?php

namespace eIDASCertificate\Extensions;

use eIDASCertificate\OID;
use eIDASCertificate\Finding;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\ExtensionInterface;
use eIDASCertificate\QCStatements\QCStatement;
use eIDASCertificate\QCStatements\QCStatementException;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
class QCStatements implements ExtensionInterface
{
    private $binary;
    private $qcStatements = [];
    private $findings = [];
    private $isCritical;

    const type = 'qcStatements';
    const oid = '1.3.6.1.5.5.7.1.3';
    const uri = 'https://tools.ietf.org/html/rfc3739.html';

    public function __construct($qcStatementsDER, $isCritical = false)
    {
        $this->isCritical = $isCritical;
        $this->binary = $qcStatementsDER;
        $qcStatements = UnspecifiedType::fromDER($qcStatementsDER)->asSequence();
        foreach ($qcStatements->elements() as $qcStatementElement) {
            $qcStatementElement = $qcStatementElement->asSequence();
            $qcStatementDER = $qcStatementElement->toDER();
            $qcStatement = QCStatement::fromBinary($qcStatementDER);
            if (is_a($qcStatement, 'eIDASCertificate\Finding')) {
                $this->findings = array_merge([$qcStatement], $this->findings);
                continue;
            }
            if (! empty($qcStatement)) {
                $findings = $qcStatement->getFindings();
                if (!empty($findings)) {
                    $this->findings = array_merge($findings, $this->findings);
                }
                $qcStatementName = $qcStatement->getType();
                if (array_key_exists($qcStatementName, $this->qcStatements)) {
                    // TODO: Figure out a way to handle multiple qcStatements
                    // of same name, if valid
                    $this->findings[] = new Finding(
                        'qcStatements',
                        'error',
                        "Multiple QCStatements of type " .
                        $qcStatement->getType() . ": " .
                        base64_encode($qcStatementsDER)
                    );
                    unset($this->qcStatements[$qcStatementName]);
                } else {
                    $this->qcStatements[$qcStatement->getType()] = $qcStatement;
                    if (substr($qcStatement->getType(), 0, 8) == 'unknown-') {
                        $this->findings[] = new Finding(
                            'qcStatements',
                            'warning',
                            "Unrecognised qcStatement: " .
                          base64_encode($qcStatementDER)
                        );
                    }
                }
            }
        }
    }

    public function getStatements()
    {
        return $this->qcStatements;
    }

    public function getStatementNames()
    {
        return array_keys($this->qcStatements);
    }

    public function getPDSLocations()
    {
        if (array_key_exists('QCPDS', $this->qcStatements)) {
            return $this->qcStatements['QCPDS']->getLocations();
        } else {
            return false;
        }
    }

    // TODO: Combine Qualified status and type
    public function getQCType()
    {
        if (array_key_exists('QCQualifiedType', $this->qcStatements)) {
            return $this->qcStatements['QCQualifiedType']->getQCType();
        } else {
            return false;
        }
    }

    public function getQCPurpose()
    {
        if (array_key_exists('QCQualifiedType', $this->qcStatements)) {
            return $this->qcStatements['QCQualifiedType']->getQCPurpose();
        } else {
            return false;
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
        return "This is a qcStatements extension";
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
        foreach ($this->qcStatements as $name => $qcStatement) {
            $qcStatement->setCertificate($cert);
        };
    }

    public function getAttributes()
    {
        // TODO: Properly align QCType variations according to ETSI EN 319 412-5 Chapter 4.2
        $attrs = [];
        foreach ($this->qcStatements as $name => $qcStatement) {
            $qcStatementAttributes = $qcStatement->getAttributes();
            foreach (array_keys($qcStatementAttributes) as $key) {
                if (!array_key_exists($key, $attrs)) {
                    $attrs[$key] = [];
                }
                if (is_array($qcStatementAttributes[$key])) {
                    $attrs[$key] = array_merge(
                        $attrs[$key],
                        $qcStatementAttributes[$key]
                    );
                } else {
                    $attrs[$key] = $qcStatementAttributes[$key];
                }
            }
        }
        return $attrs;
    }
}
