<?php

namespace eIDASCertificate\Extensions;

use eIDASCertificate\OID;
use eIDASCertificate\Certificate\ExtensionInterface;
use eIDASCertificate\QCStatements\QCStatement;
use eIDASCertificate\QCStatements\QCStatementException;
use ASN1\Type\UnspecifiedType;

/**
 *
 */
class QCStatements implements ExtensionInterface
{
    private $asn1Object;
    private $qcStatements;

    const type = 'qcStatements';
    const oid = '1.3.6.1.5.5.7.1.3';
    const uri = 'https://tools.ietf.org/html/rfc3739.html';

    public function __construct($qcStatementsDER)
    {
        $this->qcStatements = [];
        $qcStatements = UnspecifiedType::fromDER($qcStatementsDER)->asSequence();
        foreach ($qcStatements->elements() as $qcStatementElement) {
            $qcStatementElement = $qcStatementElement->asSequence();
            $qcStatementDER = $qcStatementElement->toDER();
            $qcStatement = QCStatement::fromBinary($qcStatementDER);
            if (! empty($qcStatement)) {
                $qcStatementName = $qcStatement->getType();
                if (array_key_exists($qcStatementName, $this->qcStatements)) {
                    // TODO: Figure out a way to handle multiple qcStatements
                    // of same name, if valid
                    if ($qcStatementName != 'QCPDS') {
                        throw new QCStatementException(
                            "Multiple QCStatements of type " .
                            $qcStatement->getType() . ": " .
                            base64_encode($qcStatementsDER),
                            1
                        );
                    }
                } else {
                    $this->qcStatements[$qcStatement->getType()] = $qcStatement;
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
        if (array_key_exists('QCPDS', $this->getStatements())) {
            return $this->getStatements()['QCPDS']->getLocations();
        } else {
            return false;
        }
    }

    // TODO: Combine Qualified status and type
    public function getQCType()
    {
        if (array_key_exists('QCQualifiedType', $this->getStatements())) {
            return $this->getStatements()['QCQualifiedType']->getQCType();
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
}
