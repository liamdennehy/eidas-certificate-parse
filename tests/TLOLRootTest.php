<?php

namespace eIDASCertificate\tests;

use PHPUnit\Framework\TestCase;
use eIDASCertificate\DataSource;
use eIDASCertificate\TrustedList;

class TLOLRootTest extends TestCase
{
    public function testTLOLFromRoot()
    {
        $tlolxml=DataSource::load(TrustedList::TrustedListOfListsXML);
        $TrustedListOfLists = new TrustedList($tlolxml, null, false);
        $TLs = $TrustedListOfLists->getTrustedLists();
        $this->assertEquals(
            '59a1bf290b818b177ad61ac4b3e6dcddd46da6d5be9579f8564adea6f2cf073e',
            $TrustedListOfLists->getSignedBy()
        );
        // foreach ($TLs as $tl) {
        //     print $tl->getSchemeTerritory() .': ' . $tl->getSchemeOperatorName() . PHP_EOL;
        //     foreach ($tl->getTSPs() as $tsp) {
        //         print "  TSP: " . $tsp->getName() . PHP_EOL;
        //         foreach ($tsp->getTSPServices() as $tspService) {
        //             print "    TSPService " .
        //                 $tspService->getType() . ": " .
        //                 $tspService->getName() . " (" .
        //                 $tspService->getStatus() . ")" . PHP_EOL;
        //             print
        //                 "      Starting: " . gmdate("Y-m-d H:i:s", $tspService->getDate()) . PHP_EOL;
        //
        //             foreach ($tspService->getIdentities() as $tspServiceIdentity) {
        //                 print "      DigitalIds: " . count($tspServiceIdentity->getDigitalIds()) . PHP_EOL;
        //                 foreach ($tspServiceIdentity->getDigitalIds() as $type => $digitalId) {
        //                     print "        $type: " . $digitalId . PHP_EOL;
        //                 };
        //             };
        //             print "      History Instances: " .
        //                 count($tspService->getTSPServiceHistory()->getInstances()) . PHP_EOL;
        //             if (count($tspService->getTSPServiceHistory())) {
        //                 foreach ($tspService->getTSPServiceHistory()->getInstances() as $instance) {
        //                     print "        " .
        //                         gmdate("Y-m-d H:i:s", $instance->getTime()) . ": " .
        //                         $tspService->getStatus() . PHP_EOL;
        //                 };
        //             }
        //         }
        //     }
        // }
    }
}
