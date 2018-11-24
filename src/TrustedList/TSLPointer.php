<?php

namespace eIDASCertificate\TrustedList;

/**
 *
 */
class TSLPointer extends \Exception
{
    private $tslLocation;

    public function __construct($tslPointer)
    {
        foreach ($tslPointer->AdditionalInformation->OtherInformation as $tslOtherInfo) {
            if (strpos($tslOtherInfo->asXML(), '<ns3:MimeType>')) {
                if (
                    explode("<", explode(">", $tslOtherInfo->asXML())[2])[0] ==
                    'application/vnd.etsi.tsl+xml'
                ) {
                    $this->tslLocation = (string)$tslPointer->TSLLocation;
                    // if ($fetch) {
                    //     $tslXml = DataSource::fetch($tslLocation);
                    // } else {
                    //     $tslXml = DataSource::load($tslLocation);
                    // }
                    // $newTL = new TrustedList($tslXml, $tslPointer);
                    // return $newTL;
                }
            };
        };
    }

    public function loadTrustedList()
    {
        $tslXml = DataSource::load($tslLocation);
        $newTL = new TrustedList($tslXml, $tslPointer);
        return $newTL;
    }

    public function fetchTrustedList()
    {
        $tslXml = DataSource::fetch($tslLocation);
        $newTL = new TrustedList($tslXml, $tslPointer);
        return $newTL;
    }
}
