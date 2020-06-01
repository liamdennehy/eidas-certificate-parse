<?php

require_once __DIR__.'/../vendor/autoload.php';

use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\TrustedList;
use eIDASCertificate\DataSource;

$lotlURL = 'https://ec.europa.eu/tools/lotl/eu-lotl.xml';

$lotl = new TrustedList(file_get_contents($lotlURL));
foreach ($lotl->getTLPointerPaths() as $tlName => $tlPointer) {
    $tls[] = [
    'name' => $tlName,
    'url' => $tlPointer['location'],
    'filename' => 'tl-' . hash('sha256', $tlName) . 'xml'
  ];
}
print json_encode($tls, JSON_PRETTY_PRINT);
exit;
