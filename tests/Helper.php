<?php

namespace eIDASCertificate\tests;

use eIDASCertificate\DataSource;

class Helper
{
    public function getHTTP($URI, $type)
    {
        $datadir = __DIR__ . '/../data/';
        $uriId = hash('sha256', $URI);
        switch ($type) {
        case 'tl':
          $filePath = $datadir.'tl-'.$uriId.'.xml';
          if (! file_exists($filePath)) {
              $data = DataSource::getHTTP($URI);
              file_put_contents($filePath, $data);
          }
          return file_get_contents($filePath);
          break;

        default:
          throw new \Exception("Unknown subject type '$type'", 1);

          break;
      }
    }
}
