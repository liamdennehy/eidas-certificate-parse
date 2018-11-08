<?php

namespace eIDASCertificate;

/**
 *
 */
class DataSource
{
    const DataDir = __DIR__ . '/../data/';
    public static function getDataFile($url, $forceUpdate = false)
    {
        $fileHash = hash('sha256', $url);
        $filePath = self::DataDir . $fileHash;
        if (! file_exists(self::DataDir . $fileHash)) {
            print "File not found, fetching " . $url . PHP_EOL;
            $data=file_get_contents($url);
            file_put_contents(self::DataDir . $fileHash, $data);
        } else {
            print "Found file with hash " . $fileHash . " for " . $url . PHP_EOL;
        };
        return file_get_contents($filePath);
    }
}
