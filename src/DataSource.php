<?php

namespace eIDASCertificate;

/**
 *
 */
class DataSource
{
    const DataDir = __DIR__ . '/../data/';

    /**
     * [load description]
     * @param  string $url [description]
     * @return string      [description]
     */
    public static function load($url)
    {
        $fileHash = hash('sha256', $url);
        $filePath = self::DataDir . $fileHash;
        if (! file_exists(self::DataDir . $fileHash)) {
            return self::fetch($url);
        } else {
            return file_get_contents($filePath);
        }
    }

    /**
     * [fetch description]
     * @param  string $url [description]
     * @return string      [description]
     */
    public static function fetch($url)
    {
        $data=file_get_contents($url);
        return $data;
    }

    /**
     * [persist description]
     * @param  string $data [description]
     * @param  string $url  [description]
     */
    public static function persist($data, $url)
    {
        $fileHash = hash('sha256', $url);
        $filePath = self::DataDir . $fileHash;
        file_put_contents(self::DataDir . $fileHash, $data);
    }
}
