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
        if (strtolower(substr($url, 0, 4)) == 'http') {
            $filePath = self::DataDir . $fileHash;
        } else {
            $filePath = self::DataDir . $url;
        };
        if (! file_exists($filePath)) {
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
        file_put_contents($filePath, $data);
    }

    /**
     * [getHTTPModifiedTime description]
     * @param  string $url [description]
     * @return null|integer      [description]
     */
    public static function getHTTPModifiedTime($url)
    {
        $lastModified = DataSource::getHTTPHeader($url, 'Last-Modified', 'HEAD');
        if (! $lastModified) {
            $lastModified = DataSource::getHTTPHeader($url, 'Last-Modified', 'GET');
        }
        return $lastModified;
    }

    public static function getHTTPHeader($url, $header, $method = 'HEAD')
    {
        $headerValue = null; // Method may not be supported
        $searchHeader = $header . ':';
        $context  = stream_context_create(array('http' =>array('method'=>$method)));
        $fd = fopen($url, 'rb', false, $context);
        $meta = stream_get_meta_data($fd);
        fclose($fd);
        var_dump($meta['wrapper_data']);
        foreach ($meta['wrapper_data'] as $header) {
            if (explode(' ', $header, 2)[0] == $searchHeader) {
                $headerValue = explode(' ', $header, 2)[1];
            }
        }
        return $headerValue;
    }
}
