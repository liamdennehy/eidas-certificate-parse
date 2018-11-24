<?php

namespace eIDASCertificate;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ServerException;

/**
 *
 */
class DataSource
{
    const DataDir = __DIR__ . '/../../data/';

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
            return self::getHTTP($url);
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
        $data=self::getHTTP($url);
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
     * @return string|boolean      [description]
     */
    public static function getHTTPModifiedTime($url)
    {
        $lastModified = DataSource::getHTTPHeader($url, 'Last-Modified', 'HEAD');
        if (! $lastModified) {
            $lastModified = DataSource::getHTTPHeader($url, 'Last-Modified', 'GET');
        }
        return $lastModified;
    }

    /**
     * [getHTTPHeader description]
     * @param  string $url    [description]
     * @param  string $header [description]
     * @param  string $method [description]
     * @return string|boolean         [description]
     */
    public static function getHTTPHeader($url, $header, $method = 'HEAD')
    {
        $client = new Client([
            'base_uri' => $url,
        ]);
        try {
            $response = $client->request($method);
            if (sizeof($response->getHeader($header))) {
                return $response->getHeader($header)[0];
            }
        } catch (ServerException $e) {
            return false;
        };
        return false;
    }

    public static function getHTTP($url)
    {
        $client = new Client([
            'base_uri' => $url,
        ]);
        try {
            $response = $client->request('GET');
            return (string)($response->getBody());
        } catch (\Exception $e) {
            return false;
        }
    }
}
