<?php

namespace eIDASCertificate;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ServerException;
use eIDASCertificate\DataSource\HTTPException;

/**
 *
 */
class DataSource
{
    const DataDir = __DIR__ . '/../../data/';

    /**
     * [load description]
     * @param  string $url Either a URL or a filename in DataDir
     * @return string     Contents of (cached) URL
     */
    public static function load($url)
    {
        if (file_exists(self::DataDir . $url)) {
            return file_get_contents($url);
        };
        $isURL = filter_var(
            $url,
            FILTER_VALIDATE_URL,
            FILTER_FLAG_PATH_REQUIRED |
            FILTER_FLAG_HOST_REQUIRED |
            FILTER_FLAG_SCHEME_REQUIRED
        );
        if (! $isURL) {
            throw new \Exception("Does not look like a URL and file not found: $url", 1);
        };
        $urlHash = hash('sha256', $url);
        $filePath = self::DataDir . '*-' . $urlHash;
        $results = glob($filePath);
        if (sizeof($results)) {
            return file_get_contents($results[sizeof($results)-1]);
        } else {
            return self::getHTTP($url);
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
     * @param  [type] $timestamp [description]
     * @return [type]            [description]
     */
    public static function persist($data, $url, $timestamp = null)
    {
        $locationHash = hash('sha256', $url);
        if ($timestamp) {
            $locationHash = "$timestamp-$locationHash";
        };
        $filePath = self::DataDir . $locationHash;
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
            'headers' => [
                // 'User-Agent' => 'GuzzleHttp/6.3.3 curl/7.61.1 PHP/7.1.22',
                'User-Agent' => 'eIDAS-Certificate-Parse',
            ]
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
            'headers' => [
                // 'User-Agent' => 'GuzzleHttp/6.3.3 curl/7.61.1 PHP/7.1.22',
                'User-Agent' => 'eIDAS-Certificate-Parse',
            ]
        ]);
        try {
            $response = $client->request('GET');
            return (string)($response->getBody());
        } catch (\Exception $e) {
            return false;
        }
    }
}
