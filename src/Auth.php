<?php
namespace Ericsource\QcloudCos;

use GuzzleHttp\Client;
use Illuminate\Support\Facades\Cache;

class Auth
{
    private $secretId;
    private $secretKey;
    private $config;
    private $cosUrl;

    const QCLOUD_URL = "https://sts.api.qcloud.com/v2/index.php";
    const QCLOUD_DOMAIN = "sts.api.qcloud.com";
    const DURATION_SECONDS = 7200;

    const CACHE_TEMP_KEY = "qcloud_cos_tempkey";

    public function __construct($secretId="", $secretKey="")
    {
        $this->config = config('qcloud-cos');
        $this->secretId = $secretId ? $secretId : $this->config['SecretId'];
        $this->secretKey = $secretKey ? $secretKey : $this->config['SecretKey'];

        $this->cosUrl = "https://". $this->config['Bucket'] .".cos.". $this->config['Region'] .".myqcloud.com";
    }

    public function getAuth()
    {
        // 缓存的临时密钥
        //Cache::forget(self::CACHE_TEMP_KEY);
        $keys = Cache::remember(self::CACHE_TEMP_KEY, intval((self::DURATION_SECONDS - 60*5)/60), function() {
            return $this->getTempKeys();
        });
        if( !$keys ) {
            abort(1001, "获取上传Token失败", ["abort" => "getTempKey获取失败， 请检查qcloud-cos config"]);
        }
        if( $keys['expiredTime'] <= time() ) {
            Cache::forget(self::CACHE_TEMP_KEY);
            abort(1001, "获取上传Token失败", ["abort" => $keys]);
        }

        $Authorization = $this->getAuthorization($keys, "post", "/");

        $data = array(
            'Authorization' => $Authorization,
            'XCosSecurityToken' => $keys['credentials']['sessionToken'],
        );
        $data['bucket'] = $this->config['Bucket'];
        $data['region'] = $this->config['Region'];

        return $data;
    }

    // 计算 COS API 请求用的签名
    protected function getAuthorization($keys, $method="GET", $pathname="/")
    {
        // 获取个人 API 密钥 https://console.qcloud.com/capi
        $SecretId = $keys['credentials']['tmpSecretId'];
        $SecretKey = $keys['credentials']['tmpSecretKey'];

        // 整理参数
        $query = array();
        $headers = array();
        $method = strtolower($method ? $method : 'get');
        $pathname = $pathname ? $pathname : '/';
        substr($pathname, 0, 1) != '/' && ($pathname = '/' . $pathname);

        // 签名有效起止时间
        $now = time() - 1;
        $expired = $now + 600; // 签名过期时刻，600 秒后
        // 要用到的 Authorization 参数列表
        $qSignAlgorithm = 'sha1';
        $qAk = $SecretId;
        $qSignTime = $now . ';' . $expired;
        $qKeyTime = $now . ';' . $expired;
        $qHeaderList = strtolower(implode(';', self::getObjectKeys($headers)));
        $qUrlParamList = strtolower(implode(';', self::getObjectKeys($query)));

        // 签名算法说明文档：https://www.qcloud.com/document/product/436/7778
        // 步骤一：计算 SignKey
        $signKey = hash_hmac("sha1", $qKeyTime, $SecretKey);
        // 步骤二：构成 FormatString
        $formatString = implode("\n", array(strtolower($method), $pathname, self::obj2str($query), self::obj2str($headers), ''));
        header('x-test-method', $method);
        header('x-test-pathname', $pathname);
        // 步骤三：计算 StringToSign
        $stringToSign = implode("\n", array('sha1', $qSignTime, sha1($formatString), ''));
        // 步骤四：计算 Signature
        $qSignature = hash_hmac('sha1', $stringToSign, $signKey);
        // 步骤五：构造 Authorization
        $authorization = implode('&', array(
            'q-sign-algorithm=' . $qSignAlgorithm,
            'q-ak=' . $qAk,
            'q-sign-time=' . $qSignTime,
            'q-key-time=' . $qKeyTime,
            'q-header-list=' . $qHeaderList,
            'q-url-param-list=' . $qUrlParamList,
            'q-signature=' . $qSignature
        ));
        return $authorization;
    }

    // 获取临时密钥
    protected function getTempKeys()
    {
        $ShortBucketName = substr($this->config['Bucket'],0, strripos($this->config['Bucket'], '-'));
        $AppId = substr($this->config['Bucket'], 1 + strripos($this->config['Bucket'], '-'));

        $baseResource = $this->config['Region'] . ':uid/' . $AppId . ':prefix//' . $AppId . '/' . $ShortBucketName . '/';

        $policy = array(
            'version'=> '2.0',
            'statement'=> array(
                array(
                    'action'=> array(
                        // // 这里可以从临时密钥的权限上控制前端允许的操作
                        // 'name/cos:*', // 这样写可以包含下面所有权限
                        // // 列出所有允许的操作
                        // // ACL 读写
                        // 'name/cos:GetBucketACL',
                        // 'name/cos:PutBucketACL',
                        // 'name/cos:GetObjectACL',
                        // 'name/cos:PutObjectACL',
                        // // 简单 Bucket 操作
                        // 'name/cos:PutBucket',
                        // 'name/cos:HeadBucket',
                        // 'name/cos:GetBucket',
                        // 'name/cos:DeleteBucket',
                        // 'name/cos:GetBucketLocation',
                        // // Versioning
                        // 'name/cos:PutBucketVersioning',
                        // 'name/cos:GetBucketVersioning',
                        // // CORS
                        // 'name/cos:PutBucketCORS',
                        // 'name/cos:GetBucketCORS',
                        // 'name/cos:DeleteBucketCORS',
                        // // Lifecycle
                        // 'name/cos:PutBucketLifecycle',
                        // 'name/cos:GetBucketLifecycle',
                        // 'name/cos:DeleteBucketLifecycle',
                        // // Replication
                        // 'name/cos:PutBucketReplication',
                        // 'name/cos:GetBucketReplication',
                        // 'name/cos:DeleteBucketReplication',
                        // // 删除文件
                        // 'name/cos:DeleteMultipleObject',
                        // 'name/cos:DeleteObject',
                        // 简单文件操作
                        'name/cos:PutObject',
                        'name/cos:PostObject',
                        'name/cos:AppendObject',
                        'name/cos:GetObject',
                        'name/cos:HeadObject',
                        'name/cos:OptionsObject',
                        'name/cos:PutObjectCopy',
                        'name/cos:PostObjectRestore',
                        // 分片上传操作
                        'name/cos:InitiateMultipartUpload',
                        'name/cos:ListMultipartUploads',
                        'name/cos:ListParts',
                        'name/cos:UploadPart',
                        'name/cos:CompleteMultipartUpload',
                        'name/cos:AbortMultipartUpload',
                    ),
                    'effect'=> 'allow',
                    'principal'=> array('qcs'=> array('*')),
                    'resource'=> array(
                        'qcs::cos:' . $baseResource,
                        'qcs::cos:' . $baseResource . self::resourceUrlEncode($this->config['AllowPrefix'])
                    )
                )
            )
        );

        $policyStr = str_replace('\\/', '/', json_encode($policy));
        $Action = 'GetFederationToken';
        $Nonce = rand(10000, 20000);
        $Timestamp = time() - 1;
        $Method = 'GET';
        $params = array(
            'Action'=> $Action,
            'Nonce'=> $Nonce,
            'Region'=> '',
            'SecretId'=> $this->secretId,
            'Timestamp'=> $Timestamp,
            'durationSeconds'=> 7200,
            'name'=> 'cos',
            'policy'=> urlencode($policyStr)
        );
        $params['Signature'] = urlencode(self::getSignature($params, $this->secretKey, $Method));

        //请求url
        $url = self::QCLOUD_URL . '?' . self::json2str($params);

        $http = new Client();
        $response = $http->get($url);
        $content = $response->getBody()->getContents();
        $result = json_decode($content, true);

        return array_get($result, "data", false);
    }

    // 计算临时密钥用的签名
    protected static function resourceUrlEncode($str)
    {
        $str = rawurlencode($str);
        //特殊处理字符 !()~
        $str = str_replace('%2F', '/', $str);
        $str = str_replace('%2A', '*', $str);
        $str = str_replace('%21', '!', $str);
        $str = str_replace('%28', '(', $str);
        $str = str_replace('%29', ')', $str);
        $str = str_replace('%7E', '~', $str);
        return $str;
    }

    // 计算临时密钥用的签名
    protected static function getSignature($opt, $key, $method)
    {
        $formatString = $method . self::QCLOUD_DOMAIN . '/v2/index.php?' . self::json2str($opt);
        $formatString = urldecode($formatString);
        $sign = hash_hmac('sha1', $formatString, $key);
        $sign = base64_encode(hex2bin($sign));
        return $sign;
    }

    // obj 转 query string
    protected static function json2str($obj)
    {
        ksort($obj);
        $arr = array();
        foreach ($obj as $key => $val) {
            array_push($arr, $key . '=' . $val);
        }
        return join('&', $arr);
    }

    // 工具方法
    protected static function getObjectKeys($obj)
    {
        $list = array_keys($obj);
        sort($list);
        return $list;
    }
    protected static function obj2str($obj)
    {
        $list = array();
        $keyList = self::getObjectKeys($obj);
        $len = count($keyList);
        for ($i = 0; $i < $len; $i++) {
            $key = $keyList[$i];
            $val = isset($obj[$key]) ? $obj[$key] : '';
            $key = strtolower($key);
            $list[] = rawurlencode($key) . '=' . rawurlencode($val);
        }
        return implode('&', $list);
    }
}