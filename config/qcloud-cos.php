<?php
/**
 * 腾讯云对象存储配置
 *
 * qcloud-cos.php
 *
 */
return [
    //密钥
    'SecretId' => 'xx',
    //固定密钥
    'SecretKey' => 'xx',
    'Bucket' => 'xxx',
    'Region' => 'ap-guangzhou',
    // 这里改成允许的路径前缀，这里可以根据自己网站的用户登录态判断允许上传的目录，例子：* 或者 a/* 或者 a.jpg
    'AllowPrefix' => '*',
    'Proxy' => '',
];