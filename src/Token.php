<?php

namespace homevip;

use Illuminate\Support\Facades\Crypt;

class Token
{
    /**
     * 连贯操作方法
     *
     * @var array
     */
    private $token = [
        'iss'   => NULL,
        'iat'   => NULL,
        'exp'   => NULL,
        'aud'   => NULL,
        'sub'   => NULL,
        'key'   => NULL,
        'ip'    => NULL,
    ];


    /**
     * 过期时间
     *
     * @var integer
     */
    private static $expires = 7200;


    /**
     * 错误码
     *
     * @var array
     */
    private $errorCode = [
        '41000' => '不合法的 aud',
        '41001' => '不合法的 iss',
        '41002' => '不合法的 token',
        '41003' => '不合法的 使用令牌',
    ];


    /**
     * 定义实例
     *
     * @var [type]
     */
    private static $instance;


    /**
     * 返回静态实例
     *
     * @return void
     */
    public static function instance(): object
    {
        if (!self::$instance instanceof self) {
            self::$instance = new self();
        }
        return self::$instance;
    }


    /**
     * token 失效时间[多少秒后过期]
     *
     * @param integer $exp/秒
     * @return object
     */
    public function exp(int $exp): object
    {
        $this->token['exp'] = $exp;
        return $this;
    }


    /**
     * 接收该 token 的一方 可做权限判断
     *
     * @param string $aud public_*
     * @return object
     */
    public function aud(string $aud): object
    {
        $this->token['aud'] = $aud;
        return $this;
    }


    /**
     * 该 token 所面向的用户、应用,可做应用模块限制
     *
     * @param string $sub
     * @return void
     */
    public function sub(string $sub): object
    {
        $this->token['sub'] = $sub;
        return $this;
    }


    /**
     * 初始化参数
     *
     * iss 	issuer 发起请求的来源用户
     * iat 	token 创建时间, unix时间戳格式  => $_SERVER['REQUEST_TIME'],
     * exp	非必须。token 过期时间, unix时间戳格式  => $_SERVER['REQUEST_TIME'] + 7200,
     * aud	非必须。接收该token 的一方 可做权限判断
     * sub	非必须。该token所面向的用户、应用,可做应用模块限制
     * nbf	非必须。not before。如果当前时间在nbf里的时间之前，则Token不被接受；一般都会留一些余地，比如几分钟 => 1357000000
     * key	非必须。TokenID 针对当前token的唯一标识 => '222we',
     * ip	非必须。签发时请求者的IP,
     * ...	其他自定义
     *
     * @return void
     */
    public function initial()
    {
        $newTime = $_SERVER['REQUEST_TIME'] ?? time();

        $this->token['iss'] = $_SERVER['HTTP_HOST'];
        $this->token['iat'] = $newTime;
        $this->token['exp'] = empty($this->token['exp']) ? $newTime + self::$expires : $newTime + $this->token['exp'];
        $this->token['key'] = substr(md5($newTime), 6, 5);
        $this->token['ip']  = $this->getIP();

        // 去除为空的值
        $this->token = array_filter($this->token);
    }


    /**
     * 加密数据
     *
     * @param array $param
     * @return void
     */
    public function encrypt(array $param)
    {
        // 初始化参数
        $this->initial();

        $this->token['param'] = $param;
        
        return Crypt::encrypt($this->token);
    }


    /**
     * 解密数据
     *
     * @param string $ciphertext
     * @return void
     */
    public function decrypt(string $ciphertext)
    {
        // 初始化参数
        $this->initial();

        $result = Crypt::decrypt($ciphertext);
        if ($result) {
            // 验证 aud
            if (isset($result['aud']) && $this->token['aud'] != $result['aud']) {
                return 41000;
            } elseif ($_SERVER['HTTP_HOST'] != $result['iss']) {
                // 颁发令牌是否与请求是同域
                return 41001;
            } elseif (($result['iat'] + self::$expires) < time() || $result['exp'] < time()) {
                // Token 过期
                return 41002;
            } elseif ($this->getIP() != $result['ip']) {
                // 获取令牌的ip与使用者的ip 对比
                return 41003;
            }
        }

        return $this->token['param'];
    }


    /**
     * 获取IP
     *
     * @return void
     */
    private function getIP()
    {
        $onlineip = '';
        if (getenv('HTTP_CLIENT_IP') && strcasecmp(getenv('HTTP_CLIENT_IP'), 'unknown')) {
            $onlineip = getenv('HTTP_CLIENT_IP');
        } elseif (getenv('HTTP_X_FORWARDED_FOR') && strcasecmp(getenv('HTTP_X_FORWARDED_FOR'), 'unknown')) {
            $onlineip = getenv('HTTP_X_FORWARDED_FOR');
        } elseif (getenv('REMOTE_ADDR') && strcasecmp(getenv('REMOTE_ADDR'), 'unknown')) {
            $onlineip = getenv('REMOTE_ADDR');
        } elseif (isset($_SERVER['REMOTE_ADDR']) && $_SERVER['REMOTE_ADDR'] && strcasecmp($_SERVER['REMOTE_ADDR'], 'unknown')) {
            $onlineip = $_SERVER['REMOTE_ADDR'];
        }
        return $onlineip;
    }
}
