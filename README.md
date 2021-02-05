#### 使用文档



##### 实例化参数

```php
use homevip;

$Token = Token::instance()
    ->exp(60)
    ->aud('public_*')
    ->sub('zhangsan');
```



##### 加密

```php
$encode = $Token->encrypt([
    'id' => 100,
    'name' => '张三',
]);
```

##### 解密

```php
$decode = $Token->decrypt($encode);
```

