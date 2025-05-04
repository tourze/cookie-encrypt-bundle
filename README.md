# Cookie Encrypt Bundle

这个 Symfony Bundle 用于自动加密和解密特定的 Cookie，特别适用于某些 WAF 特别严格的部署环境（例如 Azure）。

## 功能

- 自动加密响应中的特定 Cookie
- 自动解密请求中的特定 Cookie
- 使用 XOR 加密算法和 base64 编码

## 安装

使用 Composer 安装:

```bash
composer require tourze/cookie-encrypt-bundle
```

## 配置

1. 在 `.env` 文件中设置加密密钥:

```
COOKIE_XOR_SECURITY_KEY=your_secure_key_here
```

2. 在 `config/bundles.php` 中注册 Bundle:

```php
return [
    // ...其他 bundles
    Tourze\CookieEncryptBundle\CookieEncryptBundle::class => ['all' => true],
];
```

## 使用

安装并配置后，Bundle 会自动加密和解密以下 Cookie:

- sf_redirect

## 测试

运行测试:

```bash
./vendor/bin/phpunit packages/cookie-encrypt-bundle/tests
```

## 许可证

MIT
