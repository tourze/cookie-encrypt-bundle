# Cookie 加密包

[English](README.md) | [中文](README.zh-CN.md)

[![PHP 版本](https://img.shields.io/packagist/php-v/tourze/cookie-encrypt-bundle.svg?style=flat-square)](https://packagist.org/packages/tourze/cookie-encrypt-bundle)
[![最新版本](https://img.shields.io/packagist/v/tourze/cookie-encrypt-bundle.svg?style=flat-square)](https://packagist.org/packages/tourze/cookie-encrypt-bundle)
[![许可证](https://img.shields.io/packagist/l/tourze/cookie-encrypt-bundle.svg?style=flat-square)](https://packagist.org/packages/tourze/cookie-encrypt-bundle)
[![总下载量](https://img.shields.io/packagist/dt/tourze/cookie-encrypt-bundle.svg?style=flat-square)](https://packagist.org/packages/tourze/cookie-encrypt-bundle)

一个用于自动加密和解密特定 Cookie 的 Symfony Bundle，特别适用于 WAF（Web 应用防火墙）规则严格的部署环境，如 Azure。

## 功能特性

- 自动加密响应中的指定 Cookie
- 自动解密请求中的指定 Cookie  
- 使用 XOR 加密算法配合 base64 编码
- 初始设置后零配置
- 与 Symfony 事件系统无缝集成

## 系统要求

- PHP 8.1 或更高版本
- Symfony 6.4 或更高版本

## 安装

通过 Composer 安装：

```bash
composer require tourze/cookie-encrypt-bundle
```

## 配置

### 1. 设置加密密钥

在 `.env` 文件中添加加密密钥：

```env
COOKIE_XOR_SECURITY_KEY=your_secure_key_here
```

⚠️ **重要提示**：
- 使用强随机加密密钥
- 保持密钥机密，切勿提交到版本控制
- 考虑为不同环境使用不同的密钥

### 2. 注册 Bundle

如果未使用 Symfony Flex，在 `config/bundles.php` 中注册 bundle：

```php
return [
    // ...其他 bundles
    Tourze\CookieEncryptBundle\CookieEncryptBundle::class => ['all' => true],
];
```

## 使用方法

安装并配置后，bundle 会自动处理以下 Cookie 的加密/解密：

- `sf_redirect` - Symfony 的重定向 Cookie

Bundle 透明地工作：
- **请求时**：在应用程序处理之前自动解密加密的 Cookie
- **响应时**：在发送给客户端之前自动加密 Cookie

### 工作原理

1. 当请求到达时，`CookieEncryptSubscriber` 检查加密的 Cookie
2. 如果找到，使用 XOR 算法解密并替换加密值
3. 应用程序正常处理解密后的值
4. 在发送响应之前，订阅器再次加密 Cookie 值

## 高级配置

### 自定义 Cookie 名称

要加密额外的 Cookie，扩展 `CookieEncryptSubscriber` 类：

```php
namespace App\EventSubscriber;

use Tourze\CookieEncryptBundle\EventSubscriber\CookieEncryptSubscriber;

class CustomCookieEncryptSubscriber extends CookieEncryptSubscriber
{
    protected array $names = [
        'sf_redirect',
        'my_custom_cookie',
        'another_cookie',
    ];
}
```

然后在 `config/services.yaml` 中覆盖服务定义：

```yaml
services:
    Tourze\CookieEncryptBundle\EventSubscriber\CookieEncryptSubscriber:
        class: App\EventSubscriber\CustomCookieEncryptSubscriber
```

## 安全考虑

- XOR 加密设计用于绕过 WAF，而非加密安全
- 生产环境中始终使用 HTTPS 以防止中间人攻击
- 定期轮换加密密钥
- 安全存储加密密钥（使用 Symfony 密钥管理）

## 测试

运行测试套件：

```bash
# 从 monorepo 根目录
./vendor/bin/phpunit packages/cookie-encrypt-bundle/tests

# 使用 PHPStan 运行
php -d memory_limit=2G ./vendor/bin/phpstan analyse packages/cookie-encrypt-bundle
```

## 故障排除

### InvalidEncryptionKeyException

此异常在以下情况下抛出：
- 未设置 `COOKIE_XOR_SECURITY_KEY` 环境变量
- 加密密钥为空或仅包含空白字符

**解决方案**：确保在 `.env` 文件中设置了有效的加密密钥。

### Cookie 未被加密

检查：
1. Bundle 已正确注册
2. 已设置加密密钥
3. Cookie 名称在要加密的列表中

## 贡献

请参阅主 monorepo README 了解贡献指南。

## 许可证

MIT
