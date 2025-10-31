# Cookie Encrypt Bundle

[English](README.md) | [中文](README.zh-CN.md)

[![PHP Version](https://img.shields.io/packagist/php-v/tourze/cookie-encrypt-bundle.svg?style=flat-square)](https://packagist.org/packages/tourze/cookie-encrypt-bundle)
[![Latest Version](https://img.shields.io/packagist/v/tourze/cookie-encrypt-bundle.svg?style=flat-square)](https://packagist.org/packages/tourze/cookie-encrypt-bundle)
[![License](https://img.shields.io/packagist/l/tourze/cookie-encrypt-bundle.svg?style=flat-square)](https://packagist.org/packages/tourze/cookie-encrypt-bundle)
[![Total Downloads](https://img.shields.io/packagist/dt/tourze/cookie-encrypt-bundle.svg?style=flat-square)](https://packagist.org/packages/tourze/cookie-encrypt-bundle)

A Symfony Bundle for automatically encrypting and decrypting specific cookies, particularly useful for deployment environments with strict WAF (Web Application Firewall) rules, such as Azure.

## Features

- Automatic encryption of specified cookies in responses
- Automatic decryption of specified cookies in requests
- Uses XOR encryption algorithm with base64 encoding
- Zero configuration after initial setup
- Seamless integration with Symfony's event system

## Requirements

- PHP 8.1 or higher
- Symfony 6.4 or higher

## Installation

Install via Composer:

```bash
composer require tourze/cookie-encrypt-bundle
```

## Configuration

### 1. Set Encryption Key

Add the encryption key to your `.env` file:

```env
COOKIE_XOR_SECURITY_KEY=your_secure_key_here
```

⚠️ **Important**: 
- Use a strong, random encryption key
- Keep the key secret and never commit it to version control
- Consider using different keys for different environments

### 2. Register the Bundle

If not using Symfony Flex, register the bundle in `config/bundles.php`:

```php
return [
    // ...other bundles
    Tourze\CookieEncryptBundle\CookieEncryptBundle::class => ['all' => true],
];
```

## Usage

Once installed and configured, the bundle automatically handles encryption/decryption for the following cookies:

- `sf_redirect` - Symfony's redirect cookie

The bundle works transparently:
- **On Request**: Automatically decrypts encrypted cookies before your application processes them
- **On Response**: Automatically encrypts cookies before sending them to the client

### How It Works

1. When a request arrives, the `CookieEncryptSubscriber` checks for encrypted cookies
2. If found, it decrypts them using the XOR algorithm and replaces the encrypted values
3. Your application works with the decrypted values normally
4. Before sending the response, the subscriber encrypts the cookie values again

## Advanced Configuration

### Custom Cookie Names

To encrypt additional cookies, extend the `CookieEncryptSubscriber` class:

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

Then override the service definition in your `config/services.yaml`:

```yaml
services:
    Tourze\CookieEncryptBundle\EventSubscriber\CookieEncryptSubscriber:
        class: App\EventSubscriber\CustomCookieEncryptSubscriber
```

## Security Considerations

- The XOR encryption is designed for WAF bypass, not cryptographic security
- Always use HTTPS in production to prevent man-in-the-middle attacks
- Rotate encryption keys periodically
- Store encryption keys securely (use Symfony secrets management)

## Testing

Run the test suite:

```bash
# From the monorepo root
./vendor/bin/phpunit packages/cookie-encrypt-bundle/tests

# Run with PHPStan
php -d memory_limit=2G ./vendor/bin/phpstan analyse packages/cookie-encrypt-bundle
```

## Troubleshooting

### InvalidEncryptionKeyException

This exception is thrown when:
- The `COOKIE_XOR_SECURITY_KEY` environment variable is not set
- The encryption key is empty or contains only whitespace

**Solution**: Ensure you have set a valid encryption key in your `.env` file.

### Cookies Not Being Encrypted

Check that:
1. The bundle is properly registered
2. The encryption key is set
3. The cookie name is in the list of cookies to encrypt

## Contributing

Please see the main monorepo README for contribution guidelines.

## License

MIT
