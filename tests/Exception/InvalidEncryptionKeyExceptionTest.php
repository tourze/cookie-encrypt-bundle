<?php

namespace Tourze\CookieEncryptBundle\Tests\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\CookieEncryptBundle\Exception\InvalidEncryptionKeyException;
use Tourze\PHPUnitBase\AbstractExceptionTestCase;

/**
 * @internal
 */
#[CoversClass(InvalidEncryptionKeyException::class)]
final class InvalidEncryptionKeyExceptionTest extends AbstractExceptionTestCase
{
    public function testCanBeInstantiated(): void
    {
        $exception = new InvalidEncryptionKeyException();
        self::assertSame('', $exception->getMessage());
        self::assertSame(0, $exception->getCode());
        self::assertNull($exception->getPrevious());
    }

    public function testCanBeInstantiatedWithMessage(): void
    {
        $message = 'Invalid encryption key provided';
        $exception = new InvalidEncryptionKeyException($message);
        self::assertSame($message, $exception->getMessage());
    }

    public function testCanBeInstantiatedWithMessageAndCode(): void
    {
        $message = 'Invalid encryption key provided';
        $code = 123;
        $exception = new InvalidEncryptionKeyException($message, $code);
        self::assertSame($message, $exception->getMessage());
        self::assertSame($code, $exception->getCode());
    }

    public function testCanBeInstantiatedWithMessageCodeAndPrevious(): void
    {
        $message = 'Invalid encryption key provided';
        $code = 123;
        $previous = new \Exception('Previous exception');
        $exception = new InvalidEncryptionKeyException($message, $code, $previous);
        self::assertSame($message, $exception->getMessage());
        self::assertSame($code, $exception->getCode());
        self::assertSame($previous, $exception->getPrevious());
    }
}
