<?php

namespace Tourze\CookieEncryptBundle\Tests\Unit\Exception;

use PHPUnit\Framework\TestCase;
use Tourze\CookieEncryptBundle\Exception\InvalidEncryptionKeyException;

class InvalidEncryptionKeyExceptionTest extends TestCase
{
    public function testCanBeInstantiated(): void
    {
        $exception = new InvalidEncryptionKeyException();
        self::assertInstanceOf(InvalidEncryptionKeyException::class, $exception);
        self::assertInstanceOf(\RuntimeException::class, $exception);
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