<?php

namespace Tourze\CookieEncryptBundle\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\CookieEncryptBundle\CookieEncryptBundle;

class CookieEncryptBundleTest extends TestCase
{
    /**
     * 测试 Bundle 初始化
     */
    public function testBundleInitialization(): void
    {
        $bundle = new CookieEncryptBundle();
        $this->assertInstanceOf(CookieEncryptBundle::class, $bundle);
    }
}
