<?php

namespace Tourze\CookieEncryptBundle\Tests\DependencyInjection;

use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Tourze\CookieEncryptBundle\DependencyInjection\CookieEncryptExtension;

class CookieEncryptExtensionTest extends TestCase
{
    /**
     * 测试服务加载不抛出异常
     */
    public function testLoadDoesNotThrowException(): void
    {
        $container = new ContainerBuilder();
        $extension = new CookieEncryptExtension();

        // 我们只测试方法不会抛出异常
        $configs = [];

        try {
            $extension->load($configs, $container);
            $this->assertTrue(true); // 如果没有异常，测试通过
        } catch (\Exception $e) {
            $this->fail('Extension load method threw an exception: ' . $e->getMessage());
        }
    }

    /**
     * 测试服务配置是否正确加载
     */
    public function testServiceDefinitionIsLoaded(): void
    {
        $container = new ContainerBuilder();
        $extension = new CookieEncryptExtension();

        $extension->load([], $container);

        // 验证是否有服务定义
        $this->assertTrue(
            $container->hasDefinition('Tourze\CookieEncryptBundle\EventSubscriber\CookieEncryptSubscriber') ||
            $container->hasAlias('Tourze\CookieEncryptBundle\EventSubscriber\CookieEncryptSubscriber')
        );
    }
}
