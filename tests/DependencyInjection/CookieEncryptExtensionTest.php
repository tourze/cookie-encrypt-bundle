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
        } catch (\Throwable $e) {
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

    /**
     * 测试加载空配置数组
     */
    public function test_load_with_empty_configs(): void
    {
        $container = new ContainerBuilder();
        $extension = new CookieEncryptExtension();

        // 测试空配置数组
        $emptyConfigs = [];

        $this->expectNotToPerformAssertions();
        $extension->load($emptyConfigs, $container);
    }

    /**
     * 测试Extension别名
     */
    public function test_extension_alias(): void
    {
        $extension = new CookieEncryptExtension();
        $this->assertEquals('cookie_encrypt', $extension->getAlias());
    }

    /**
     * 测试配置加载后容器状态
     */
    public function test_container_after_load(): void
    {
        $container = new ContainerBuilder();
        $extension = new CookieEncryptExtension();

        $extension->load([], $container);

        // 验证容器中是否有自动配置的服务
        $definitions = $container->getDefinitions();
        $this->assertNotEmpty($definitions, '容器应该包含服务定义');

        // 验证是否加载了EventSubscriber相关的服务
        $hasEventSubscriber = false;
        foreach ($definitions as $definition) {
            if (strpos($definition->getClass() ?? '', 'EventSubscriber') !== false) {
                $hasEventSubscriber = true;
                break;
            }
        }
        $this->assertTrue($hasEventSubscriber, '应该加载EventSubscriber相关服务');
    }
}
