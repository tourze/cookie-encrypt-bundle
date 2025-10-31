<?php

namespace Tourze\CookieEncryptBundle\Tests\DependencyInjection;

use PHPUnit\Framework\Attributes\CoversClass;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Tourze\CookieEncryptBundle\DependencyInjection\CookieEncryptExtension;
use Tourze\CookieEncryptBundle\EventSubscriber\CookieEncryptEventSubscriber;
use Tourze\PHPUnitSymfonyUnitTest\AbstractDependencyInjectionExtensionTestCase;

/**
 * @internal
 */
#[CoversClass(CookieEncryptExtension::class)]
final class CookieEncryptExtensionTest extends AbstractDependencyInjectionExtensionTestCase
{
    private CookieEncryptExtension $extension;

    protected function setUp(): void
    {
        parent::setUp();
        $this->extension = new CookieEncryptExtension();
    }

    public function testLoadDoesNotThrowException(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');

        $this->expectNotToPerformAssertions();
        $this->extension->load([], $container);
    }

    /**
     * 测试服务配置是否正确加载
     */
    public function testServiceDefinitionIsLoaded(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $this->extension->load([], $container);

        // 验证是否有服务定义
        $this->assertTrue(
            $container->hasDefinition(CookieEncryptEventSubscriber::class)
            || $container->hasAlias(CookieEncryptEventSubscriber::class)
        );
    }

    /**
     * 测试加载空配置数组
     */
    public function testLoadWithEmptyConfigs(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');

        // 测试空配置数组
        $emptyConfigs = [];

        $this->expectNotToPerformAssertions();
        $this->extension->load($emptyConfigs, $container);
    }

    /**
     * 测试Extension别名
     */
    public function testExtensionAlias(): void
    {
        $this->assertEquals('cookie_encrypt', $this->extension->getAlias());
    }

    /**
     * 测试配置加载后容器状态
     */
    public function testContainerAfterLoad(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $this->extension->load([], $container);

        // 验证容器中是否有自动配置的服务
        $definitions = $container->getDefinitions();
        $this->assertNotEmpty($definitions, '容器应该包含服务定义');

        // 验证是否加载了EventSubscriber相关的服务
        $hasEventSubscriber = false;
        foreach ($definitions as $definition) {
            if (false !== strpos($definition->getClass() ?? '', 'EventSubscriber')) {
                $hasEventSubscriber = true;
                break;
            }
        }
        $this->assertTrue($hasEventSubscriber, '应该加载EventSubscriber相关服务');
    }
}
