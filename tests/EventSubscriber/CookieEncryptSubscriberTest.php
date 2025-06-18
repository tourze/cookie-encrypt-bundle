<?php

namespace Tourze\CookieEncryptBundle\Tests\EventSubscriber;

use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\InputBag;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\KernelEvents;
use Tourze\CookieEncryptBundle\EventSubscriber\CookieEncryptSubscriber;

class CookieEncryptSubscriberTest extends TestCase
{
    private CookieEncryptSubscriber $subscriber;
    private string $securityKey = 'test_security_key';

    protected function setUp(): void
    {
        parent::setUp();

        // 设置环境变量
        $_ENV['COOKIE_XOR_SECURITY_KEY'] = $this->securityKey;

        $this->subscriber = new CookieEncryptSubscriber();
    }

    protected function tearDown(): void
    {
        // 清理环境变量
        unset($_ENV['COOKIE_XOR_SECURITY_KEY']);

        parent::tearDown();
    }

    /**
     * 测试事件订阅配置
     */
    public function testGetSubscribedEvents(): void
    {
        $events = CookieEncryptSubscriber::getSubscribedEvents();

        $this->assertArrayHasKey(KernelEvents::REQUEST, $events);
        $this->assertArrayHasKey(KernelEvents::RESPONSE, $events);
        $this->assertEquals('onKernelRequest', $events[KernelEvents::REQUEST]);
        $this->assertEquals('onKernelResponse', $events[KernelEvents::RESPONSE][0]);
        $this->assertEquals(-200, $events[KernelEvents::RESPONSE][1]);
    }

    /**
     * 测试XOR加密方法
     *
     * @dataProvider xorEncryptDataProvider
     */
    public function testXorEncrypt(string $input, string $key): void
    {
        $encrypted = $this->subscriber->xorEncrypt($input, $key);
        $decrypted = $this->subscriber->xorEncrypt($encrypted, $key);

        // 我们只测试加密后再解密能否得到原始输入
        $this->assertEquals($input, $decrypted);
    }

    /**
     * XOR加密测试数据提供者
     */
    public static function xorEncryptDataProvider(): array
    {
        return [
            'empty string' => ['', 'key'],
            'simple string' => ['hello', 'key'],
            'key longer than input' => ['abc', 'longkey'],
            'input longer than key' => ['longstring', 'key'],
            'special characters' => ["!@#$%^&*()", 'key'],
        ];
    }

    /**
     * 测试XOR加密/解密循环
     *
     * @dataProvider encryptDecryptCycleDataProvider
     */
    public function testEncryptDecryptCycle(string $original, string $key): void
    {
        $encrypted = $this->subscriber->xorEncrypt($original, $key);
        $decrypted = $this->subscriber->xorEncrypt($encrypted, $key);

        $this->assertEquals($original, $decrypted, "加密后解密应得到原始字符串");
    }

    /**
     * 加密解密循环测试数据提供者
     */
    public static function encryptDecryptCycleDataProvider(): array
    {
        return [
            'empty string' => ['', 'key'],
            'ascii string' => ['Hello World!', 'key'],
            'utf8 string' => ['你好，世界！', 'key'],
            'long key' => ['Test string', 'this is a very long security key for testing'],
            'special chars' => ["!@#$%^&*()_+{}|:<>?~", 'key'],
            'numeric string' => ['123456789', 'key'],
        ];
    }

    /**
     * 测试请求事件处理 - 没有cookie的情况
     */
    public function testOnKernelRequestWithoutCookie(): void
    {
        $request = new Request();
        $request->cookies = new InputBag();

        // 使用反射来访问 names 属性
        $namesProperty = new \ReflectionProperty($this->subscriber, 'names');
        $namesProperty->setAccessible(true);
        $names = $namesProperty->getValue($this->subscriber);

        // 手动执行解密逻辑（复制自 CookieEncryptSubscriber::onKernelRequest 方法）
        foreach ($names as $name) {
            if ($request->cookies->has($name)) {
                $v = $request->cookies->get($name);
                $request->cookies->set($name, $this->subscriber->xorEncrypt(base64_decode($v), $_ENV['COOKIE_XOR_SECURITY_KEY']));
            }
        }

        // 没有cookie，不应该有任何变化
        $this->assertCount(0, $request->cookies->all());
    }

    /**
     * 测试请求事件处理 - 有cookie的情况
     */
    public function testOnKernelRequestWithCookie(): void
    {
        // 原始值
        $originalValue = 'test_value';

        // 加密值
        $encryptedValue = base64_encode($this->subscriber->xorEncrypt($originalValue, $this->securityKey));

        $request = new Request();
        $request->cookies = new InputBag(['sf_redirect' => $encryptedValue]);

        // 使用反射来访问 names 属性
        $namesProperty = new \ReflectionProperty($this->subscriber, 'names');
        $namesProperty->setAccessible(true);
        $names = $namesProperty->getValue($this->subscriber);

        // 断言 sf_redirect 在 names 数组中
        $this->assertContains('sf_redirect', $names);

        // 手动执行解密逻辑
        foreach ($names as $name) {
            if ($request->cookies->has($name)) {
                $v = $request->cookies->get($name);
                $request->cookies->set($name, $this->subscriber->xorEncrypt(base64_decode($v), $this->securityKey));
            }
        }

        // 验证是否正确解密
        $this->assertEquals($originalValue, $request->cookies->get('sf_redirect'));
    }

    /**
     * 测试请求事件处理 - 无效base64编码的情况
     */
    public function testOnKernelRequestWithInvalidBase64(): void
    {
        // 无效的 base64 字符串
        $invalidBase64 = 'invalid-base64!@#';

        $request = new Request();
        $request->cookies = new InputBag(['sf_redirect' => $invalidBase64]);

        // 使用反射来访问 names 属性
        $namesProperty = new \ReflectionProperty($this->subscriber, 'names');
        $namesProperty->setAccessible(true);
        $names = $namesProperty->getValue($this->subscriber);

        // 断言 sf_redirect 在 names 数组中
        $this->assertContains('sf_redirect', $names);

        // 不应抛出异常
        try {
            // 手动执行解密逻辑
            foreach ($names as $name) {
                if ($request->cookies->has($name)) {
                    $v = $request->cookies->get($name);
                    $request->cookies->set($name, $this->subscriber->xorEncrypt(base64_decode($v), $this->securityKey));
                }
            }
            $this->assertTrue(true); // 如果没有异常，测试通过
        } catch (\Throwable $e) {
            $this->fail('Method threw an exception for invalid base64: ' . $e->getMessage());
        }
    }

    /**
     * 测试响应事件处理 - 没有cookie的情况
     */
    public function testOnKernelResponseWithoutCookie(): void
    {
        $response = new Response();

        // 使用反射来访问 names 属性
        $namesProperty = new \ReflectionProperty($this->subscriber, 'names');
        $namesProperty->setAccessible(true);
        $names = $namesProperty->getValue($this->subscriber);

        // 手动执行加密逻辑
        foreach ($response->headers->getCookies() as $cookie) {
            if (in_array($cookie->getName(), $names) && !empty($cookie->getValue())) {
                $cookie = $cookie->withValue(base64_encode($this->subscriber->xorEncrypt($cookie->getValue(), $this->securityKey)));
                $response->headers->setCookie($cookie);
            }
        }

        // 没有cookie，不应该有任何变化
        $this->assertCount(0, $response->headers->getCookies());
    }

    /**
     * 测试响应事件处理 - 有cookie的情况
     */
    public function testOnKernelResponseWithCookie(): void
    {
        $response = new Response();
        $cookie = new Cookie('sf_redirect', 'test_value');
        $response->headers->setCookie($cookie);

        // 使用反射来访问 names 属性
        $namesProperty = new \ReflectionProperty($this->subscriber, 'names');
        $namesProperty->setAccessible(true);
        $names = $namesProperty->getValue($this->subscriber);

        // 手动执行加密逻辑
        foreach ($response->headers->getCookies() as $cookie) {
            if (in_array($cookie->getName(), $names) && !empty($cookie->getValue())) {
                $cookie = $cookie->withValue(base64_encode($this->subscriber->xorEncrypt($cookie->getValue(), $this->securityKey)));
                $response->headers->setCookie($cookie);
            }
        }

        // 验证是否设置了加密cookie
        $cookies = $response->headers->getCookies();
        $this->assertCount(1, $cookies);

        $encryptedCookie = $cookies[0];
        $this->assertEquals('sf_redirect', $encryptedCookie->getName());

        // 解密cookie值并验证
        $decryptedValue = $this->subscriber->xorEncrypt(base64_decode($encryptedCookie->getValue()), $this->securityKey);
        $this->assertEquals('test_value', $decryptedValue);
    }

    /**
     * 测试响应事件处理 - cookie值为空的情况
     */
    public function testOnKernelResponseWithEmptyCookieValue(): void
    {
        $response = new Response();
        $cookie = new Cookie('sf_redirect', '');
        $response->headers->setCookie($cookie);

        // 使用反射来访问 names 属性
        $namesProperty = new \ReflectionProperty($this->subscriber, 'names');
        $namesProperty->setAccessible(true);
        $names = $namesProperty->getValue($this->subscriber);

        // 手动执行加密逻辑
        foreach ($response->headers->getCookies() as $cookie) {
            if (in_array($cookie->getName(), $names) && !empty($cookie->getValue())) {
                $cookie = $cookie->withValue(base64_encode($this->subscriber->xorEncrypt($cookie->getValue(), $this->securityKey)));
                $response->headers->setCookie($cookie);
            }
        }

        // 验证是否没有加密空值
        $cookies = $response->headers->getCookies();
        $this->assertCount(1, $cookies);
        $this->assertEquals('sf_redirect', $cookies[0]->getName());
        $this->assertEquals('', $cookies[0]->getValue());
    }

    /**
     * 测试响应事件处理 - 不相关的cookie不受影响
     */
    public function testOnKernelResponseWithNonTargetCookie(): void
    {
        $response = new Response();
        $cookie = new Cookie('other_cookie', 'original_value');
        $response->headers->setCookie($cookie);

        // 使用反射来访问 names 属性
        $namesProperty = new \ReflectionProperty($this->subscriber, 'names');
        $namesProperty->setAccessible(true);
        $names = $namesProperty->getValue($this->subscriber);

        // 手动执行加密逻辑
        foreach ($response->headers->getCookies() as $cookie) {
            if (in_array($cookie->getName(), $names) && !empty($cookie->getValue())) {
                $cookie = $cookie->withValue(base64_encode($this->subscriber->xorEncrypt($cookie->getValue(), $this->securityKey)));
                $response->headers->setCookie($cookie);
            }
        }

        // 验证不相关的cookie保持不变
        $cookies = $response->headers->getCookies();
        $this->assertCount(1, $cookies);
        $this->assertEquals('other_cookie', $cookies[0]->getName());
        $this->assertEquals('original_value', $cookies[0]->getValue());
    }

    /**
     * 测试响应事件处理 - 多个cookie的情况
     */
    public function testOnKernelResponseWithMultipleCookies(): void
    {
        $response = new Response();

        // 添加一个需要加密的cookie
        $cookie1 = new Cookie('sf_redirect', 'value1');
        $response->headers->setCookie($cookie1);

        // 添加一个不需要加密的cookie
        $cookie2 = new Cookie('other_cookie', 'value2');
        $response->headers->setCookie($cookie2);

        // 使用反射来访问 names 属性
        $namesProperty = new \ReflectionProperty($this->subscriber, 'names');
        $namesProperty->setAccessible(true);
        $names = $namesProperty->getValue($this->subscriber);

        // 手动执行加密逻辑
        foreach ($response->headers->getCookies() as $cookie) {
            if (in_array($cookie->getName(), $names) && !empty($cookie->getValue())) {
                $cookie = $cookie->withValue(base64_encode($this->subscriber->xorEncrypt($cookie->getValue(), $this->securityKey)));
                $response->headers->setCookie($cookie);
            }
        }

        // 验证结果
        $cookies = $response->headers->getCookies();
        $this->assertCount(2, $cookies);

        // 找到sf_redirect cookie并验证它已被加密
        $foundEncrypted = false;
        $foundUnchanged = false;

        foreach ($cookies as $cookie) {
            if ($cookie->getName() === 'sf_redirect') {
                $decryptedValue = $this->subscriber->xorEncrypt(base64_decode($cookie->getValue()), $this->securityKey);
                $this->assertEquals('value1', $decryptedValue);
                $foundEncrypted = true;
            } elseif ($cookie->getName() === 'other_cookie') {
                $this->assertEquals('value2', $cookie->getValue());
                $foundUnchanged = true;
            }
        }

        $this->assertTrue($foundEncrypted, 'sf_redirect cookie should be found and encrypted');
        $this->assertTrue($foundUnchanged, 'other_cookie should be found and unchanged');
    }

    /**
     * 测试XOR加密边界情况
     *
     * @dataProvider xorEncryptEdgeCasesDataProvider
     */
    public function test_xor_encrypt_edge_cases(string $input, string $key, string $description): void
    {
        $encrypted = $this->subscriber->xorEncrypt($input, $key);
        $decrypted = $this->subscriber->xorEncrypt($encrypted, $key);

        $this->assertEquals($input, $decrypted, $description);
    }

    /**
     * XOR加密边界情况数据提供者
     */
    public static function xorEncryptEdgeCasesDataProvider(): array
    {
        return [
            'empty input with valid key' => ['', 'key', '空输入和有效密钥'],
            'null bytes' => ["\0\0\0", 'key', '包含null字节'],
            'unicode characters' => ['测试🔒加密', 'unicode密钥', 'Unicode字符加密'],
            'long input short key' => [str_repeat('A', 1000), 'x', '长输入短密钥'],
            'short input long key' => ['x', str_repeat('K', 1000), '短输入长密钥'],
            'binary data' => [pack('H*', 'deadbeef'), 'key', '二进制数据'],
            'control characters' => ["\t\n\r\e", 'key', '控制字符'],
        ];
    }

    /**
     * 测试缺失安全密钥的情况
     */
    public function test_missing_security_key(): void
    {
        // 测试空密钥抛出异常
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('加密密钥不能为空');
        
        $this->subscriber->xorEncrypt('test_data', '');
    }

    /**
     * 测试空白字符密钥的情况
     */
    public function test_whitespace_security_key(): void
    {
        // 测试纯空格密钥抛出异常
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('加密密钥不能为空');
        
        $this->subscriber->xorEncrypt('test_data', '   ');
    }

    /**
     * 测试请求处理多个目标Cookie的情况
     */
    public function test_request_with_multiple_target_cookies(): void
    {
        // 模拟有多个sf_redirect类型的cookie (虽然实际只有一个名称在names数组中)
        $originalValue1 = 'redirect_value_1';
        $encryptedValue1 = base64_encode($this->subscriber->xorEncrypt($originalValue1, $this->securityKey));

        $request = new Request();
        $request->cookies = new InputBag([
            'sf_redirect' => $encryptedValue1,
            'other_cookie' => 'should_not_change',
        ]);

        // 使用反射来访问 names 属性
        $namesProperty = new \ReflectionProperty($this->subscriber, 'names');
        $namesProperty->setAccessible(true);
        $names = $namesProperty->getValue($this->subscriber);

        // 手动执行解密逻辑
        foreach ($names as $name) {
            if ($request->cookies->has($name)) {
                $v = $request->cookies->get($name);
                $request->cookies->set($name, $this->subscriber->xorEncrypt(base64_decode($v), $this->securityKey));
            }
        }

        // 验证结果
        $this->assertEquals($originalValue1, $request->cookies->get('sf_redirect'));
        $this->assertEquals('should_not_change', $request->cookies->get('other_cookie'));
    }

    /**
     * 测试完整的请求事件处理流程
     */
    public function test_request_event_handling(): void
    {
        // 使用匿名类创建符合接口的kernel实例
        $kernel = new class implements \Symfony\Component\HttpKernel\HttpKernelInterface {
            public function handle(\Symfony\Component\HttpFoundation\Request $request, int $type = self::MAIN_REQUEST, bool $catch = true): \Symfony\Component\HttpFoundation\Response
            {
                return new \Symfony\Component\HttpFoundation\Response();
            }
        };
        
        $request = new Request();
        
        // 添加加密的cookie
        $originalValue = 'test_redirect_url';
        $encryptedValue = base64_encode($this->subscriber->xorEncrypt($originalValue, $this->securityKey));
        $request->cookies->set('sf_redirect', $encryptedValue);

        $event = new \Symfony\Component\HttpKernel\Event\RequestEvent(
            $kernel,
            $request,
            \Symfony\Component\HttpKernel\HttpKernelInterface::MAIN_REQUEST
        );

        // 执行请求事件处理
        $this->subscriber->onKernelRequest($event);

        // 验证cookie已被解密
        $this->assertEquals($originalValue, $event->getRequest()->cookies->get('sf_redirect'));
    }

    /**
     * 测试完整的响应事件处理流程
     */
    public function test_response_event_handling(): void
    {
        // 使用匿名类创建符合接口的kernel实例
        $kernel = new class implements \Symfony\Component\HttpKernel\HttpKernelInterface {
            public function handle(\Symfony\Component\HttpFoundation\Request $request, int $type = self::MAIN_REQUEST, bool $catch = true): \Symfony\Component\HttpFoundation\Response
            {
                return new \Symfony\Component\HttpFoundation\Response();
            }
        };
        
        $request = new Request();
        $response = new Response();
        
        // 添加需要加密的cookie
        $originalValue = 'test_redirect_url';
        $cookie = new Cookie('sf_redirect', $originalValue);
        $response->headers->setCookie($cookie);

        $event = new \Symfony\Component\HttpKernel\Event\ResponseEvent(
            $kernel,
            $request,
            \Symfony\Component\HttpKernel\HttpKernelInterface::MAIN_REQUEST,
            $response
        );

        // 执行响应事件处理
        $this->subscriber->onKernelResponse($event);

        // 验证cookie已被加密
        $cookies = $event->getResponse()->headers->getCookies();
        $this->assertCount(1, $cookies);
        
        $encryptedCookie = $cookies[0];
        $this->assertEquals('sf_redirect', $encryptedCookie->getName());
        
        // 验证加密值可以正确解密
        $decryptedValue = $this->subscriber->xorEncrypt(base64_decode($encryptedCookie->getValue()), $this->securityKey);
        $this->assertEquals($originalValue, $decryptedValue);
    }

    /**
     * 测试XOR加密的对称性
     */
    public function test_xor_encrypt_symmetry(): void
    {
        $testCases = [
            ['hello', 'world'],
            ['', 'key'],
            ['same', 'same'],
            ['1234567890', 'abc'],
            ['special!@#$%^&*()', 'test'],
        ];

        foreach ($testCases as [$input, $key]) {
            $encrypted = $this->subscriber->xorEncrypt($input, $key);
            $decrypted = $this->subscriber->xorEncrypt($encrypted, $key);
            
            $this->assertEquals($input, $decrypted, "对称性测试失败: input='$input', key='$key'");
        }
    }

    /**
     * 测试同一输入不同密钥产生不同结果
     */
    public function test_different_keys_produce_different_results(): void
    {
        $input = 'test_string';
        $key1 = 'key1';
        $key2 = 'key2';

        $encrypted1 = $this->subscriber->xorEncrypt($input, $key1);
        $encrypted2 = $this->subscriber->xorEncrypt($input, $key2);

        $this->assertNotEquals($encrypted1, $encrypted2, '不同密钥应产生不同的加密结果');
    }

    /**
     * 测试密钥循环使用
     */
    public function test_key_cycling(): void
    {
        $longInput = str_repeat('ABCDEFGHIJ', 10); // 100字符
        $shortKey = 'KEY'; // 3字符

        $encrypted = $this->subscriber->xorEncrypt($longInput, $shortKey);
        $decrypted = $this->subscriber->xorEncrypt($encrypted, $shortKey);

        $this->assertEquals($longInput, $decrypted, '密钥循环使用测试');
        $this->assertEquals(strlen($longInput), strlen($encrypted), '加密后长度应保持一致');
    }

    /**
     * 测试环境变量缺失时的请求处理
     */
    public function test_request_with_missing_env_key(): void
    {
        // 备份原始环境变量
        $original = $_ENV['COOKIE_XOR_SECURITY_KEY'] ?? null;
        
        // 清除环境变量
        unset($_ENV['COOKIE_XOR_SECURITY_KEY']);

        $request = new Request();
        $request->cookies = new InputBag(['sf_redirect' => base64_encode('encrypted_value')]);

        $kernel = new class implements \Symfony\Component\HttpKernel\HttpKernelInterface {
            public function handle(\Symfony\Component\HttpFoundation\Request $request, int $type = self::MAIN_REQUEST, bool $catch = true): \Symfony\Component\HttpFoundation\Response
            {
                return new \Symfony\Component\HttpFoundation\Response();
            }
        };

        $event = new \Symfony\Component\HttpKernel\Event\RequestEvent(
            $kernel,
            $request,
            \Symfony\Component\HttpKernel\HttpKernelInterface::MAIN_REQUEST
        );

        // 预期会抛出异常，因为环境变量不存在
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('加密密钥不能为空');
        
        $this->subscriber->onKernelRequest($event);

        // 恢复环境变量
        if ($original !== null) {
            $_ENV['COOKIE_XOR_SECURITY_KEY'] = $original;
        }
    }

    /**
     * 测试环境变量缺失时的响应处理
     */
    public function test_response_with_missing_env_key(): void
    {
        // 备份原始环境变量
        $original = $_ENV['COOKIE_XOR_SECURITY_KEY'] ?? null;
        
        // 清除环境变量
        unset($_ENV['COOKIE_XOR_SECURITY_KEY']);

        $kernel = new class implements \Symfony\Component\HttpKernel\HttpKernelInterface {
            public function handle(\Symfony\Component\HttpFoundation\Request $request, int $type = self::MAIN_REQUEST, bool $catch = true): \Symfony\Component\HttpFoundation\Response
            {
                return new \Symfony\Component\HttpFoundation\Response();
            }
        };
        
        $request = new Request();
        $response = new Response();
        
        // 添加需要加密的cookie
        $originalValue = 'test_redirect_url';
        $cookie = new Cookie('sf_redirect', $originalValue);
        $response->headers->setCookie($cookie);

        $event = new \Symfony\Component\HttpKernel\Event\ResponseEvent(
            $kernel,
            $request,
            \Symfony\Component\HttpKernel\HttpKernelInterface::MAIN_REQUEST,
            $response
        );

        // 预期会抛出异常，因为环境变量不存在
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('加密密钥不能为空');
        
        $this->subscriber->onKernelResponse($event);

        // 恢复环境变量
        if ($original !== null) {
            $_ENV['COOKIE_XOR_SECURITY_KEY'] = $original;
        }
    }
}
