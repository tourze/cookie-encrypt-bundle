<?php

namespace Tourze\CookieEncryptBundle\EventSubscriber;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * 一些特殊的部署环境，例如Azure，他们的waf特别严格，cookie内容需要做一层加密以防止被识别
 */
class CookieEncryptSubscriber implements EventSubscriberInterface
{
    protected array $names = [
        'sf_redirect',
    ];

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => 'onKernelRequest',
            KernelEvents::RESPONSE => ['onKernelResponse', -200],
        ];
    }

    /**
     * 请求进入后，先解密
     */
    public function onKernelRequest(RequestEvent $event): void
    {
        foreach ($this->names as $name) {
            if (!$event->getRequest()->cookies->has($name)) {
                continue;
            }
            $v = $event->getRequest()->cookies->get($name);
            $key = $_ENV['COOKIE_XOR_SECURITY_KEY'] ?? '';
            $event->getRequest()->cookies->set($name, $this->xorEncrypt(base64_decode($v), $key));
        }
    }

    public function xorEncrypt(string $string, string $key): string
    {
        if (empty(trim($key))) {
            throw new \InvalidArgumentException('加密密钥不能为空');
        }
        
        $result = '';
        for ($i = 0; $i < strlen($string); ++$i) {
            $result .= $string[$i] ^ $key[$i % strlen($key)];
        }

        return $result;
    }

    /**
     * 请求开始响应时，加密数据
     */
    public function onKernelResponse(ResponseEvent $event): void
    {
        // 检查所有要返回的Cookie
        foreach ($event->getResponse()->headers->getCookies() as $cookie) {
            if (in_array($cookie->getName(), $this->names) && !empty($cookie->getValue())) {
                $key = $_ENV['COOKIE_XOR_SECURITY_KEY'] ?? '';
                $cookie = $cookie->withValue(base64_encode($this->xorEncrypt($cookie->getValue(), $key)));
                $event->getResponse()->headers->setCookie($cookie);
            }
        }
    }
}
