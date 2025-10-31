<?php

namespace Tourze\CookieEncryptBundle\EventSubscriber;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Tourze\CookieEncryptBundle\Exception\InvalidEncryptionKeyException;

/**
 * 一些特殊的部署环境，例如Azure，他们的waf特别严格，cookie内容需要做一层加密以防止被识别
 */
class CookieEncryptEventSubscriber implements EventSubscriberInterface
{
    /** @var array<string> */
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
            if (!is_string($v)) {
                continue;
            }
            $key = $_ENV['COOKIE_XOR_SECURITY_KEY'] ?? '';
            $decoded = base64_decode($v, true);
            if (false !== $decoded) {
                $event->getRequest()->cookies->set($name, $this->xorEncrypt($decoded, $key));
            }
        }
    }

    public function xorEncrypt(string $string, string $key): string
    {
        if ('' === trim($key)) {
            throw new InvalidEncryptionKeyException('Encryption key cannot be empty');
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
            if (in_array($cookie->getName(), $this->names, true) && '' !== $cookie->getValue() && null !== $cookie->getValue()) {
                $key = $_ENV['COOKIE_XOR_SECURITY_KEY'] ?? '';
                $cookie = $cookie->withValue(base64_encode($this->xorEncrypt($cookie->getValue(), $key)));
                $event->getResponse()->headers->setCookie($cookie);
            }
        }
    }
}
