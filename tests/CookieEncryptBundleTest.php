<?php

declare(strict_types=1);

namespace CookieEncryptBundle\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Tourze\CookieEncryptBundle\CookieEncryptBundle;
use Tourze\PHPUnitSymfonyKernelTest\AbstractBundleTestCase;

/**
 * @internal
 */
#[CoversClass(CookieEncryptBundle::class)]
#[RunTestsInSeparateProcesses]
final class CookieEncryptBundleTest extends AbstractBundleTestCase
{
}
