<?php

namespace App\Trace;

use Psr\Clock\ClockInterface;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpKernel\Event\ControllerEvent;

/**
 * Records the renewals of the access token made with the refresh token grant.
 *
 * With "refresh_access_token" enabled, a firewall listener renews the access token before the
 * controller runs, on the first request made less than "leeway" seconds before it expires.
 * This listener runs right after the firewall, finds the refresh_token grant among the calls
 * made to the provider during the request, and keeps the last renewals in the session, so
 * that the account page rendered by that very request can show them.
 */
#[AsEventListener]
final class TokenRefreshRecorder
{
    private const SESSION_KEY_PREFIX = 'oidc_demo.renewals.';
    private const MAX_ENTRIES = 5;

    public function __construct(
        private readonly OidcHttpRecorder $httpRecorder,
        private readonly Security $security,
        private readonly ClockInterface $clock,
    ) {}

    public function __invoke(ControllerEvent $event): void
    {
        $request = $event->getRequest();
        if (!$event->isMainRequest() || !$request->hasSession()) {
            return;
        }

        $firewall = $this->security->getFirewallConfig($request)?->getName();
        if (null === $firewall) {
            return;
        }

        $renewals = [];
        foreach ($this->httpRecorder->getExchanges() as $exchange) {
            $body = self::formBody($exchange['options']['body'] ?? null);

            if ('POST' !== $exchange['method'] || !in_array($body['grant_type'] ?? null, ['refresh_token'], true)) {
                continue;
            }

            try {
                $status = $exchange['response']->getStatusCode();
                $json = self::jsonObject($exchange['response']->getContent(false));
            } catch (\Throwable) {
                continue;
            }

            $renewals[] = [
                'at' => $this->clock->now()->getTimestamp(),
                'status' => $status,
                'error' => is_string($json['error'] ?? null) ? $json['error'] : null,
                'expires_in' => is_int($json['expires_in'] ?? null) ? $json['expires_in'] : null,
                'refresh_token_rotated' => isset($json['refresh_token']),
                'id_token_reissued' => isset($json['id_token']),
            ];
        }

        if (!$renewals) {
            return;
        }

        $session = $request->getSession();
        $history = self::arrayOrEmpty($session->get(self::SESSION_KEY_PREFIX . $firewall));
        $session->set(self::SESSION_KEY_PREFIX . $firewall, array_slice(
            [...$history, ...$renewals],
            -self::MAX_ENTRIES,
        ));
    }

    /**
     * @return array<array-key, mixed>
     */
    private static function formBody(mixed $body): array
    {
        if (is_string($body)) {
            $fields = [];
            parse_str($body, $fields);

            return $fields;
        }

        return self::arrayOrEmpty($body);
    }

    /**
     * @return array<array-key, mixed>
     */
    private static function jsonObject(string $content): array
    {
        try {
            return self::arrayOrEmpty(json_decode($content, true, 512, JSON_THROW_ON_ERROR));
        } catch (\JsonException) {
            return [];
        }
    }

    /**
     * @return array<array-key, mixed>
     */
    private static function arrayOrEmpty(mixed $value): array
    {
        return is_array($value) ? $value : [];
    }
}
