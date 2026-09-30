<?php

namespace App\Trace;

use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\Security\Http\SecurityRequestAttributes;

/**
 * Records authorization requests as they are redirected to the OIDC provider.
 *
 * This listener captures the redirect response when it carries the authorization
 * request parameters (response_type=code, client_id, state, nonce) and stores
 * the request details in the session for later use by the FlowRecorder.
 */
#[AsEventListener]
final class AuthorizationRequestRecorder
{
    private const SESSION_KEY_PREFIX = 'oidc_demo.pending.';
    private const MAX_PENDING_ENTRIES = 5;

    public function __invoke(ResponseEvent $event): void
    {
        $request = $event->getRequest();
        $response = $event->getResponse();

        // Only record when there's an existing session
        if (!$request->hasSession() || null === ($session = $request->getSession())) {
            return;
        }

        // Only record RedirectResponse
        if (!$response instanceof RedirectResponse) {
            return;
        }

        $targetUrl = $response->getTargetUrl();
        $query = parse_url($targetUrl, PHP_URL_QUERY);

        // Only process if this looks like an OIDC authorization request
        if (!is_string($query) || !str_contains($query, 'response_type=code')) {
            return;
        }

        // Parse query parameters
        parse_str($query, $params);

        // Must have the essential OIDC authorization params
        if (!isset($params['response_type'], $params['client_id'], $params['state'], $params['nonce'])) {
            return;
        }

        if ($params['response_type'] !== 'code') {
            return;
        }

        // Extract endpoint (URL without query)
        $endpoint = strtok($targetUrl, '?');

        // Preserve parameter order by re-parsing from the original query
        $orderedParams = [];
        if (preg_match_all('/([^=&]+)=([^&]*)/', $query, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) {
                $orderedParams[$match[1]] = urldecode($match[2]);
            }
        }

        // the ID token a re-authentication sends as a hint is a credential: keep its head only
        if (isset($orderedParams['id_token_hint'])) {
            $idTokenHint = $orderedParams['id_token_hint'];
            $orderedParams['id_token_hint'] =
                substr($idTokenHint, 0, 32) . '... (the ID token, ' . strlen($idTokenHint) . ' chars)';
        }

        // Determine the trigger: the start route, the entry point, or a re-authentication, which
        // the firewall starts for a denied attribute it names in a request attribute
        $route = $request->attributes->get('_route', '');
        $reAuthenticationAttribute = $request->attributes->get(SecurityRequestAttributes::RE_AUTHENTICATION_ATTRIBUTE);
        $trigger = match (true) {
            null !== $reAuthenticationAttribute => 're_authentication',
            str_starts_with($route, '_oidc_login_start_') => 'start_route',
            default => 'entry_point',
        };

        // Determine the firewall name
        $firewall = $request->attributes->get('firewallName');
        if (null === $firewall) {
            // Fallback: first path segment
            $pathInfo = $request->getPathInfo();
            $firewall = trim(explode('/', trim($pathInfo, '/'))[0] ?? '', '/');
            if ($firewall === '') {
                $firewall = 'unknown';
            }
        }

        // Create pending entry with UTC timestamp
        $startedAt = new \DateTimeImmutable('now', new \DateTimeZone('UTC'))->format('Y-m-d\TH:i:s.u\Z');

        // Create pending entry
        $entry = [
            'endpoint' => $endpoint,
            'params' => $orderedParams,
            'started_at' => $startedAt,
            'trigger' => $trigger,
            're_authentication_attribute' => is_string($reAuthenticationAttribute) ? $reAuthenticationAttribute : null,
            'requested_path' => $request->getPathInfo(),
            'firewall' => $firewall,
        ];

        // Store in session with state as key
        $sessionKey = self::SESSION_KEY_PREFIX . $params['state'];

        // Get existing pending entries and clean up if needed
        $pendingKeys = [];
        foreach ($session->all() as $key => $value) {
            if (str_starts_with($key, self::SESSION_KEY_PREFIX)) {
                $pendingKeys[] = $key;
            }
        }

        // Remove oldest entries if we're over the limit, based on started_at
        if (count($pendingKeys) >= self::MAX_PENDING_ENTRIES) {
            // Get started_at times for each pending entry
            $entriesWithTimes = [];
            foreach ($pendingKeys as $key) {
                $entryData = $session->get($key);
                if (is_array($entryData) && isset($entryData['started_at'])) {
                    try {
                        $dateTime = new \DateTimeImmutable($entryData['started_at'], new \DateTimeZone('UTC'));
                        $entriesWithTimes[] = ['key' => $key, 'time' => $dateTime->getTimestamp()];
                    } catch (\Exception) {
                        // Invalid timestamp, treat as oldest
                        $entriesWithTimes[] = ['key' => $key, 'time' => 0];
                    }
                } else {
                    $entriesWithTimes[] = ['key' => $key, 'time' => 0];
                }
            }

            // Sort by timestamp ascending (oldest first)
            usort($entriesWithTimes, function ($a, $b) {
                return $a['time'] <=> $b['time'];
            });

            // Remove oldest entries
            $toRemove = array_slice($entriesWithTimes, 0, count($entriesWithTimes) - self::MAX_PENDING_ENTRIES + 1);
            foreach ($toRemove as $oldEntry) {
                $session->remove($oldEntry['key']);
            }
        }

        // Store the new pending entry
        $session->set($sessionKey, $entry);
    }
}
