<?php

// castor.php - Castor 1.x configuration for Symfony OIDC login demo
// See https://castor.jolicode.com

use Castor\Attribute\AsTask;
use function Castor\capture;
use function Castor\context;
use function Castor\exit_code;
use function Castor\io;
use function Castor\run;

#[AsTask(description: 'Install dependencies and generate certificates')]
function install(): void
{
    run('composer install --no-interaction --no-scripts');
    certs();
}

#[AsTask(description: 'Generate TLS certificates for the Identity Provider')]
function certs(): void
{
    run('docker/generate-certs.sh');
}

#[AsTask(description: 'Start the application and containers')]
function start(): void
{
    certs();
    
    // Start Docker containers
    run('docker compose up -d --wait');
    
    // Clear cache
    run('php bin/console cache:clear');
    
    // Start Symfony server (allow failure if already running)
    run('symfony server:start -d --no-tls --port=8001', context: context()->withAllowFailure());
    
    // Verify setup
    verify_setup();
}

#[AsTask(description: 'Stop the application and containers')]
function stop(): void
{
    run('symfony server:stop');
    run('docker compose down');
}

#[AsTask(description: 'Restart the application')]
function restart(): void
{
    stop();
    start();
}

#[AsTask(description: 'Open application URLs in browser')]
function open(): void
{
    \Castor\open('http://localhost:8001/');
    \Castor\open('https://localhost:8443/admin/');
}

#[AsTask(description: 'Verify the application configuration')]
function check(): void
{
    io()->section('Checking container configuration');
    run('php bin/console lint:container');
    
    io()->section('Checking YAML configuration');
    run('php bin/console lint:yaml config');
    
    io()->section('Checking Twig templates');
    run('php bin/console lint:twig templates');
    
    io()->section('Firewalls and routes');
    run('php bin/console debug:firewall');
    run('php bin/console debug:router | grep -E \'_oidc_login_\'');
}

#[AsTask(description: 'Run smoke tests for all scenarios')]
function smoke(): void
{
    $scenarios = [
        'default' => ['--authz', 'code_challenge_method=S256', '--authz', 'client_id=symfony-demo', '--page', 'OidcUser', '--page', 'ROLE_USER', '--page', 'alice'],
        'basic' => ['--page', 'ROLE_USER'],
        'public' => ['--authz', 'client_id=symfony-demo-public', '--authz', 'code_challenge_method=S256', '--page', 'OidcUser'],
        'strict' => ['--authz', 'max_age=60', '--authz', 'prompt=login', '--authz', 'login_hint=alice', '--authz', 'ui_locales=fr', '--login-page', 'Mot de passe', '--page', 'auth_time'],
        'es256' => ['--page', 'ES256'],
        'plain' => ['--authz', 'code_challenge_method=plain', '--page', 'OidcUser'],
        'roles' => ['--page', 'ROLE_ADMIN', '--page', 'ROLE_EDITOR'],
        'email' => ['--page', 'User identifier alice@example.com', '--page', 'OidcUser'],
        'idtoken' => ['--page', 'read from the ID token', '--page', 'OidcUser']
    ];
    
    foreach ($scenarios as $firewall => $expectations) {
        // an array command keeps multi-word expectations ("Mot de passe") as single arguments
        $command = ['bin/smoke.sh', $firewall, ...$expectations];
        io()->writeln("Running smoke test for <info>{$firewall}</info>...");
        
        $exitCode = exit_code($command);
        
        if ($exitCode !== 0) {
            io()->error("Smoke test failed for {$firewall} (exit code: {$exitCode})");
            exit(1);
        }
        
        io()->success("Smoke test passed for {$firewall}");
    }
    
    io()->success('All smoke tests passed!');
}

#[AsTask(description: 'Run PHPUnit tests')]
function test(): void
{
    run('php bin/phpunit');
}

#[AsTask(description: 'Clear caches')]
function cc(): void
{
    run('php bin/console cache:clear');
    run('php bin/console cache:pool:clear cache.app');
}

#[AsTask(description: 'Follow Keycloak logs')]
function logs(): void
{
    run('docker compose logs -f keycloak');
}

#[AsTask(description: 'Clean everything (containers, volumes, certificates, cache)')]
function clean(): void
{
    stop();
    run('docker compose down -v --remove-orphans');
    run('rm -rf docker/certs var/cache var/log');
}

/**
 * Verify that the application is properly set up.
 */
function verify_setup(): void
{
    io()->writeln('Verifying application setup...');
    
    // Check Symfony server
    $response = capture('curl -s -o /dev/null -w "%{http_code}" http://localhost:8001/');
    if (trim($response) !== '200') {
        io()->error('Symfony server not responding on http://localhost:8001/');
        exit(1);
    }
    io()->writeln('  Symfony server: OK');
    
    // Check Keycloak discovery endpoint
    $response = capture('curl -s -o /dev/null -w "%{http_code}" --cacert docker/certs/ca.crt https://localhost:8443/realms/demo/.well-known/openid-configuration');
    if (trim($response) !== '200') {
        io()->error('Keycloak discovery endpoint not responding');
        exit(1);
    }
    io()->writeln('  Keycloak discovery: OK');
    
    // Check clock drift between container and host
    $containerTime = trim(capture('docker compose exec -T keycloak date +%s'));
    $hostTime = trim(capture('date +%s'));
    $drift = abs(intval($containerTime) - intval($hostTime));
    
    if ($drift > 2) {
        io()->warning("Clock drift detected: {$drift} seconds (allowed_time_drift is 0 on most scenarios)");
    } else {
        io()->writeln('  Clock drift: OK');
    }
    
    // Print scenario table
    io()->writeln('');
    io()->writeln('Available scenarios:');
    io()->writeln('  <comment>Firewall</comment>  <comment>Protected URL</comment>               <comment>Credentials</comment>');
    io()->writeln('  ----------  ----------------               ------------');
    
    $scenarios = [
        'default' => '/default',
        'basic' => '/basic',
        'public' => '/public',
        'strict' => '/strict',
        'es256' => '/es256',
        'plain' => '/plain',
        'roles' => '/roles',
        'email' => '/email',
        'idtoken' => '/idtoken'
    ];
    
    foreach ($scenarios as $name => $path) {
        io()->writeln(sprintf('  %-9s  http://localhost:8001%s/account  alice/alice, bob/bob', $name, $path));
    }
    
    io()->writeln('');
    io()->writeln('Keycloak admin: https://localhost:8443/admin/ (admin/admin)');
    io()->success('Application is ready!');
}