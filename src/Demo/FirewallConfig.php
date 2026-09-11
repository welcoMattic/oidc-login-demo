<?php

namespace App\Demo;

/**
 * Helper to extract the raw YAML configuration block for a specific firewall
 * from the security.yaml configuration file.
 *
 * This is used to display the exact firewall configuration on the account page.
 */
final class FirewallConfig
{
    private const SECURITY_YAML_PATH = __DIR__ . '/../../config/packages/security.yaml';
    private const FIREWALL_INDENT = '        '; // 8 spaces
    private const CHILD_INDENT = '            '; // 12 spaces

    /**
     * Extract the YAML block for a specific firewall from security.yaml.
     *
     * The firewall configuration starts at 8 spaces indentation with the firewall name
     * and includes all lines with 12+ spaces until a line with 8 or fewer spaces is found.
     *
     * @return string The YAML block for the firewall, or empty string if not found
     */
    public static function getFirewallYaml(string $firewallName): string
    {
        if (!file_exists(self::SECURITY_YAML_PATH)) {
            return '';
        }

        $content = file_get_contents(self::SECURITY_YAML_PATH);
        $lines = explode("\n", $content);

        $inFirewall = false;
        $firewallLines = [];
        $expectedIndent = self::FIREWALL_INDENT;
        $childIndent = self::CHILD_INDENT;

        foreach ($lines as $line) {
            // Check if this line starts the firewall
            if (str_starts_with($line, $expectedIndent . $firewallName . ':')) {
                $inFirewall = true;
                $firewallLines[] = $line;
                continue;
            }

            if (!$inFirewall) {
                continue;
            }

            // Check if this is the next firewall at the same level or a parent level
            $trimmed = ltrim($line);
            $leadingSpaces = strlen($line) - strlen($trimmed);

            // If line is blank or has 12+ spaces (child of current firewall), include it
            if ($trimmed === '' || $leadingSpaces >= strlen($childIndent)) {
                $firewallLines[] = $line;
                continue;
            }

            // If line has 8 or fewer leading spaces (sibling or parent), we've reached the end
            if ($leadingSpaces <= strlen($expectedIndent)) {
                break;
            }

            // For lines with 9-11 spaces (invalid but possible), include them
            $firewallLines[] = $line;
        }

        // Trim trailing empty lines
        while (!empty($firewallLines) && trim(end($firewallLines)) === '') {
            array_pop($firewallLines);
        }

        return implode("\n", $firewallLines);
    }
}
