<?php
/**
 * NetSentinel - Automatic Version Tracker
 * 
 * Detects changes to any PHP file in the project and automatically
 * bumps the patch version (e.g. 1.0.0 -> 1.0.1).
 * 
 * Version state is persisted in .version.json so it survives across requests.
 */

function get_version(): string {
    // Static cache so multiple calls per request are free
    static $cached = null;
    if ($cached !== null) {
        return $cached;
    }

    $base_dir     = dirname(__DIR__);
    $version_file = __DIR__ . '/.version.json';
    $default      = ['version' => '1.0.0', 'hash' => '', 'last_bumped' => ''];

    // 1. Build a fingerprint from every PHP file's path + mtime
    //    (Using mtime is much faster than hashing file contents)
    $fingerprint = '';
    $newest_mtime = 0;

    try {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($base_dir, RecursiveDirectoryIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if (!$file->isFile() || $file->getExtension() !== 'php') {
                continue;
            }
            $path = $file->getPathname();

            // Skip things we don't want to trigger a bump
            if (strpos($path, '/vendor/') !== false) continue;
            if (strpos($path, '/.version.json') !== false) continue;
            if (strpos($path, '/node_modules/') !== false) continue;

            $mtime = $file->getMTime();
            $fingerprint .= $path . '|' . $mtime . ';';
            if ($mtime > $newest_mtime) {
                $newest_mtime = $mtime;
            }
        }
    } catch (Exception $e) {
        // If we can't scan, just return the last known version
        $cached = $default['version'];
        return $cached;
    }

    $current_hash = md5($fingerprint);

    // 2. Load the stored version state
    $data = $default;
    if (file_exists($version_file) && is_readable($version_file)) {
        $stored = json_decode(file_get_contents($version_file), true);
        if (is_array($stored)) {
            $data = array_merge($default, $stored);
        }
    }

    // 3. If the fingerprint changed, bump the patch version
    if ($data['hash'] !== $current_hash) {
        $parts = explode('.', $data['version']);
        // Ensure we have 3 parts (major.minor.patch)
        while (count($parts) < 3) {
            $parts[] = '0';
        }
        $parts[2] = (string)(((int)$parts[2]) + 1);
        $data['version']       = implode('.', $parts);
        $data['hash']          = $current_hash;
        $data['last_bumped']   = date('Y-m-d H:i:s');
        $data['triggered_by']  = date('Y-m-d H:i:s') . ' (newest file mtime: ' . date('Y-m-d H:i:s', $newest_mtime) . ')';

        // Best-effort write; if the file isn't writable we just keep going
        @file_put_contents($version_file, json_encode($data, JSON_PRETTY_PRINT));
    }

    $cached = $data['version'];
    return $cached;
}

/**
 * Returns a small info array useful for an admin/debug page.
 */
function get_version_info(): array {
    $version_file = __DIR__ . '/.version.json';
    $data = ['version' => '1.0.0', 'hash' => '', 'last_bumped' => 'never', 'triggered_by' => ''];
    if (file_exists($version_file)) {
        $stored = json_decode(file_get_contents($version_file), true);
        if (is_array($stored)) {
            $data = array_merge($data, $stored);
        }
    }
    // Make sure the current version is fresh
    $data['version'] = get_version();
    return $data;
}