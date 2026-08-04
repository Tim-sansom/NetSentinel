<?php
declare(strict_types=1);
// NetSentinel B0: persistent finding state (events -> alerts model)

function finding_category(string $key): string
{
    $cat = explode(':', $key, 2)[0];
    return in_array($cat, ['port','firewall','system','latency'], true) ? $cat : 'system';
}

/**
 * Upsert observed findings; auto-resolve open findings not re-observed.
 * NOTE: This function expects to be called within an active PDO transaction 
 * (started by submit.php).
 * @param array $observed list of ['finding_key'=>string,'severity'=>string,'detail'=>array]
 */
function record_findings(PDO $pdo, int $deviceId, array $observed, int $staleMinutes = 15): void
{
    $validSev = ['low','medium','high','critical'];

    // Bound values twice (sev2/det2) = version-proof across MySQL 8.x
    $upsert = $pdo->prepare("
        INSERT INTO finding (device_id, category, finding_key, severity, detail_json, first_seen, last_seen)
        VALUES (:did, :cat, :key, :sev, :det, NOW(), NOW())
        ON DUPLICATE KEY UPDATE
            last_seen   = NOW(),
            occurrences = occurrences + 1,
            severity    = :sev2,
            detail_json = :det2,
            status      = 'open',
            resolved_at = NULL
    ");

    $resolve = $pdo->prepare("
        UPDATE finding
           SET status = 'resolved', resolved_at = NOW()
         WHERE device_id = :did
           AND status = 'open'
           AND last_seen < :cutoff
    ");

    // REMOVED: $pdo->beginTransaction(); 
    // We are already inside the transaction started by submit.php
    
    foreach ($observed as $f) {
        $key = substr((string)$f['finding_key'], 0, 80);
        $sev = in_array($f['severity'], $validSev, true) ? $f['severity'] : 'low';
        $det = json_encode($f['detail'] ?? [], JSON_UNESCAPED_SLASHES);
        $upsert->execute([
            ':did' => $deviceId, ':cat' => finding_category($key),
            ':key' => $key,      ':sev' => $sev,  ':det' => $det,
            ':sev2'=> $sev,      ':det2'=> $det,
        ]);
    }
    
    // Anything open but not re-observed within the window flips to resolved
    $resolve->execute([
        ':did'    => $deviceId,
        ':cutoff' => date('Y-m-d H:i:s', time() - ($staleMinutes * 60)),
    ]);
    
    // REMOVED: $pdo->commit(); and try/catch/rollBack
    // submit.php will handle the final commit for the entire payload.
}