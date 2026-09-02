<?php
/**
 * NetSentinel Findings Handler
 * Upsert's observed findings and auto-resolves open findings
 * not re-observed in the latest check run.
 */
declare(strict_types=1);

/**
 * Determines the category of a finding based on its key prefix.
 */
function finding_category(string $key): string {
    $cat = explode(':', $key, 2)[0];
    return in_array($cat, ['port','firewall','system','latency'], true) ? $cat : 'system';
}

/**
 * Upsert observed findings; auto-resolve open findings not re-observed.
 * 
 * ARCHITECTURE NOTE: This function expects to be called within an active PDO transaction 
 * (started by submit.php). This ensures that if the agent payload fails halfway through, 
 * the finding state doesn't get corrupted.
 * 
 * @param PDO $pdo Database connection
 * @param int $deviceId The internal DB device ID
 * @param array $observed list of ['finding_key'=>string,'severity'=>string,'detail'=>array]
 * @param int $staleMinutes Time window before an unobserved finding is auto-resolved
 */
function record_findings(PDO $pdo, int $deviceId, array $observed, int $staleMinutes = 15): void {
    $validSev = ['low','medium','high','critical'];
    
    // 1. UPSERT Statement: Insert new findings or update existing ones if seen again.
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
    
    // 2. AUTO-RESOLVE Statement: NFR1 (Lightweight) Compliance
    // Instead of keeping thousands of historical "open" alerts, we automatically flip them 
    // to "resolved" if the agent hasn't reported them in the last X minutes.
    $resolve = $pdo->prepare("
        UPDATE finding
        SET status = 'resolved', resolved_at = NOW()
        WHERE device_id = :did
        AND status = 'open'
        AND last_seen < :cutoff
    ");
    
    // Process the observed findings from the current agent run
    foreach ($observed as $f) {
        $key = substr((string)$f['finding_key'], 0, 80); // Prevent DB key overflow
        $sev = in_array($f['severity'], $validSev, true) ? $f['severity'] : 'low';
        $det = json_encode($f['detail'] ?? [], JSON_UNESCAPED_SLASHES);
        
        $upsert->execute([
            ':did' => $deviceId, ':cat' => finding_category($key),
            ':key' => $key,      ':sev' => $sev,  ':det' => $det,
            ':sev2'=> $sev,      ':det2'=> $det,
        ]);
    }
    
    // Auto-resolve stale findings
    $resolve->execute([
        ':did'    => $deviceId,
        ':cutoff' => date('Y-m-d H:i:s', time() - ($staleMinutes * 60)),
    ]);
}