<?php
/**
 * NetSentinel Policy Management Page
 * Admin-only interface for Device Groups, endpoint assignments, 
 * and Baseline Security Rules.
 */
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/audit.php';

if (session_status() === PHP_SESSION_NONE) { 
    session_start(); 
}
requireLogin();

// SECURITY: Strict case-insensitive admin check to prevent authorization bypass (Fixes D-023).
if (!isset($_SESSION['role']) || strtolower($_SESSION['role']) !== 'admin') {
    http_response_code(403);
    die('<div class="container mt-4"><div class="alert alert-danger">Access denied. Admin privileges required.</div></div>');
}

$message = '';
$message_type = 'success';
$active_tab = $_GET['tab'] ?? 'groups';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // SECURITY: Verify CSRF token on all state-changing POST requests (SR4).
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $message = 'Invalid security token. Please refresh and try again.';
        $message_type = 'danger';
    }
    // 1. Create Group
    elseif (isset($_POST['create_group'])) {
        $group_name = trim($_POST['group_name']);
        $description = trim($_POST['description']);
        if (!empty($group_name)) {
            try {
                $stmt = $pdo->prepare("INSERT INTO device_group (name, description) VALUES (?, ?)");
                $stmt->execute([$group_name, $description]);
                log_audit($pdo, $_SESSION['user_id'], 'GROUP_CREATED', 'device_group', $pdo->lastInsertId());
                $message = 'Device group created successfully.';
            } catch (PDOException $e) {
                $message = 'Error creating group: ' . htmlspecialchars($e->getMessage());
                $message_type = 'danger';
            }
        }
    }
    // 2. Delete Group
    elseif (isset($_POST['delete_group'])) {
        $group_id = (int) $_POST['group_id'];
        try {
            $pdo->prepare("DELETE FROM device_group_map WHERE group_id = ?")->execute([$group_id]);
            $pdo->prepare("DELETE FROM device_group WHERE group_id = ?")->execute([$group_id]);
            log_audit($pdo, $_SESSION['user_id'], 'GROUP_DELETED', 'device_group', $group_id);
            $message = 'Device group deleted successfully.';
        } catch (PDOException $e) {
            $message = 'Error deleting group.';
            $message_type = 'danger';
        }
    }
    // 3. Assign Devices to Group
    elseif (isset($_POST['assign_devices'])) {
        $group_id = (int) $_POST['group_id'];
        $device_ids = $_POST['device_ids'] ?? [];
        try {
            // DATA INTEGRITY: Clear existing assignments first to prevent duplicate mapping errors.
            $pdo->prepare("DELETE FROM device_group_map WHERE group_id = ?")->execute([$group_id]);
            
            if (!empty($device_ids)) {
                $stmt = $pdo->prepare("INSERT INTO device_group_map (device_id, group_id) VALUES (?, ?)");
                foreach ($device_ids as $device_id) {
                    $stmt->execute([(int)$device_id, $group_id]);
                }
            }
            // AUDIT: Log the bulk assignment action for compliance tracking.
            log_audit($pdo, $_SESSION['user_id'], 'DEVICES_ASSIGNED_TO_GROUP', 'device_group', $group_id, ['count' => count($device_ids)]);
            $message = 'Devices assigned successfully.';
            $active_tab = 'groups';
        } catch (PDOException $e) {
            $message = 'Error assigning devices.';
            $message_type = 'danger';
        }
    }
    // 4. Create Rule
    elseif (isset($_POST['create_rule'])) {
        $rule_name = trim($_POST['rule_name']);
        $condition = trim($_POST['condition']);
        $action = trim($_POST['action']);
        $severity = $_POST['severity'] ?? 'medium';
        if (!empty($rule_name) && !empty($condition)) {
            try {
                $stmt = $pdo->prepare("INSERT INTO security_rules (name, condition_logic, action, severity) VALUES (?, ?, ?, ?)");
                $stmt->execute([$rule_name, $condition, $action, $severity]);
                log_audit($pdo, $_SESSION['user_id'], 'RULE_CREATED', 'security_rule', $pdo->lastInsertId());
                $message = 'Security rule created successfully.';
                $active_tab = 'rules';
            } catch (PDOException $e) {
                $message = 'Error creating rule: ' . htmlspecialchars($e->getMessage());
                $message_type = 'danger';
            }
        }
    }
    // 5. Delete Rule
    elseif (isset($_POST['delete_rule'])) {
        $rule_id = (int) $_POST['rule_id'];
        try {
            $pdo->prepare("DELETE FROM security_rules WHERE rule_id = ?")->execute([$rule_id]);
            log_audit($pdo, $_SESSION['user_id'], 'RULE_DELETED', 'security_rule', $rule_id);
            $message = 'Security rule deleted successfully.';
        } catch (PDOException $e) {
            $message = 'Error deleting rule.';
            $message_type = 'danger';
        }
    }
}

// Fetch Data
try {
    $groups = $pdo->query("SELECT * FROM device_group ORDER BY name ASC")->fetchAll(PDO::FETCH_ASSOC);
    $devices = $pdo->query("SELECT device_id, hostname, os_family FROM device ORDER BY hostname ASC")->fetchAll(PDO::FETCH_ASSOC);
    $rules = $pdo->query("SELECT * FROM security_rules ORDER BY created_at DESC")->fetchAll(PDO::FETCH_ASSOC);
    
    // Fetch current mappings for the assignment modal
    $mappings = [];
    foreach ($groups as $group) {
        $stmt = $pdo->prepare("SELECT device_id FROM device_group_map WHERE group_id = ?");
        $stmt->execute([$group['group_id']]);
        $mappings[$group['group_id']] = $stmt->fetchAll(PDO::FETCH_COLUMN);
    }
} catch (PDOException $e) {
    $error = "Database error: " . htmlspecialchars($e->getMessage());
    $groups = [];
    $devices = [];
    $rules = [];
    $mappings = [];
}

$page_title = "Policy Management";
require_once __DIR__ . '/includes/header.php';
?>

<div class="container-fluid mt-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2><i class="bi bi-shield-check"></i> Policy & Group Management</h2>
    </div>

    <?php if ($message): ?>
        <div class="alert alert-<?= htmlspecialchars($message_type) ?> alert-dismissible fade show" role="alert">
            <?= htmlspecialchars($message) ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    <?php endif; ?>

    <?php if (isset($error)): ?>
        <div class="alert alert-danger"><?= $error ?></div>
    <?php endif; ?>

    <!-- Tabs -->
    <ul class="nav nav-tabs mb-4" id="policyTabs" role="tablist">
        <li class="nav-item" role="presentation">
            <button class="nav-link <?= $active_tab === 'groups' ? 'active' : '' ?>" id="groups-tab" data-bs-toggle="tab" data-bs-target="#groups" type="button" role="tab">Device Groups</button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link <?= $active_tab === 'rules' ? 'active' : '' ?>" id="rules-tab" data-bs-toggle="tab" data-bs-target="#rules" type="button" role="tab">Security Rules</button>
        </li>
    </ul>

    <div class="tab-content" id="policyTabsContent">
        <!-- Device Groups Tab -->
        <div class="tab-pane fade <?= $active_tab === 'groups' ? 'show active' : '' ?>" id="groups" role="tabpanel">
            <div class="d-flex justify-content-between mb-3">
                <h5 class="mb-0">Configured Device Groups</h5>
                <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#createGroupModal">
                    <i class="bi bi-plus-circle"></i> Create Group
                </button>
            </div>
            <div class="card shadow-sm">
                <div class="card-body">
                    <?php if (empty($groups)): ?>
                        <p class="text-muted text-center py-4">No device groups configured yet.</p>
                    <?php else: ?>
                        <div class="table-responsive">
                            <table class="table table-hover align-middle" id="groupsTable">
                                <thead class="table-light">
                                    <tr>
                                        <th>Group Name</th>
                                        <th>Description</th>
                                        <th class="text-end">Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($groups as $group): ?>
                                    <tr>
                                        <td class="fw-bold"><?= htmlspecialchars($group['name']) ?></td>
                                        <td><?= htmlspecialchars($group['description'] ?: 'N/A') ?></td>
                                        <td class="text-end">
                                            <button class="btn btn-sm btn-outline-primary me-1" data-bs-toggle="modal" data-bs-target="#assignDevicesModal" 
                                                data-group-id="<?= $group['group_id'] ?>" data-group-name="<?= htmlspecialchars($group['name']) ?>">
                                                <i class="bi bi-people"></i> Assign Devices
                                            </button>
                                            <form method="POST" style="display:inline;" onsubmit="return confirm('Delete this group and all its device assignments?');">
                                                <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                                                <input type="hidden" name="group_id" value="<?= $group['group_id'] ?>">
                                                <input type="hidden" name="delete_group" value="1">
                                                <button type="submit" class="btn btn-sm btn-outline-danger">
                                                    <i class="bi bi-trash"></i>
                                                </button>
                                            </form>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <!-- Security Rules Tab -->
        <div class="tab-pane fade <?= $active_tab === 'rules' ? 'show active' : '' ?>" id="rules" role="tabpanel">
            <div class="d-flex justify-content-between mb-3">
                <h5 class="mb-0">Baseline Security Rules</h5>
                <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#createRuleModal">
                    <i class="bi bi-plus-circle"></i> Create Rule
                </button>
            </div>
            <div class="card shadow-sm">
                <div class="card-body">
                    <?php if (empty($rules)): ?>
                        <p class="text-muted text-center py-4">No security rules configured yet.</p>
                    <?php else: ?>
                        <div class="table-responsive">
                            <table class="table table-hover align-middle" id="rulesTable">
                                <thead class="table-light">
                                    <tr>
                                        <th>Rule Name</th>
                                        <th>Condition</th>
                                        <th>Action</th>
                                        <th>Severity</th>
                                        <th class="text-end">Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($rules as $rule): 
                                        $sev_class = 'bg-secondary';
                                        if ($rule['severity'] === 'critical') $sev_class = 'bg-danger';
                                        elseif ($rule['severity'] === 'high') $sev_class = 'bg-warning text-dark';
                                        elseif ($rule['severity'] === 'low') $sev_class = 'bg-info text-dark';
                                    ?>
                                    <tr>
                                        <td class="fw-bold"><?= htmlspecialchars($rule['name']) ?></td>
                                        <td><code><?= htmlspecialchars($rule['condition_logic']) ?></code></td>
                                        <td><?= htmlspecialchars($rule['action']) ?></td>
                                        <td><span class="badge <?= $sev_class ?>"><?= ucfirst(htmlspecialchars($rule['severity'])) ?></span></td>
                                        <td class="text-end">
                                            <form method="POST" style="display:inline;" onsubmit="return confirm('Delete this security rule?');">
                                                <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                                                <input type="hidden" name="rule_id" value="<?= $rule['rule_id'] ?>">
                                                <input type="hidden" name="delete_rule" value="1">
                                                <button type="submit" class="btn btn-sm btn-outline-danger">
                                                    <i class="bi bi-trash"></i>
                                                </button>
                                            </form>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Create Group Modal -->
<div class="modal fade" id="createGroupModal" tabindex="-1">
    <div class="modal-dialog">
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
            <input type="hidden" name="create_group" value="1">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Create Device Group</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label">Group Name <span class="text-danger">*</span></label>
                        <input type="text" class="form-control" name="group_name" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Description</label>
                        <textarea class="form-control" name="description" rows="2"></textarea>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">Create Group</button>
                </div>
            </div>
        </form>
    </div>
</div>

<!-- Assign Devices Modal -->
<div class="modal fade" id="assignDevicesModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
            <input type="hidden" name="assign_devices" value="1">
            <input type="hidden" name="group_id" id="assign_group_id">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Assign Devices to <span id="assign_group_name"></span></h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <?php if (empty($devices)): ?>
                        <p class="text-muted">No devices registered in the system yet.</p>
                    <?php else: ?>
                        <div class="mb-3">
                            <button type="button" class="btn btn-sm btn-outline-secondary me-2" onclick="checkAllDevices(true)">Select All</button>
                            <button type="button" class="btn btn-sm btn-outline-secondary" onclick="checkAllDevices(false)">Deselect All</button>
                        </div>
                        <div class="border rounded p-3" style="max-height: 300px; overflow-y: auto;">
                            <?php foreach ($devices as $device): ?>
                                <div class="form-check">
                                    <input class="form-check-input device-checkbox" type="checkbox" name="device_ids[]" value="<?= $device['device_id'] ?>" id="dev_<?= $device['device_id'] ?>">
                                    <label class="form-check-label" for="dev_<?= $device['device_id'] ?>">
                                        <strong><?= htmlspecialchars($device['hostname']) ?></strong> 
                                        <span class="text-muted small">(<?= htmlspecialchars($device['os_family']) ?>)</span>
                                    </label>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">Save Assignments</button>
                </div>
            </div>
        </form>
    </div>
</div>

<!-- Create Rule Modal -->
<div class="modal fade" id="createRuleModal" tabindex="-1">
    <div class="modal-dialog">
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
            <input type="hidden" name="create_rule" value="1">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Create Security Rule</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label">Rule Name <span class="text-danger">*</span></label>
                        <input type="text" class="form-control" name="rule_name" required placeholder="e.g., Detect Open RDP">
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Condition Logic <span class="text-danger">*</span></label>
                        <input type="text" class="form-control" name="condition" required placeholder="e.g., port == 3389 AND is_expected == false">
                        <div class="form-text">Simple condition evaluated against incoming check findings.</div>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Action</label>
                        <select class="form-select" name="action">
                            <option value="alert">Generate Alert</option>
                            <option value="log">Log Only</option>
                            <option value="block">Block (Future)</option>
                        </select>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Severity</label>
                        <select class="form-select" name="severity">
                            <option value="low">Low</option>
                            <option value="medium" selected>Medium</option>
                            <option value="high">High</option>
                            <option value="critical">Critical</option>
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">Create Rule</button>
                </div>
            </div>
        </form>
    </div>
</div>

<script>
// Pass PHP mappings to JS for the modal
const groupMappings = <?= json_encode($mappings) ?>;

// Handle Assign Devices Modal Show
const assignModal = document.getElementById('assignDevicesModal');
assignModal.addEventListener('show.bs.modal', function (event) {
    const button = event.relatedTarget;
    const groupId = button.getAttribute('data-group-id');
    const groupName = button.getAttribute('data-group-name');
    
    document.getElementById('assign_group_id').value = groupId;
    document.getElementById('assign_group_name').textContent = groupName;
    
    // Reset checkboxes
    document.querySelectorAll('.device-checkbox').forEach(cb => cb.checked = false);
    
    // Check assigned devices
    if (groupMappings[groupId]) {
        groupMappings[groupId].forEach(devId => {
            const cb = document.getElementById('dev_' + devId);
            if (cb) cb.checked = true;
        });
    }
});

function checkAllDevices(checked) {
    document.querySelectorAll('.device-checkbox').forEach(cb => cb.checked = checked);
}

$(document).ready(function() {
    $('#groupsTable').DataTable({
        pageLength: 10,
        language: { search: "Filter groups:" }
    });
    $('#rulesTable').DataTable({
        pageLength: 10,
        language: { search: "Filter rules:" },
        columnDefs: [{ targets: [4], orderable: false }]
    });
});
</script>

<?php require_once __DIR__ . '/includes/footer.php'; ?>