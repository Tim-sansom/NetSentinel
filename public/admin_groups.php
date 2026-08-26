<?php
// 1. Include dependencies first
require_once 'includes/db.php';
require_once 'includes/auth.php';
require_once 'includes/audit.php';

// 2. Start session if not already started (must happen before checking $_SESSION)
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// 3. Ensure user is logged in (requireLogin() handles the redirect to login.php if not)
requireLogin(); 

// 4. STRICT ADMIN CHECK: Case-insensitive (handles 'Admin', 'admin', 'ADMIN')
if (!isset($_SESSION['role']) || strtolower($_SESSION['role']) !== 'admin') {
    http_response_code(403);
    die('<div class="container mt-4"><div class="alert alert-danger">Access denied. Admin privileges required.</div></div>');
}

$message = '';
$message_type = 'success';
$active_tab = 'groups'; // Default tab

// Handle Form Submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $message = 'Invalid security token. Please refresh and try again.';
        $message_type = 'danger';
    } 
    // 1. Create New Group
    elseif (isset($_POST['create_group'])) {
        $name = trim($_POST['name']);
        $description = trim($_POST['description'] ?? '');

        if (empty($name)) {
            $message = 'Group name is required.';
            $message_type = 'danger';
        } else {
            try {
                $stmt = $pdo->prepare("INSERT INTO device_group (name, description) VALUES (?, ?)");
                $stmt->execute([$name, $description]);
                log_audit($pdo, $_SESSION['user_id'], 'DEVICE_GROUP_CREATED', 'device_group', (int)$pdo->lastInsertId());
                $message = "Group '$name' created successfully.";
            } catch (PDOException $e) {
                $message = 'Error creating group. Name may already be in use.';
                $message_type = 'danger';
            }
        }
    } 
    // 2. Delete Group
    elseif (isset($_POST['delete_group'])) {
        $group_id = (int) $_POST['group_id'];
        
        try {
            $stmt = $pdo->prepare("SELECT name FROM device_group WHERE group_id = ?");
            $stmt->execute([$group_id]);
            $group = $stmt->fetch(PDO::FETCH_ASSOC);
            
            $pdo->prepare("DELETE FROM device_group WHERE group_id = ?")->execute([$group_id]);
            log_audit($pdo, $_SESSION['user_id'], 'DEVICE_GROUP_DELETED', 'device_group', $group_id);
            $message = "Group '{$group['name']}' deleted successfully.";
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
            // Remove existing assignments
            $pdo->prepare("DELETE FROM device_group_map WHERE group_id = ?")->execute([$group_id]);
            
            // Add new assignments
            if (!empty($device_ids)) {
                $stmt = $pdo->prepare("INSERT INTO device_group_map (device_id, group_id) VALUES (?, ?)");
                foreach ($device_ids as $device_id) {
                    $stmt->execute([(int)$device_id, $group_id]);
                }
            }
            
            log_audit($pdo, $_SESSION['user_id'], 'DEVICES_ASSIGNED_TO_GROUP', 'device_group', $group_id, ['count' => count($device_ids)]);
            $message = 'Devices assigned successfully.';
            $active_tab = 'devices';
        } catch (PDOException $e) {
            $message = 'Error assigning devices.';
            $message_type = 'danger';
        }
    } 
    // 4. Create Baseline Rule
    elseif (isset($_POST['create_rule'])) {
        $group_id = (int) $_POST['group_id'];
        $check_type = $_POST['check_type'];
        $target = trim($_POST['target']);
        $expected_state = $_POST['expected_state'];
        $severity = $_POST['severity'];

        if (empty($target)) {
            $message = 'Target value is required.';
            $message_type = 'danger';
        } else {
            try {
                $stmt = $pdo->prepare("
                    INSERT INTO baseline_rule (group_id, check_type, target, expected_state, severity) 
                    VALUES (?, ?, ?, ?, ?)
                ");
                $stmt->execute([$group_id, $check_type, $target, $expected_state, $severity]);
                log_audit($pdo, $_SESSION['user_id'], 'BASELINE_RULE_CREATED', 'baseline_rule', (int)$pdo->lastInsertId());
                $message = 'Baseline rule created successfully.';
                $active_tab = 'rules';
            } catch (PDOException $e) {
                $message = 'Error creating rule.';
                $message_type = 'danger';
            }
        }
    } 
    // 5. Delete Baseline Rule
    elseif (isset($_POST['delete_rule'])) {
        $rule_id = (int) $_POST['rule_id'];
        
        try {
            $pdo->prepare("DELETE FROM baseline_rule WHERE rule_id = ?")->execute([$rule_id]);
            log_audit($pdo, $_SESSION['user_id'], 'BASELINE_RULE_DELETED', 'baseline_rule', $rule_id);
            $message = 'Rule deleted successfully.';
            $active_tab = 'rules';
        } catch (PDOException $e) {
            $message = 'Error deleting rule.';
            $message_type = 'danger';
        }
    }
}

// Fetch all groups
$groups_stmt = $pdo->query("SELECT * FROM device_group ORDER BY group_id DESC");
$groups = $groups_stmt->fetchAll(PDO::FETCH_ASSOC);

// Fetch all devices
$devices_stmt = $pdo->query("SELECT device_id, hostname, os_family, os_version, last_seen_at FROM device ORDER BY hostname");
$devices = $devices_stmt->fetchAll(PDO::FETCH_ASSOC);

// Fetch all rules with group names
$rules_stmt = $pdo->query("
    SELECT r.*, g.name as group_name 
    FROM baseline_rule r 
    LEFT JOIN device_group g ON r.group_id = g.group_id 
    ORDER BY r.rule_id DESC
");
$rules = $rules_stmt->fetchAll(PDO::FETCH_ASSOC);

$page_title = "Asset & Policy Management";
require_once 'includes/header.php';
?>

<div class="container mt-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2><i class="bi bi-shield-check"></i> Asset & Policy Management</h2>
    </div>

    <?php if ($message): ?>
        <div class="alert alert-<?= $message_type ?> alert-dismissible fade show" role="alert">
            <?= htmlspecialchars($message) ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    <?php endif; ?>

    <!-- Tabs Navigation -->
    <ul class="nav nav-tabs mb-4" id="policyTabs" role="tablist">
        <li class="nav-item" role="presentation">
            <button class="nav-link <?= $active_tab === 'groups' ? 'active' : '' ?>" id="groups-tab" data-bs-toggle="tab" data-bs-target="#groups" type="button" role="tab">
                <i class="bi bi-folder"></i> Device Groups
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link <?= $active_tab === 'devices' ? 'active' : '' ?>" id="devices-tab" data-bs-toggle="tab" data-bs-target="#devices" type="button" role="tab">
                <i class="bi bi-hdd-network"></i> Assign Devices
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link <?= $active_tab === 'rules' ? 'active' : '' ?>" id="rules-tab" data-bs-toggle="tab" data-bs-target="#rules" type="button" role="tab">
                <i class="bi bi-list-check"></i> Baseline Rules
            </button>
        </li>
    </ul>

    <!-- Tab Content -->
    <div class="tab-content" id="policyTabsContent">
        
        <!-- TAB 1: Device Groups -->
        <div class="tab-pane fade <?= $active_tab === 'groups' ? 'show active' : '' ?>" id="groups" role="tabpanel">
            <div class="card shadow-sm">
                <div class="card-header bg-white d-flex justify-content-between align-items-center">
                    <h5 class="mb-0"><i class="bi bi-folder-plus"></i> Manage Device Groups</h5>
                    <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#createGroupModal">
                        <i class="bi bi-plus-circle"></i> New Group
                    </button>
                </div>
                <div class="card-body">
                    <table id="groupsTable" class="table table-striped table-hover" style="width:100%">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Group Name</th>
                                <th>Description</th>
                                <th>Created</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($groups as $group): ?>
                                <tr>
                                    <td><?= $group['group_id'] ?></td>
                                    <td><strong><?= htmlspecialchars($group['name']) ?></strong></td>
                                    <td><?= htmlspecialchars($group['description'] ?? '-') ?></td>
                                    <td><?= isset($group['created_at']) ? date('Y-m-d', strtotime($group['created_at'])) : 'N/A' ?></td>
                                    <td>
                                        <button class="btn btn-sm btn-outline-danger" data-bs-toggle="modal" data-bs-target="#deleteGroupModal<?= $group['group_id'] ?>">
                                            <i class="bi bi-trash"></i> Delete
                                        </button>
                                    </td>
                                </tr>

                                <!-- Delete Group Modal -->
                                <div class="modal fade" id="deleteGroupModal<?= $group['group_id'] ?>" tabindex="-1">
                                    <div class="modal-dialog">
                                        <form method="POST" action="admin_groups.php">
                                            <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                                            <input type="hidden" name="group_id" value="<?= $group['group_id'] ?>">
                                            <div class="modal-content">
                                                <div class="modal-header bg-danger text-white">
                                                    <h5 class="modal-title">Delete Group</h5>
                                                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                                                </div>
                                                <div class="modal-body">
                                                    <p>Are you sure you want to delete <strong><?= htmlspecialchars($group['name']) ?></strong>?</p>
                                                    <p class="text-muted small">This will also remove all device assignments and baseline rules for this group.</p>
                                                </div>
                                                <div class="modal-footer">
                                                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                                    <button type="submit" name="delete_group" class="btn btn-danger">Delete Group</button>
                                                </div>
                                            </div>
                                        </form>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 2: Assign Devices -->
        <div class="tab-pane fade <?= $active_tab === 'devices' ? 'show active' : '' ?>" id="devices" role="tabpanel">
            <div class="card shadow-sm">
                <div class="card-header bg-white">
                    <h5 class="mb-0"><i class="bi bi-link-45deg"></i> Assign Devices to Groups</h5>
                </div>
                <div class="card-body">
                    <?php if (empty($groups)): ?>
                        <div class="alert alert-warning">
                            <i class="bi bi-exclamation-triangle"></i> No groups found. Please create a group first in the <strong>Device Groups</strong> tab.
                        </div>
                    <?php else: ?>
                        <form method="POST" action="admin_groups.php">
                            <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                            
                            <div class="mb-3">
                                <label for="group_select" class="form-label">Select Group</label>
                                <select class="form-select" id="group_select" name="group_id" required>
                                    <option value="">-- Choose a Group --</option>
                                    <?php foreach ($groups as $group): ?>
                                        <option value="<?= $group['group_id'] ?>"><?= htmlspecialchars($group['name']) ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </div>

                            <div class="mb-3">
                                <label class="form-label">Select Devices (Hold Ctrl/Cmd to select multiple)</label>
                                <select class="form-select" name="device_ids[]" multiple size="10" required>
                                    <?php foreach ($devices as $device): ?>
                                        <option value="<?= $device['device_id'] ?>">
                                          <?= htmlspecialchars($device['hostname']) ?> 
                                         (<?= htmlspecialchars($device['os_family'] ?? 'Unknown') ?> <?= htmlspecialchars($device['os_version'] ?? '') ?>)
                                       </option>
                                    <?php endforeach; ?>
                                </select>
                                <div class="form-text">Devices not in any group will not have baseline rules applied.</div>
                            </div>

                            <button type="submit" name="assign_devices" class="btn btn-primary">
                                <i class="bi bi-check-circle"></i> Assign Devices
                            </button>
                        </form>

                        <!-- Current Assignments -->
                        <hr class="my-4">
                        <h6>Current Group Memberships</h6>
                        <table class="table table-sm table-bordered">
                            <thead class="table-light">
                                <tr>
                                    <th>Group</th>
                                    <th>Devices</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php 
                                $assignment_stmt = $pdo->query("
                                    SELECT g.name, COUNT(m.device_id) as device_count
                                    FROM device_group g
                                    LEFT JOIN device_group_map m ON g.group_id = m.group_id
                                    GROUP BY g.group_id
                                ");
                                $assignments = $assignment_stmt->fetchAll(PDO::FETCH_ASSOC);
                                foreach ($assignments as $assignment): 
                                ?>
                                    <tr>
                                        <td><?= htmlspecialchars($assignment['name']) ?></td>
                                        <td><span class="badge bg-info"><?= $assignment['device_count'] ?> devices</span></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <!-- TAB 3: Baseline Rules -->
        <div class="tab-pane fade <?= $active_tab === 'rules' ? 'show active' : '' ?>" id="rules" role="tabpanel">
            <div class="card shadow-sm">
                <div class="card-header bg-white d-flex justify-content-between align-items-center">
                    <h5 class="mb-0"><i class="bi bi-list-check"></i> Baseline Security Rules</h5>
                    <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#createRuleModal">
                        <i class="bi bi-plus-circle"></i> New Rule
                    </button>
                </div>
                <div class="card-body">
                    <table id="rulesTable" class="table table-striped table-hover" style="width:100%">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Group</th>
                                <th>Check Type</th>
                                <th>Target</th>
                                <th>Expected State</th>
                                <th>Severity</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($rules as $rule): ?>
                                <tr>
                                    <td><?= $rule['rule_id'] ?></td>
                                    <td><span class="badge bg-secondary"><?= htmlspecialchars($rule['group_name'] ?? 'Unknown') ?></span></td>
                                    <td><?= htmlspecialchars($rule['check_type']) ?></td>
                                    <td><code><?= htmlspecialchars($rule['target']) ?></code></td>
                                    <td><?= htmlspecialchars($rule['expected_state']) ?></td>
                                    <td>
                                        <?php
                                        $severity_colors = [
                                            'low' => 'info',
                                            'medium' => 'warning',
                                            'high' => 'danger',
                                            'critical' => 'dark'
                                        ];
                                        $color = $severity_colors[$rule['severity']] ?? 'secondary';
                                        ?>
                                        <span class="badge bg-<?= $color ?>"><?= ucfirst($rule['severity']) ?></span>
                                    </td>
                                    <td>
                                        <button class="btn btn-sm btn-outline-danger" data-bs-toggle="modal" data-bs-target="#deleteRuleModal<?= $rule['rule_id'] ?>">
                                            <i class="bi bi-trash"></i>
                                        </button>
                                    </td>
                                </tr>

                                <!-- Delete Rule Modal -->
                                <div class="modal fade" id="deleteRuleModal<?= $rule['rule_id'] ?>" tabindex="-1">
                                    <div class="modal-dialog">
                                        <form method="POST" action="admin_groups.php">
                                            <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                                            <input type="hidden" name="rule_id" value="<?= $rule['rule_id'] ?>">
                                            <div class="modal-content">
                                                <div class="modal-header bg-danger text-white">
                                                    <h5 class="modal-title">Delete Rule</h5>
                                                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                                                </div>
                                                <div class="modal-body">
                                                    <p>Delete this baseline rule?</p>
                                                </div>
                                                <div class="modal-footer">
                                                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                                    <button type="submit" name="delete_rule" class="btn btn-danger">Delete</button>
                                                </div>
                                            </div>
                                        </form>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Create Group Modal -->
<div class="modal fade" id="createGroupModal" tabindex="-1">
    <div class="modal-dialog">
        <form method="POST" action="admin_groups.php">
            <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Create New Device Group</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="mb-3">
                        <label for="group_name" class="form-label">Group Name *</label>
                        <input type="text" class="form-control" id="group_name" name="name" placeholder="e.g., Remote Workers" required>
                    </div>
                    <div class="mb-3">
                        <label for="group_desc" class="form-label">Description</label>
                        <textarea class="form-control" id="group_desc" name="description" rows="3" placeholder="Describe the purpose of this group"></textarea>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" name="create_group" class="btn btn-primary">Create Group</button>
                </div>
            </div>
        </form>
    </div>
</div>

<!-- Create Rule Modal -->
<div class="modal fade" id="createRuleModal" tabindex="-1">
    <div class="modal-dialog">
        <form method="POST" action="admin_groups.php">
            <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Create Baseline Rule</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="mb-3">
                        <label for="rule_group" class="form-label">Apply to Group *</label>
                        <select class="form-select" id="rule_group" name="group_id" required>
                            <option value="">-- Choose Group --</option>
                            <?php foreach ($groups as $group): ?>
                                <option value="<?= $group['group_id'] ?>"><?= htmlspecialchars($group['name']) ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="mb-3">
                        <label for="check_type" class="form-label">Check Type *</label>
                        <select class="form-select" id="check_type" name="check_type" required>
                            <option value="port_check">Port Check</option>
                            <option value="firewall_check">Firewall Check</option>
                            <option value="system_check">System Check</option>
                        </select>
                    </div>
                    <div class="mb-3">
                        <label for="rule_target" class="form-label">Target *</label>
                        <input type="text" class="form-control" id="rule_target" name="target" placeholder="e.g., 3389 (for port) or Windows 10 (for OS)" required>
                        <div class="form-text">For ports: enter port number. For firewall: enter "enabled" or "disabled". For system: enter OS version.</div>
                    </div>
                    <div class="mb-3">
                        <label for="expected_state" class="form-label">Expected State *</label>
                        <select class="form-select" id="expected_state" name="expected_state" required>
                            <option value="closed">Closed (for ports)</option>
                            <option value="open">Open (for ports)</option>
                            <option value="enabled">Enabled (for firewall)</option>
                            <option value="disabled">Disabled (for firewall)</option>
                        </select>
                    </div>
                    <div class="mb-3">
                        <label for="severity" class="form-label">Severity *</label>
                        <select class="form-select" id="severity" name="severity" required>
                            <option value="low">Low</option>
                            <option value="medium" selected>Medium</option>
                            <option value="high">High</option>
                            <option value="critical">Critical</option>
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" name="create_rule" class="btn btn-primary">Create Rule</button>
                </div>
            </div>
        </form>
    </div>
</div>

<script>
$(document).ready(function() {
    // Initialize DataTables
    $('#groupsTable').DataTable({
        order: [[0, 'desc']],
        pageLength: 10
    });
    
    $('#rulesTable').DataTable({
        order: [[0, 'desc']],
        pageLength: 15
    });
});
</script>

<?php require_once 'includes/footer.php'; ?>