<?php
/**
 * NetSentinel Role-Based Access Control (RBAC) Helper
 * 
 * Provides universal access control functions for multi-tenant SaaS architecture.
 * 
 * Role Hierarchy:
 * - super_admin: Platform owner, sees ALL data across ALL tenants
 * - admin: Tenant admin, full control within their tenant only
 * - user: Tenant user, partial control within their tenant
 * - viewer: Tenant viewer, read-only access within their tenant
 */

/**
 * Check if user is Super Admin (platform owner)
 */
function is_super_admin(): bool {
    return isset($_SESSION['role']) && strtolower($_SESSION['role']) === 'super_admin';
}

/**
 * Check if user is Tenant Admin
 */
function is_tenant_admin(): bool {
    return isset($_SESSION['role']) && strtolower($_SESSION['role']) === 'admin';
}

/**
 * Check if user is Tenant User (partial control)
 */
function is_tenant_user(): bool {
    return isset($_SESSION['role']) && strtolower($_SESSION['role']) === 'user';
}

/**
 * Check if user is Viewer (read-only)
 */
function is_viewer(): bool {
    return isset($_SESSION['role']) && strtolower($_SESSION['role']) === 'viewer';
}

/**
 * Get user's tenant ID (group_id)
 * Returns NULL for super_admin
 */
function get_user_tenant_id(): ?int {
    if (is_super_admin()) {
        return null; // Super admin sees all tenants
    }
    return $_SESSION['group_id'] ?? null;
}

/**
 * Get the current user's role
 */
function get_user_role(): string {
    return strtolower($_SESSION['role'] ?? 'viewer');
}

/**
 * Build SQL WHERE clause for tenant filtering
 * Returns empty string for super_admin (sees all)
 * Returns filtered clause for tenant users
 */
function get_tenant_filter_sql(string $table_alias = 'd'): string {
    if (is_super_admin()) {
        return ''; // No filtering for super admin
    }
    
    $tenant_id = get_user_tenant_id();
    if ($tenant_id === null) {
        return '1=0'; // User has no tenant, show nothing
    }
    
    return "{$table_alias}.device_group_id = " . (int)$tenant_id;
}

/**
 * Check if user can perform write operations (add/edit/delete)
 * Super Admin and Tenant Admin can write
 * User and Viewer cannot
 */
function can_write(): bool {
    return is_super_admin() || is_tenant_admin();
}

/**
 * Check if user can manage other users (Tenant Admin only, or Super Admin)
 */
function can_manage_users(): bool {
    return is_super_admin() || is_tenant_admin();
}

/**
 * Get all devices visible to current user
 */
function get_visible_devices(PDO $pdo): array {
    if (is_super_admin()) {
        return $pdo->query("SELECT * FROM device ORDER BY hostname")->fetchAll(PDO::FETCH_ASSOC);
    }
    
    $tenant_id = get_user_tenant_id();
    if ($tenant_id === null) {
        return []; // No tenant, no devices
    }
    
    $stmt = $pdo->prepare("SELECT * FROM device WHERE device_group_id = ? ORDER BY hostname");
    $stmt->execute([$tenant_id]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}