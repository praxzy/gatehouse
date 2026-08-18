-- +goose Up

CREATE TABLE permission_catalog (
    permission  text PRIMARY KEY,
    name        text NOT NULL,
    description text NOT NULL,

    CONSTRAINT permission_catalog_key_format
        CHECK (
            permission ~
            '^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$'
        ),

    CONSTRAINT permission_catalog_name_not_blank
        CHECK (length(btrim(name)) BETWEEN 1 AND 100),

    CONSTRAINT permission_catalog_description_not_blank
        CHECK (length(btrim(description)) BETWEEN 1 AND 300)
);

INSERT INTO permission_catalog (
    permission,
    name,
    description
)
VALUES
    (
        'tenant.read',
        'View organization',
        'View organization identity and configuration.'
    ),
    (
        'member.read',
        'View members',
        'View tenant members and pending invitations.'
    ),
    (
        'member.manage',
        'Manage members',
        'Invite members and change membership roles or status.'
    ),
    (
        'role.read',
        'View roles',
        'View built-in and custom roles with their permissions.'
    ),
    (
        'role.manage',
        'Manage roles',
        'Create and update tenant custom roles.'
    );

ALTER TABLE role_permissions
ADD CONSTRAINT role_permissions_catalog_fk
FOREIGN KEY (permission)
REFERENCES permission_catalog (permission)
ON DELETE RESTRICT;

INSERT INTO role_permissions (
    tenant_id,
    role_id,
    permission
)
SELECT
    role.tenant_id,
    role.id,
    catalog.permission
FROM roles AS role
CROSS JOIN permission_catalog AS catalog
WHERE role.role_key = 'owner'
  AND role.is_system = true
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (
    tenant_id,
    role_id,
    permission
)
SELECT
    role.tenant_id,
    role.id,
    built_in_permission.permission
FROM roles AS role
CROSS JOIN (
    VALUES
        ('tenant.read'),
        ('member.read')
) AS built_in_permission(permission)
WHERE role.role_key = 'member'
  AND role.is_system = true
ON CONFLICT DO NOTHING;


-- +goose Down

DELETE FROM role_permissions AS role_permission
USING roles AS role
WHERE role_permission.tenant_id = role.tenant_id
  AND role_permission.role_id = role.id
  AND role.is_system = true
  AND role.role_key IN ('owner', 'member')
  AND role_permission.permission IN (
      'tenant.read',
      'member.read',
      'member.manage',
      'role.read',
      'role.manage'
  );

ALTER TABLE role_permissions
DROP CONSTRAINT role_permissions_catalog_fk;

DROP TABLE permission_catalog;