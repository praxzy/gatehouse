-- +goose Up

ALTER TABLE totp_credentials
    ADD COLUMN enrollment_expires_at timestamptz;

UPDATE totp_credentials
SET enrollment_expires_at =
    updated_at + interval '10 minutes'
WHERE status = 'pending';

ALTER TABLE totp_credentials
    DROP CONSTRAINT totp_credentials_state_consistent;

ALTER TABLE totp_credentials
    ADD CONSTRAINT totp_credentials_state_consistent
    CHECK (
        (
            status = 'pending'
            AND confirmed_at IS NULL
            AND last_accepted_timestep IS NULL
            AND enrollment_expires_at IS NOT NULL
            AND enrollment_expires_at > updated_at
        )
        OR
        (
            status = 'active'
            AND confirmed_at IS NOT NULL
            AND last_accepted_timestep IS NOT NULL
            AND enrollment_expires_at IS NULL
        )
    );


-- +goose Down

ALTER TABLE totp_credentials
    DROP CONSTRAINT totp_credentials_state_consistent;

ALTER TABLE totp_credentials
    ADD CONSTRAINT totp_credentials_state_consistent
    CHECK (
        (
            status = 'pending'
            AND confirmed_at IS NULL
            AND last_accepted_timestep IS NULL
        )
        OR
        (
            status = 'active'
            AND confirmed_at IS NOT NULL
            AND last_accepted_timestep IS NOT NULL
        )
    );

ALTER TABLE totp_credentials
    DROP COLUMN enrollment_expires_at;