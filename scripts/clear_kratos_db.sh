docker compose exec db-kratos bash -c "`
  export PGHOST=localhost PGPORT=5432 PGUSER=kratos PGPASSWORD=secret PGDATABASE=kratos 
  psql -c "
    TRUNCATE continuity_containers CASCADE;
    TRUNCATE courier_message_dispatches CASCADE;
    TRUNCATE courier_messages CASCADE;
    TRUNCATE identities CASCADE;
    TRUNCATE identity_credential_identifiers CASCADE;
    TRUNCATE identity_credentials CASCADE;
    TRUNCATE identity_login_codes CASCADE;
    TRUNCATE identity_recovery_addresses CASCADE;
    TRUNCATE identity_recovery_codes CASCADE;
    TRUNCATE identity_recovery_tokens CASCADE;
    TRUNCATE identity_registration_codes CASCADE;
    TRUNCATE identity_verifiable_addresses CASCADE;
    TRUNCATE identity_verification_codes CASCADE;
    TRUNCATE identity_verification_tokens CASCADE;
    TRUNCATE selfservice_errors CASCADE;
    TRUNCATE selfservice_login_flows CASCADE;
    TRUNCATE selfservice_recovery_flows CASCADE;
    TRUNCATE selfservice_registration_flows CASCADE;
    TRUNCATE selfservice_settings_flows CASCADE;
    TRUNCATE selfservice_verification_flows CASCADE;
    TRUNCATE session_devices CASCADE;
    TRUNCATE session_token_exchanges CASCADE;
    TRUNCATE sessions CASCADE;
  " > /dev/null 2>&1
`"