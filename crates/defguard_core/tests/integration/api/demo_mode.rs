use defguard_common::db::models::{Settings, settings::update_current_settings};
use defguard_core::{
    enterprise::{directory_sync::do_directory_sync, ldap::do_ldap_sync},
    grpc::GatewayEvent,
    handlers::Auth,
};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tokio::sync::broadcast;

use super::common::{client::TestClient, fetch_user_details, make_test_client_demo, setup_pool};

async fn login_as_admin(client: &TestClient) {
    let auth = Auth::new("admin", "pass123");
    let response = client.post("/api/v1/auth").json(&auth).send().await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[sqlx::test]
async fn test_demo_change_own_password_blocked(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (client, _state) = make_test_client_demo(pool).await;
    login_as_admin(&client).await;

    let response = client
        .put("/api/v1/user/change_password")
        .json(&json!({ "old_password": "pass123", "new_password": "NewPass1234!" }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[sqlx::test]
async fn test_demo_enable_totp_blocked(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (client, _state) = make_test_client_demo(pool).await;
    login_as_admin(&client).await;

    let response = client
        .post("/api/v1/auth/totp")
        .json(&json!({ "code": "123456" }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[sqlx::test]
async fn test_demo_enable_email_mfa_blocked(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (client, _state) = make_test_client_demo(pool).await;
    login_as_admin(&client).await;

    let response = client
        .post("/api/v1/auth/email")
        .json(&json!({ "code": "123456" }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[sqlx::test]
async fn test_demo_create_api_token_blocked(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (client, _state) = make_test_client_demo(pool).await;
    login_as_admin(&client).await;

    let response = client
        .post("/api/v1/user/admin/api_token")
        .json(&json!({ "name": "demo-token" }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[sqlx::test]
async fn test_demo_modify_user_blocked(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (client, _state) = make_test_client_demo(pool).await;
    login_as_admin(&client).await;

    let details = fetch_user_details(&client, "admin").await;
    let response = client
        .put("/api/v1/user/admin")
        .json(&details.user)
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[sqlx::test]
async fn test_demo_support_config_export_blocked(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (client, _state) = make_test_client_demo(pool).await;
    login_as_admin(&client).await;

    let response = client.get("/api/v1/support/configuration").send().await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[sqlx::test]
async fn test_demo_support_logs_export_blocked(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (client, _state) = make_test_client_demo(pool).await;
    login_as_admin(&client).await;

    let response = client.get("/api/v1/support/logs").send().await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[sqlx::test]
async fn test_demo_send_support_data_blocked(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (client, _state) = make_test_client_demo(pool).await;
    login_as_admin(&client).await;

    let response = client.post("/api/v1/mail/support").send().await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[sqlx::test]
async fn test_demo_edit_locked_setting_blocked(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (client, _state) = make_test_client_demo(pool).await;
    login_as_admin(&client).await;

    let response = client
        .patch("/api/v1/settings")
        .json(&json!({ "license": "SOME-NEW-LICENSE-KEY" }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[sqlx::test]
async fn test_demo_webhook_token_is_hardcoded(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (client, _state) = make_test_client_demo(pool).await;
    login_as_admin(&client).await;

    let response = client
        .post("/api/v1/webhook")
        .json(&json!({
            "url": "https://example.com/hook",
            "description": "demo",
            "token": "super-secret-real-token",
            "enabled": true,
            "on_user_created": true,
            "on_user_deleted": false,
            "on_user_modified": false,
            "on_hwkey_provision": false
        }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = client.get("/api/v1/webhook").send().await;
    assert_eq!(response.status(), StatusCode::OK);
    let webhooks: Vec<Value> = response.json().await;
    let hook = webhooks
        .iter()
        .find(|w| w["url"] == "https://example.com/hook")
        .expect("created webhook not found");
    assert_eq!(hook["token"], "SECRET");
}

#[sqlx::test]
async fn test_demo_ldap_bind_password_not_stored(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (client, _state) = make_test_client_demo(pool).await;
    login_as_admin(&client).await;

    let response = client
        .patch("/api/v1/settings")
        .json(&json!({
            "ldap_url": "ldap://192.0.2.1:389",
            "ldap_bind_username": "cn=admin,dc=example,dc=org",
            "ldap_bind_password": "super-secret-real-password"
        }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    let response = client.get("/api/v1/settings").send().await;
    assert_eq!(response.status(), StatusCode::OK);
    let settings: Value = response.json().await;
    assert_ne!(settings["ldap_bind_password"], "super-secret-real-password");
    assert_eq!(settings["ldap_bind_password"], "SECRET");
}

#[sqlx::test]
async fn test_demo_openid_provider_secret_not_stored(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    let (client, _state) = make_test_client_demo(pool).await;
    login_as_admin(&client).await;

    let response = client
        .post("/api/v1/openid/provider")
        .json(&json!({
            "name": "demoidp",
            "base_url": "https://192.0.2.1/",
            "kind": "Custom",
            "client_id": "demo-client-id",
            "client_secret": "super-secret-real-value",
            "directory_sync_enabled": true,
            "directory_sync_interval": 600,
            "directory_sync_user_behavior": "keep",
            "directory_sync_admin_behavior": "keep",
            "directory_sync_target": "all",
            "prefetch_users": false,
            "create_account": false,
            "username_handling": "RemoveForbidden"
        }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = client.get("/api/v1/openid/provider/demoidp").send().await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await;
    assert_ne!(body["provider"]["client_secret"], "super-secret-real-value");
    assert_eq!(body["provider"]["client_secret"], "SECRET");
}

#[sqlx::test]
async fn test_demo_settings_secrets_redacted(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (client, _state) = make_test_client_demo(pool).await;
    login_as_admin(&client).await;

    let response = client.get("/api/v1/settings").send().await;
    assert_eq!(response.status(), StatusCode::OK);
    let settings: Value = response.json().await;
    assert!(settings["secret_key"].is_null());
    assert!(settings["license"].is_null());
}

#[sqlx::test]
async fn test_demo_ldap_sync_job_does_not_run(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (_client, state) = make_test_client_demo(pool).await;

    let mut settings = Settings::get_current_settings();
    settings.ldap_enabled = true;
    settings.ldap_sync_enabled = true;
    settings.ldap_url = Some("ldap://192.0.2.1:389".into());
    settings.ldap_bind_username = Some("cn=admin,dc=example,dc=org".into());
    settings.ldap_bind_password = Some("secret".parse().unwrap());
    settings.ldap_username_attr = Some("uid".into());
    settings.ldap_user_search_base = Some("ou=users,dc=example,dc=org".into());
    settings.ldap_user_obj_class = Some("inetOrgPerson".into());
    settings.ldap_member_attr = Some("memberUid".into());
    settings.ldap_groupname_attr = Some("cn".into());
    settings.ldap_group_obj_class = Some("groupOfNames".into());
    settings.ldap_group_member_attr = Some("member".into());
    settings.ldap_group_search_base = Some("ou=groups,dc=example,dc=org".into());
    update_current_settings(&state.pool, settings).await.unwrap();

    let (wg_tx, _wg_rx) = broadcast::channel::<GatewayEvent>(16);
    do_ldap_sync(&state.pool, &wg_tx)
        .await
        .expect("LDAP sync must be a no-op in demo mode");
}

#[sqlx::test]
async fn test_demo_directory_sync_job_does_not_run(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (client, state) = make_test_client_demo(pool).await;
    login_as_admin(&client).await;

    let response = client
        .post("/api/v1/openid/provider")
        .json(&json!({
            "name": "demoidp",
            "base_url": "https://192.0.2.1/",
            "kind": "Custom",
            "client_id": "demo-client-id",
            "client_secret": "secret",
            "directory_sync_enabled": true,
            "directory_sync_interval": 600,
            "directory_sync_user_behavior": "keep",
            "directory_sync_admin_behavior": "keep",
            "directory_sync_target": "all",
            "prefetch_users": false,
            "create_account": false,
            "username_handling": "RemoveForbidden"
        }))
        .send()
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let (wg_tx, _wg_rx) = broadcast::channel::<GatewayEvent>(16);
    do_directory_sync(&state.pool, &wg_tx)
        .await
        .expect("directory sync must be a no-op in demo mode");
}
