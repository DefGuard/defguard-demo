use axum::{
    Extension,
    extract::{Json, Path, State},
    http::StatusCode,
};
use defguard_common::{
    config::server_config,
    db::{
        Id,
        models::{
            Settings, SettingsEssentials,
            settings::{LdapSyncStatus, SettingsPatch, update_current_settings},
        },
    },
    types::proxy::ProxyControlMessage,
};
use sqlx::PgPool;
use struct_patch::Patch;

use super::{ApiResponse, ApiResult};
use crate::{
    AppState,
    auth::{AdminRole, SessionInfo},
    enterprise::{
        db::models::enterprise_settings::EnterpriseSettings,
        handlers::LicenseInfo,
        ldap::{
            LDAPConnection,
            sync::{Authority, LdapDryRunAction, LdapDryRunResult, LdapDryRunUser},
        },
        license::update_cached_license,
    },
    error::WebError,
    events::{ApiEvent, ApiEventType, ApiRequestContext},
};

static DEFAULT_NAV_LOGO_URL: &str = "/svg/defguard-nav-logo.svg";
static DEFAULT_MAIN_LOGO_URL: &str = "/svg/logo-defguard-white.svg";

pub async fn get_settings(_admin: AdminRole, State(appstate): State<AppState>) -> ApiResult {
    debug!("Retrieving settings");
    if let Some(mut settings) = Settings::get(&appstate.pool).await? {
        if settings.nav_logo_url.is_empty() {
            settings.nav_logo_url = DEFAULT_NAV_LOGO_URL.into();
        }
        if settings.main_logo_url.is_empty() {
            settings.main_logo_url = DEFAULT_MAIN_LOGO_URL.into();
        }
        if server_config().is_demo_mode {
            settings.secret_key = None;
            settings.license = None;
            settings.smtp.password = None;
            settings.smtp.oauth_client_secret = None;
            settings.smtp.oauth_refresh_token = None;
        }
        return Ok(ApiResponse::json(settings, StatusCode::OK));
    }
    debug!("Retrieved settings");
    Ok(ApiResponse::default())
}

pub(crate) async fn update_settings(
    _admin: AdminRole,
    session: SessionInfo,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Json(mut data): Json<Settings>,
) -> ApiResult {
    debug!("User {} updating settings", session.user.username);

    // fetch current settings for event
    let before = Settings::get_current_settings();
    let license = data.license.clone();

    data.uuid = before.uuid;
    data.validate()?;

    if server_config().is_demo_mode && data.demo_locked_fields_differ(&before) {
        return Err(WebError::Forbidden(
            "This setting is read-only in demo mode",
        ));
    }

    if server_config().is_demo_mode {
        data.ldap_bind_password = data.ldap_bind_password.map(|_| "SECRET".parse().unwrap());
    }

    // clone for event
    let after = data.clone();

    update_current_settings(&appstate.pool, data).await?;
    update_cached_license(license.as_deref())?;

    // If SMTP configuration changed (e.g. server/port/sender toggled),
    // push updated password-reset visibility to all connected proxies.
    if before.smtp_configured() != after.smtp_configured()
        && let Ok(enterprise_settings) = EnterpriseSettings::get(&appstate.pool).await
    {
        let display_password_reset = enterprise_settings.edge_can_display_password_reset();
        if let Err(err) = appstate
            .proxy_control_tx
            .send(ProxyControlMessage::BroadcastPublicSettings {
                display_password_reset,
                display_download_step: enterprise_settings.display_download_step,
            })
            .await
        {
            error!("Failed to broadcast PublicSettings after SMTP config change: {err:?}");
        }
    }

    info!("User {} updated settings", session.user.username);
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::SettingsUpdated { before, after }),
    })?;

    Ok(ApiResponse::default())
}

pub async fn get_settings_essentials(Extension(pool): Extension<PgPool>) -> ApiResult {
    debug!("Retrieving essential settings");
    let mut settings = SettingsEssentials::get_settings_essentials(&pool).await?;
    if settings.nav_logo_url.is_empty() {
        settings.nav_logo_url = DEFAULT_NAV_LOGO_URL.into();
    }
    if settings.main_logo_url.is_empty() {
        settings.main_logo_url = DEFAULT_MAIN_LOGO_URL.into();
    }

    info!("Retrieved essential settings");

    Ok(ApiResponse::json(settings, StatusCode::OK))
}

pub(crate) async fn set_default_branding(
    _admin: AdminRole,
    State(appstate): State<AppState>,
    Path(_id): Path<Id>, // TODO: check with front-end and remove.
    session: SessionInfo,
    context: ApiRequestContext,
) -> ApiResult {
    debug!(
        "User {} restoring default branding settings",
        session.user.username
    );
    let settings = Settings::get(&appstate.pool).await?;
    match settings {
        Some(mut settings) => {
            settings.instance_name = "Defguard".into();
            settings.nav_logo_url = DEFAULT_NAV_LOGO_URL.into();
            settings.main_logo_url = DEFAULT_MAIN_LOGO_URL.into();
            update_current_settings(&appstate.pool, settings.clone()).await?;
            info!(
                "User {} restored default branding settings",
                session.user.username
            );
            appstate.emit_event(ApiEvent {
                context,
                event: Box::new(ApiEventType::SettingsDefaultBrandingRestored),
            })?;
            Ok(ApiResponse::json(settings, StatusCode::OK))
        }
        None => Err(WebError::DbError("Cannot restore settings".into())),
    }
}

pub async fn patch_settings(
    _admin: AdminRole,
    State(appstate): State<AppState>,
    session: SessionInfo,
    context: ApiRequestContext,
    Json(data): Json<SettingsPatch>,
) -> ApiResult {
    debug!("Admin {} is patching settings", session.user.username);
    let mut settings = Settings::get_current_settings();
    // prepare clone for emitting an event
    let before = settings.clone();
    let license = data.license.clone();

    // update LDAP sync status if relevant settings have been changed
    if let Some(ldap_enabled) = data.ldap_enabled
        && !ldap_enabled
    {
        settings.ldap_sync_status = LdapSyncStatus::OutOfSync;
    }
    if let Some(ldap_authority) = data.ldap_is_authoritative
        && settings.ldap_is_authoritative != ldap_authority
    {
        settings.ldap_sync_status = LdapSyncStatus::OutOfSync;
    }
    if let Some(ldap_sync_groups) = &data.ldap_sync_groups
        && &settings.ldap_sync_groups != ldap_sync_groups
    {
        settings.ldap_sync_status = LdapSyncStatus::OutOfSync;
    }

    settings.apply(data);
    settings.validate()?;

    if server_config().is_demo_mode && settings.demo_locked_fields_differ(&before) {
        return Err(WebError::Forbidden(
            "This setting is read-only in demo mode",
        ));
    }

    if server_config().is_demo_mode {
        settings.ldap_bind_password = settings
            .ldap_bind_password
            .map(|_| "SECRET".parse().unwrap());
    }

    // clone for event
    let after = settings.clone();
    update_current_settings(&appstate.pool, settings).await?;
    if let Some(license_key) = &license {
        update_cached_license(license_key.as_deref())?;
        debug!("Updated cached license after saving settings patch");
    }

    // If SMTP configuration changed (e.g. server/port/sender toggled),
    // push updated password-reset visibility to all connected proxies.
    if before.smtp_configured() != after.smtp_configured()
        && let Ok(enterprise_settings) = EnterpriseSettings::get(&appstate.pool).await
    {
        let display_password_reset = enterprise_settings.edge_can_display_password_reset();
        if let Err(err) = appstate
            .proxy_control_tx
            .send(ProxyControlMessage::BroadcastPublicSettings {
                display_password_reset,
                display_download_step: enterprise_settings.display_download_step,
            })
            .await
        {
            error!("Failed to broadcast PublicSettings after SMTP config change: {err:?}");
        }
    }

    info!("Admin {} patched settings", session.user.username);
    appstate.emit_event(ApiEvent {
        context,
        event: Box::new(ApiEventType::SettingsUpdatedPartial { before, after }),
    })?;
    Ok(ApiResponse::default())
}

pub(crate) async fn test_ldap_settings(_admin: AdminRole, _license: LicenseInfo) -> ApiResult {
    debug!("Testing LDAP connection");
    if server_config().is_demo_mode {
        return Ok(ApiResponse::with_status(StatusCode::OK));
    }
    match LDAPConnection::create().await {
        Ok(_) => {
            debug!("LDAP connected successfully");
            Ok(ApiResponse::with_status(StatusCode::OK))
        }
        Err(err) => {
            debug!("LDAP connection rejected: {err}");
            Ok(ApiResponse::with_status(StatusCode::BAD_REQUEST))
        }
    }
}

fn demo_ldap_dry_run_result() -> LdapDryRunResult {
    LdapDryRunResult {
        defguard: vec![
            LdapDryRunUser {
                username: "j.smith".to_string(),
                email: "j.smith@example.com".to_string(),
                first_name: "John".to_string(),
                last_name: "Smith".to_string(),
                action: LdapDryRunAction::Add,
            },
            LdapDryRunUser {
                username: "a.johnson".to_string(),
                email: "a.johnson@example.com".to_string(),
                first_name: "Anna".to_string(),
                last_name: "Johnson".to_string(),
                action: LdapDryRunAction::Add,
            },
            LdapDryRunUser {
                username: "p.brown".to_string(),
                email: "p.brown@example.com".to_string(),
                first_name: "Peter".to_string(),
                last_name: "Brown".to_string(),
                action: LdapDryRunAction::Remove,
            },
        ],
        ldap: vec![
            LdapDryRunUser {
                username: "m.davis".to_string(),
                email: "m.davis@example.com".to_string(),
                first_name: "Maria".to_string(),
                last_name: "Davis".to_string(),
                action: LdapDryRunAction::Add,
            },
            LdapDryRunUser {
                username: "t.wilson".to_string(),
                email: "t.wilson@example.com".to_string(),
                first_name: "Thomas".to_string(),
                last_name: "Wilson".to_string(),
                action: LdapDryRunAction::Remove,
            },
            LdapDryRunUser {
                username: "k.miller".to_string(),
                email: "k.miller@example.com".to_string(),
                first_name: "Kate".to_string(),
                last_name: "Miller".to_string(),
                action: LdapDryRunAction::Remove,
            },
        ],
    }
}

/// Tests the LDAP connection using the provided (not yet saved) settings.
pub(crate) async fn test_submitted_ldap_settings(
    _admin: AdminRole,
    _license: LicenseInfo,
    Json(_settings): Json<Settings>,
) -> ApiResult {
    debug!("Testing LDAP connection with provided settings");
    if server_config().is_demo_mode {
        return Ok(ApiResponse::json(
            demo_ldap_dry_run_result(),
            StatusCode::OK,
        ));
    }
    match LDAPConnection::create_with_settings(_settings).await {
        Ok(_) => {
            debug!("LDAP connected successfully");
            Ok(ApiResponse::with_status(StatusCode::OK))
        }
        Err(err) => {
            debug!("LDAP connection rejected: {err}");
            Ok(ApiResponse::with_status(StatusCode::BAD_REQUEST))
        }
    }
}

/// Previews the user changes a full LDAP sync would make using the provided (not yet saved)
/// settings. This is strictly read-only: nothing is imported, removed or persisted.
pub(crate) async fn ldap_dry_run(
    _admin: AdminRole,
    _license: LicenseInfo,
    State(appstate): State<AppState>,
    Json(settings): Json<Settings>,
) -> ApiResult {
    debug!("Performing LDAP dry run with provided settings");

    if server_config().is_demo_mode {
        return Ok(ApiResponse::json(
            demo_ldap_dry_run_result(),
            StatusCode::OK,
        ));
    }

    let authority = if settings.ldap_is_authoritative {
        Authority::LDAP
    } else {
        Authority::Defguard
    };

    let mut connection = match LDAPConnection::create_with_settings(settings).await {
        Ok(connection) => connection,
        Err(err) => {
            debug!("LDAP dry run connection rejected: {err}");
            return Ok(ApiResponse::with_status(StatusCode::BAD_REQUEST));
        }
    };

    match connection.dry_run(&appstate.pool, authority).await {
        Ok(result) => {
            debug!("LDAP dry run completed successfully");
            Ok(ApiResponse::json(result, StatusCode::OK))
        }
        Err(err) => {
            debug!("LDAP dry run failed: {err}");
            Ok(ApiResponse::with_status(StatusCode::BAD_REQUEST))
        }
    }
}
