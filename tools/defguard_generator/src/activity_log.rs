use anyhow::Result;
use chrono::{Duration, Utc};
use defguard_common::db::{
    Id, NoId,
    models::{Device, MFAMethod, User, WireguardNetwork},
};
use defguard_core::{
    db::models::activity_log::{
        ActivityLogEvent, ActivityLogModule, EventType,
        metadata::{
            LoginFailedMetadata, MfaLoginFailedMetadata, MfaLoginMetadata, VpnClientMetadata,
            VpnClientMfaMetadata,
        },
    },
    events::ClientMFAMethod,
};
use defguard_event_logger::{
    description::{get_defguard_event_description, get_vpn_event_description},
    message::{DefguardEvent, VpnEvent},
};
use rand::{Rng, rngs::ThreadRng, seq::SliceRandom};
use sqlx::PgPool;
use tracing::info;

use crate::{user_devices::prepare_user_devices, users::prepare_users};

pub const DEFAULT_NUM_EVENTS: usize = 20;
pub const DEFAULT_TIME_SPAN_MINUTES: i64 = 1;
pub const DEFAULT_NUM_USERS: usize = 10;

const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
     Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) \
     Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like \
     Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) \
     Chrome/126.0.0.0 Mobile Safari/537.36",
];

#[derive(Debug)]
pub struct ActivityLogGeneratorConfig {
    pub num_events: usize,
    pub time_span_minutes: i64,
    pub num_users: usize,
}

impl Default for ActivityLogGeneratorConfig {
    fn default() -> Self {
        Self {
            num_events: DEFAULT_NUM_EVENTS,
            time_span_minutes: DEFAULT_TIME_SPAN_MINUTES,
            num_users: DEFAULT_NUM_USERS,
        }
    }
}

#[derive(Clone, Copy)]
enum EventKind {
    Login,
    Logout,
    MfaLogin,
    LoginFailed,
    MfaLoginFailed,
    RecoveryCodeUsed,
    PasswordChanged,
    MfaTotpEnabled,
    MfaTotpDisabled,
    MfaEmailEnabled,
    MfaEmailDisabled,
    VpnConnected,
    VpnDisconnected,
    VpnMfaConnected,
    VpnMfaDisconnected,
    VpnMfaSuccess,
}

struct GeneratedEvent {
    module: ActivityLogModule,
    event_type: EventType,
    description: Option<String>,
    metadata: Option<serde_json::Value>,
    location: Option<String>,
    device: String,
}

pub async fn generate_activity_log(
    pool: &PgPool,
    config: ActivityLogGeneratorConfig,
) -> Result<()> {
    info!("Running activity log generator with config: {config:#?}");

    let mut rng = rand::thread_rng();

    let mut users = prepare_users(pool, &mut rng, config.num_users.max(1)).await?;
    users.shuffle(&mut rng);

    let mut user_devices: Vec<(User<Id>, Device<Id>)> = Vec::with_capacity(users.len());
    for user in users {
        let device = prepare_user_devices(pool, &mut rng, &user, 1)
            .await?
            .into_iter()
            .next()
            .expect("prepare_user_devices always returns at least one device");
        user_devices.push((user, device));
    }

    let locations = WireguardNetwork::all(pool).await?;
    let vpn_available = !locations.is_empty();
    if !vpn_available {
        info!("No VPN locations found, skipping VPN-related events");
    }

    let kind_pool = build_kind_pool(vpn_available);

    let now = Utc::now().naive_utc();
    let span_seconds = Duration::minutes(config.time_span_minutes.max(1))
        .num_seconds()
        .max(1);

    info!("Generating {} activity log events", config.num_events);

    for _ in 0..config.num_events {
        let (user, device) = user_devices
            .choose(&mut rng)
            .expect("user_devices is non-empty");
        let kind = *kind_pool.choose(&mut rng).expect("kind_pool is non-empty");

        let timestamp = now - Duration::seconds(rng.gen_range(0..span_seconds));

        let generated = build_event(&mut rng, user, device, &locations, kind);

        let event = ActivityLogEvent {
            id: NoId,
            timestamp,
            user_id: user.id,
            username: user.username.clone(),
            location: generated.location,
            ip: None,
            event: generated.event_type,
            module: generated.module,
            device: generated.device,
            description: generated.description,
            metadata: generated.metadata,
        };

        event.save(pool).await?;
    }

    info!("Finished generating activity log events");

    Ok(())
}

fn build_kind_pool(vpn_available: bool) -> Vec<EventKind> {
    use EventKind::*;

    let mut weighted: Vec<(EventKind, u8)> = vec![
        (Login, 8),
        (Logout, 6),
        (MfaLogin, 6),
        (LoginFailed, 3),
        (MfaLoginFailed, 2),
        (RecoveryCodeUsed, 1),
        (PasswordChanged, 1),
        (MfaTotpEnabled, 1),
        (MfaTotpDisabled, 1),
        (MfaEmailEnabled, 1),
        (MfaEmailDisabled, 1),
    ];

    if vpn_available {
        weighted.extend([
            (VpnConnected, 8),
            (VpnDisconnected, 8),
            (VpnMfaConnected, 4),
            (VpnMfaDisconnected, 4),
            (VpnMfaSuccess, 3),
        ]);
    }

    weighted
        .into_iter()
        .flat_map(|(kind, weight)| std::iter::repeat_n(kind, weight as usize))
        .collect()
}

fn build_event(
    rng: &mut ThreadRng,
    user: &User<Id>,
    device: &Device<Id>,
    locations: &[WireguardNetwork<Id>],
    kind: EventKind,
) -> GeneratedEvent {
    let user_agent = random_user_agent(rng).to_string();

    let defguard = |event_type: EventType,
                    metadata: Option<serde_json::Value>,
                    description: Option<String>|
     -> GeneratedEvent {
        GeneratedEvent {
            module: ActivityLogModule::Defguard,
            event_type,
            description,
            metadata,
            location: None,
            device: user_agent.clone(),
        }
    };

    match kind {
        EventKind::Login => defguard(
            EventType::UserLogin,
            None,
            get_defguard_event_description(&DefguardEvent::UserLogin),
        ),
        EventKind::Logout => defguard(
            EventType::UserLogout,
            None,
            get_defguard_event_description(&DefguardEvent::UserLogout),
        ),
        EventKind::MfaLogin => {
            let mfa_method = random_mfa_method(rng);
            defguard(
                EventType::UserMfaLogin,
                serde_json::to_value(MfaLoginMetadata { mfa_method }).ok(),
                get_defguard_event_description(&DefguardEvent::UserMfaLogin { mfa_method }),
            )
        }
        EventKind::LoginFailed => {
            let message = format!("Authentication for {} failed: invalid password", user.username);
            defguard(
                EventType::UserLoginFailed,
                serde_json::to_value(LoginFailedMetadata {
                    message: message.clone(),
                })
                .ok(),
                get_defguard_event_description(&DefguardEvent::UserLoginFailed { message }),
            )
        }
        EventKind::MfaLoginFailed => {
            let (mfa_method, message) = if rng.r#gen::<bool>() {
                (
                    MFAMethod::OneTimePassword,
                    "TOTP code verification failed".to_string(),
                )
            } else {
                (
                    MFAMethod::Email,
                    "Email code verification failed".to_string(),
                )
            };
            defguard(
                EventType::UserMfaLoginFailed,
                serde_json::to_value(MfaLoginFailedMetadata {
                    mfa_method,
                    message: message.clone(),
                })
                .ok(),
                get_defguard_event_description(&DefguardEvent::UserMfaLoginFailed {
                    mfa_method,
                    message,
                }),
            )
        }
        EventKind::RecoveryCodeUsed => defguard(
            EventType::RecoveryCodeUsed,
            None,
            get_defguard_event_description(&DefguardEvent::RecoveryCodeUsed),
        ),
        EventKind::PasswordChanged => defguard(
            EventType::PasswordChanged,
            None,
            get_defguard_event_description(&DefguardEvent::PasswordChanged),
        ),
        EventKind::MfaTotpEnabled => defguard(
            EventType::MfaTotpEnabled,
            None,
            get_defguard_event_description(&DefguardEvent::MfaTotpEnabled),
        ),
        EventKind::MfaTotpDisabled => defguard(
            EventType::MfaTotpDisabled,
            None,
            get_defguard_event_description(&DefguardEvent::MfaTotpDisabled),
        ),
        EventKind::MfaEmailEnabled => defguard(
            EventType::MfaEmailEnabled,
            None,
            get_defguard_event_description(&DefguardEvent::MfaEmailEnabled),
        ),
        EventKind::MfaEmailDisabled => defguard(
            EventType::MfaEmailDisabled,
            None,
            get_defguard_event_description(&DefguardEvent::MfaEmailDisabled),
        ),
        EventKind::VpnConnected => {
            build_vpn_event(rng, device, locations, EventType::VpnClientConnected)
        }
        EventKind::VpnDisconnected => {
            build_vpn_event(rng, device, locations, EventType::VpnClientDisconnected)
        }
        EventKind::VpnMfaConnected => {
            build_vpn_event(rng, device, locations, EventType::VpnClientMfaConnected)
        }
        EventKind::VpnMfaDisconnected => {
            build_vpn_event(rng, device, locations, EventType::VpnClientMfaDisconnected)
        }
        EventKind::VpnMfaSuccess => {
            build_vpn_event(rng, device, locations, EventType::VpnClientMfaSuccess)
        }
    }
}

fn build_vpn_event(
    rng: &mut ThreadRng,
    device: &Device<Id>,
    locations: &[WireguardNetwork<Id>],
    event_type: EventType,
) -> GeneratedEvent {
    let location = locations
        .choose(rng)
        .expect("build_vpn_event called without any locations")
        .clone();
    let device = device.clone();

    let location_name = Some(location.name.clone());
    let device_str = match event_type {
        EventType::VpnClientMfaSuccess => device.to_string(),
        _ => format!("{} (ID {})", device.name, device.id),
    };

    let (description, metadata) = match event_type {
        EventType::VpnClientConnected => (
            get_vpn_event_description(&VpnEvent::ConnectedToLocation {
                location: location.clone(),
                device: device.clone(),
            }),
            serde_json::to_value(VpnClientMetadata { location, device }).ok(),
        ),
        EventType::VpnClientDisconnected => (
            get_vpn_event_description(&VpnEvent::DisconnectedFromLocation {
                location: location.clone(),
                device: device.clone(),
            }),
            serde_json::to_value(VpnClientMetadata { location, device }).ok(),
        ),
        EventType::VpnClientMfaConnected => (
            get_vpn_event_description(&VpnEvent::MfaConnectedToLocation {
                location: location.clone(),
                device: device.clone(),
            }),
            serde_json::to_value(VpnClientMetadata { location, device }).ok(),
        ),
        EventType::VpnClientMfaDisconnected => (
            get_vpn_event_description(&VpnEvent::MfaDisconnectedFromLocation {
                location: location.clone(),
                device: device.clone(),
            }),
            serde_json::to_value(VpnClientMetadata { location, device }).ok(),
        ),
        EventType::VpnClientMfaSuccess => {
            let method = random_client_mfa_method(rng);
            (
                get_vpn_event_description(&VpnEvent::ClientMfaSuccess {
                    location: location.clone(),
                    device: device.clone(),
                    method,
                }),
                serde_json::to_value(VpnClientMfaMetadata {
                    location,
                    device,
                    method,
                })
                .ok(),
            )
        }
        _ => unreachable!("build_vpn_event called with a non-VPN event type"),
    };

    GeneratedEvent {
        module: ActivityLogModule::Vpn,
        event_type,
        description,
        metadata,
        location: location_name,
        device: device_str,
    }
}

fn random_user_agent(rng: &mut ThreadRng) -> &'static str {
    USER_AGENTS.choose(rng).expect("USER_AGENTS is non-empty")
}

fn random_mfa_method(rng: &mut ThreadRng) -> MFAMethod {
    *[
        MFAMethod::OneTimePassword,
        MFAMethod::Webauthn,
        MFAMethod::Email,
    ]
    .choose(rng)
    .expect("slice is non-empty")
}

fn random_client_mfa_method(rng: &mut ThreadRng) -> ClientMFAMethod {
    *[
        ClientMFAMethod::Totp,
        ClientMFAMethod::Email,
        ClientMFAMethod::Biometric,
        ClientMFAMethod::MobileApprove,
    ]
    .choose(rng)
    .expect("slice is non-empty")
}
