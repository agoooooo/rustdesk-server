use crate::{
    common::{get_arg, get_arg_opt},
    database::{AddressBookPermission, Database, DelegatedRole, PeerClaimResult, User},
    peer::PeerMap,
};
use axum::{
    extract::{Extension, Path, Query},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use hbb_common::{anyhow, log, tokio};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    time::Instant,
};
use tower_http::cors::CorsLayer;

#[derive(Clone)]
struct ApiState {
    db: Database,
    jwt_secret: String,
    peer_map: PeerMap,
    started_at: Instant,
    api_address: SocketAddr,
    rendezvous_address: SocketAddr,
    relay_servers: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<usize>,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginRequest {
    username: String,
    password: String,
    #[serde(default)]
    #[allow(dead_code)]
    id: String,
    #[serde(default)]
    #[allow(dead_code)]
    uuid: String,
    #[serde(default)]
    #[allow(dead_code)]
    device_info: Value,
    #[serde(default)]
    #[allow(dead_code)]
    auto_login: bool,
    #[serde(default)]
    #[allow(dead_code)]
    r#type: String,
}

#[derive(Deserialize)]
struct DeviceIdentity {
    id: String,
    uuid: String,
}

#[derive(Deserialize)]
struct RegisterUserRequest {
    name: String,
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct Pagination {
    current: Option<i64>,
    #[serde(rename = "pageSize")]
    page_size: Option<i64>,
    status: Option<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuditLogQuery {
    current: Option<i64>,
    page_size: Option<i64>,
    actor: Option<String>,
    action: Option<String>,
    resource_type: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AutomationTaskQuery {
    current: Option<i64>,
    page_size: Option<i64>,
    task_id: Option<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AutomationTaskRequest {
    name: String,
    #[serde(default)]
    description: String,
    script: String,
    #[serde(default)]
    published: bool,
    #[serde(default)]
    interval_seconds: i64,
    #[serde(default = "default_task_max_runs")]
    max_runs: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AutomationDeviceIdentity {
    id: String,
    uuid: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AutomationExecutionResult {
    id: String,
    uuid: String,
    status: String,
    #[serde(default)]
    result: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateApiTokenRequest {
    name: String,
    scopes: Vec<String>,
    expires_in_days: i64,
}

#[derive(Deserialize)]
struct DelegatedRoleRequest {
    name: String,
    #[serde(default)]
    description: String,
    permissions: Vec<String>,
    #[serde(default)]
    user_group_ids: Vec<i64>,
    #[serde(default)]
    device_group_ids: Vec<i64>,
    #[serde(default)]
    user_ids: Vec<i64>,
}

#[derive(Deserialize)]
struct CreateUser {
    name: String,
    email: String,
    password: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    is_admin: bool,
}

#[derive(Deserialize)]
struct UpdateUser {
    email: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    is_admin: bool,
    status: i64,
    password: Option<String>,
}

#[derive(Deserialize)]
struct CreateDeviceGroup {
    name: String,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize)]
struct UpdateDeviceGroup {
    name: String,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize)]
struct UpdateDeviceGroupPeers {
    device_ids: Vec<String>,
}

#[derive(Deserialize)]
struct CreateUserGroup {
    name: String,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize)]
struct UpdateUserGroup {
    name: String,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize)]
struct UpdateUserGroupMembers {
    user_ids: Vec<i64>,
}

#[derive(Deserialize)]
struct AddressBookRequest {
    name: String,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize)]
struct AddressBookEntryRequest {
    device_id: String,
    #[serde(default)]
    alias: String,
    #[serde(default)]
    note: String,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Deserialize)]
struct AddressBookPermissionsRequest {
    permissions: Vec<AddressBookPermission>,
}

#[derive(Debug, Serialize)]
struct UserPayload {
    id: i64,
    name: String,
    display_name: String,
    email: String,
    avatar: String,
    note: String,
    is_admin: bool,
    is_delegated_admin: bool,
    delegated_permissions: Vec<String>,
    status: i64,
}

impl From<User> for UserPayload {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            name: user.name,
            display_name: user.display_name,
            email: user.email,
            avatar: user.avatar,
            note: user.note,
            is_admin: user.is_admin,
            is_delegated_admin: false,
            delegated_permissions: Vec::new(),
            status: user.status,
        }
    }
}

pub(crate) async fn start(
    peer_map: PeerMap,
    bind_addr: Option<IpAddr>,
    port: u16,
    rendezvous_bind_addr: Option<IpAddr>,
    rendezvous_port: u16,
) -> hbb_common::ResultType<tokio::task::JoinHandle<hbb_common::ResultType<()>>> {
    let db = peer_map.db.clone();
    let jwt_secret = db.get_or_create_api_secret().await?;
    bootstrap_admin(&db).await?;
    let api_address = SocketAddr::new(bind_addr.unwrap_or(IpAddr::from([0, 0, 0, 0])), port);
    let rendezvous_address = SocketAddr::new(
        rendezvous_bind_addr.unwrap_or(IpAddr::from([0, 0, 0, 0])),
        rendezvous_port,
    );
    let state = ApiState {
        db,
        jwt_secret,
        peer_map,
        started_at: Instant::now(),
        api_address,
        rendezvous_address,
        relay_servers: get_arg("relay-servers")
            .split(',')
            .map(str::trim)
            .filter(|server| !server.is_empty() && server.len() <= 300)
            .map(str::to_owned)
            .collect(),
    };
    let app = Router::new()
        .route("/api/login", post(login))
        .route("/api/register", post(register_user))
        .route("/api/login-options", get(login_options))
        .route("/api/currentUser", post(current_user))
        .route("/api/logout", post(logout))
        .route("/api/users", get(list_users))
        .route("/api/peers", get(list_peers))
        .route("/api/device-group/accessible", get(list_groups))
        .route("/api/admin/peers", get(list_admin_peers))
        .route("/api/admin/online-devices", get(list_admin_online_devices))
        .route("/api/admin/peers/:id", put(update_peer))
        .route(
            "/api/admin/device-groups",
            get(list_admin_device_groups).post(create_device_group),
        )
        .route(
            "/api/admin/device-groups/:id",
            put(update_device_group).delete(delete_device_group),
        )
        .route(
            "/api/admin/device-groups/:id/devices",
            get(list_device_group_peers).put(update_device_group_peers),
        )
        .route(
            "/api/user-group/accessible",
            get(list_accessible_user_groups),
        )
        .route(
            "/api/admin/user-groups",
            get(list_admin_user_groups).post(create_user_group),
        )
        .route(
            "/api/admin/user-groups/:id",
            put(update_user_group).delete(delete_user_group),
        )
        .route(
            "/api/admin/user-groups/:id/users",
            get(list_user_group_members).put(update_user_group_members),
        )
        .route("/api/address-books", get(list_accessible_address_books))
        .route(
            "/api/personal/address-books",
            get(list_personal_address_books).post(create_personal_address_book),
        )
        .route(
            "/api/personal/address-books/:id",
            put(update_personal_address_book).delete(delete_personal_address_book),
        )
        .route(
            "/api/address-books/:id/entries",
            get(list_accessible_address_book_entries).post(create_address_book_entry),
        )
        .route(
            "/api/address-books/:id/entries/:entry_id",
            put(update_address_book_entry).delete(delete_address_book_entry),
        )
        .route(
            "/api/address-books/:id/permissions",
            get(list_address_book_permissions).put(update_address_book_permissions),
        )
        .route(
            "/api/admin/address-books",
            get(list_admin_address_books).post(create_address_book),
        )
        .route(
            "/api/admin/address-books/:id",
            put(update_address_book).delete(delete_address_book),
        )
        .route("/api/admin/users", get(list_admin_users).post(create_user))
        .route("/api/admin/users/:id", put(update_user).delete(delete_user))
        .route(
            "/api/admin/delegated-roles",
            get(list_admin_delegated_roles).post(create_admin_delegated_role),
        )
        .route(
            "/api/admin/delegated-roles/:id",
            put(update_admin_delegated_role).delete(delete_admin_delegated_role),
        )
        .route("/api/admin/audit-logs", get(list_admin_audit_logs))
        .route(
            "/api/admin/tasks",
            get(list_admin_automation_tasks).post(create_automation_task),
        )
        .route(
            "/api/admin/tasks/:id",
            put(update_automation_task).delete(delete_automation_task),
        )
        .route(
            "/api/admin/task-executions",
            get(list_admin_automation_executions),
        )
        .route("/api/tasks", get(list_available_automation_tasks))
        .route(
            "/api/tasks/:id/executions",
            post(start_automation_execution),
        )
        .route(
            "/api/tasks/executions/:execution_id/complete",
            post(finish_automation_execution),
        )
        .route("/api/admin/server-status", get(get_admin_server_status))
        .route(
            "/api/admin/api-tokens",
            get(list_admin_api_tokens).post(create_admin_api_token),
        )
        .route(
            "/api/admin/api-tokens/:id",
            axum::routing::delete(revoke_admin_api_token),
        )
        .layer(Extension(state))
        .layer(CorsLayer::permissive());
    let listener = tokio::net::TcpListener::bind(api_address).await?;
    let listener = listener.into_std()?;
    log::info!("User API listening on http://{}", api_address);
    let server = axum::Server::from_tcp(listener)?;
    Ok(tokio::spawn(async move {
        server
            .serve(app.into_make_service())
            .await
            .map_err(Into::into)
    }))
}

async fn get_admin_server_status(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    require_admin_session(&state, &headers).await?;
    let counts = state.db.service_resource_counts().await.map_err(|error| {
        log::error!("Failed to query service resource counts: {}", error);
        ApiError::internal()
    })?;
    let online_devices = state.peer_map.online_count().await;
    Ok(Json(json!({
        "server_version": crate::version::VERSION,
        "api_address": state.api_address.to_string(),
        "rendezvous_address": state.rendezvous_address.to_string(),
        "relay_servers": state.relay_servers,
        "uptime_seconds": state.started_at.elapsed().as_secs(),
        "resources": {
            "total_users": counts.total_users,
            "active_users": counts.active_users,
            "total_devices": counts.total_devices,
            "online_devices": online_devices,
            "device_groups": counts.device_groups,
            "user_groups": counts.user_groups,
        },
    })))
}

async fn bootstrap_admin(db: &Database) -> hbb_common::ResultType<()> {
    let username = get_arg_opt("ADMIN_USER");
    let password = get_arg_opt("ADMIN_PASSWORD");
    match (username, password) {
        (None, None) => Ok(()),
        (Some(username), Some(password)) => {
            validate_name(&username).map_err(|error| anyhow::anyhow!(error.message))?;
            validate_password(&password).map_err(|error| anyhow::anyhow!(error.message))?;
            if db.get_user_by_name(&username).await?.is_none() {
                let password_hash = hash(password, DEFAULT_COST)?;
                db.create_user(
                    &username,
                    "管理员",
                    &format!("{username}@localhost"),
                    &password_hash,
                    true,
                )
                .await?;
                log::info!("Bootstrapped API administrator '{}'", username);
            }
            Ok(())
        }
        _ => Err(anyhow::anyhow!(
            "ADMIN_USER and ADMIN_PASSWORD must be configured together"
        )),
    }
}

async fn login(
    Extension(state): Extension<ApiState>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<Value>, ApiError> {
    let user = state
        .db
        .get_user_by_name(request.username.trim())
        .await
        .map_err(|error| {
            log::error!("Failed to query login user: {}", error);
            ApiError::internal()
        })?;
    let Some(user) = user else {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "Invalid username or password",
        ));
    };
    let password_valid = verify(&request.password, &user.password_hash).map_err(|error| {
        log::error!("Failed to verify login password: {}", error);
        ApiError::internal()
    })?;
    if !password_valid || user.status != 1 {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "Invalid username or password",
        ));
    }
    if !request.id.is_empty() && !request.uuid.is_empty() {
        claim_or_defer_login_device(&state.db, &request.id, &request.uuid, &user.name).await?;
    }
    let token = encode(
        &Header::default(),
        &Claims {
            sub: user.name.clone(),
            exp: None,
        },
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    )
    .map_err(|error| {
        log::error!("Failed to create API access token: {}", error);
        ApiError::internal()
    })?;
    let user_payload = user_payload_with_delegated_permissions(&state, user).await?;
    Ok(Json(json!({
        "type": "access_token",
        "access_token": token,
        "user": user_payload,
    })))
}

async fn claim_or_defer_login_device(
    db: &Database,
    id: &str,
    encoded_uuid: &str,
    owner: &str,
) -> Result<(), ApiError> {
    if id.trim() != id || id.len() > crate::peer::MAX_PEER_ID_LEN || encoded_uuid.len() > 512 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Invalid device identity",
        ));
    }
    let uuid = base64::decode(encoded_uuid)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "Invalid device identity"))?;
    let claim_result = db
        .claim_or_defer_peer(id, &uuid, owner)
        .await
        .map_err(|error| {
            log::error!("Failed to claim or defer login device: {}", error);
            ApiError::internal()
        })?;
    match claim_result {
        PeerClaimResult::Claimed | PeerClaimResult::Pending => Ok(()),
        PeerClaimResult::OwnedByAnotherAccount => Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Device belongs to another account",
        )),
        PeerClaimResult::IdentityMismatch => Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Device identity is not registered on this server",
        )),
        PeerClaimResult::PendingForAnotherAccount => Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Device is pending registration for another account",
        )),
    }
}

async fn login_options() -> Json<Vec<String>> {
    Json(Vec::new())
}

async fn register_user(
    Extension(state): Extension<ApiState>,
    Json(request): Json<RegisterUserRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    validate_name(&request.name)?;
    validate_email(&request.email)?;
    validate_password(&request.password)?;
    let password_hash = hash(request.password, DEFAULT_COST).map_err(|error| {
        log::error!("Failed to hash self-registered user password: {}", error);
        ApiError::internal()
    })?;
    state
        .db
        .create_user(
            request.name.trim(),
            "",
            request.email.trim(),
            &password_hash,
            false,
        )
        .await
        .map_err(database_write_error)?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "message": "Account created" })),
    ))
}

async fn current_user(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    request: Option<Json<DeviceIdentity>>,
) -> Result<Json<UserPayload>, ApiError> {
    let user = authenticated_user(&state, &headers).await?;
    if let Some(Json(identity)) = request {
        if !identity.id.is_empty() && !identity.uuid.is_empty() {
            claim_or_defer_login_device(&state.db, &identity.id, &identity.uuid, &user.name)
                .await?;
        }
    }
    let user_payload = user_payload_with_delegated_permissions(&state, user).await?;
    Ok(Json(user_payload))
}

async fn user_payload_with_delegated_permissions(
    state: &ApiState,
    user: User,
) -> Result<UserPayload, ApiError> {
    let mut payload = UserPayload::from(user);
    if payload.is_admin {
        return Ok(payload);
    }
    let roles = state
        .db
        .delegated_access_for_user(payload.id)
        .await
        .map_err(|error| {
            log::error!(
                "Failed to load delegated permissions for user info: {}",
                error
            );
            ApiError::internal()
        })?;
    let mut permissions = HashSet::new();
    for role in roles {
        let role_permissions =
            serde_json::from_str::<Vec<String>>(&role.permissions).map_err(|error| {
                log::error!(
                    "Failed to decode delegated permissions for user info: {}",
                    error
                );
                ApiError::internal()
            })?;
        for permission in role_permissions {
            if !matches!(
                permission.as_str(),
                "users:read" | "users:write" | "devices:read" | "devices:write"
            ) {
                log::error!("Delegated role contains an unsupported permission");
                return Err(ApiError::internal());
            }
            if let Some(resource) = permission.strip_suffix(":write") {
                permissions.insert(format!("{resource}:read"));
            }
            permissions.insert(permission);
        }
    }
    let mut permissions = permissions.into_iter().collect::<Vec<_>>();
    permissions.sort_unstable();
    payload.is_delegated_admin = !permissions.is_empty();
    payload.delegated_permissions = permissions;
    Ok(payload)
}

async fn logout(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    authenticated_user(&state, &headers).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_users(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Query(query): Query<Pagination>,
) -> Result<Json<Value>, ApiError> {
    let user = authenticated_scoped_user(&state, &headers, "users:read").await?;
    users_response(
        &state.db,
        query,
        true,
        (!user.is_admin).then_some(user.name),
    )
    .await
}

async fn list_admin_users(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Query(query): Query<Pagination>,
) -> Result<Json<Value>, ApiError> {
    let access = require_resource_access(&state, &headers, "users:read").await?;
    if access.user.is_admin {
        return users_response(&state.db, query, false, None).await;
    }
    let current = query.current.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(100).clamp(1, 200);
    let (users, total) = state
        .db
        .list_users_in_groups(
            &access.user_group_ids,
            query.status,
            page_size,
            current.saturating_sub(1).saturating_mul(page_size),
        )
        .await
        .map_err(|error| {
            log::error!("Failed to list users in delegated groups: {}", error);
            ApiError::internal()
        })?;
    Ok(Json(json!({
        "total": total,
        "data": users.into_iter().map(UserPayload::from).collect::<Vec<_>>(),
    })))
}

async fn users_response(
    db: &Database,
    query: Pagination,
    active_only: bool,
    accessible_to: Option<String>,
) -> Result<Json<Value>, ApiError> {
    let current = query.current.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(100).clamp(1, 200);
    let status = if active_only { Some(1) } else { query.status };
    let (users, total) = if let Some(name) = accessible_to {
        let user = db.get_user_by_name(&name).await.map_err(|error| {
            log::error!("Failed to query accessible user: {}", error);
            ApiError::internal()
        })?;
        let matches = user.filter(|user| status.map_or(true, |status| user.status == status));
        let total = if matches.is_some() { 1 } else { 0 };
        let users = if current == 1 && page_size > 0 {
            matches.into_iter().collect()
        } else {
            Vec::new()
        };
        (users, total)
    } else {
        db.list_users(status, page_size, (current - 1) * page_size)
            .await
            .map_err(|error| {
                log::error!("Failed to list users: {}", error);
                ApiError::internal()
            })?
    };
    Ok(Json(json!({
        "total": total,
        "data": users.into_iter().map(UserPayload::from).collect::<Vec<_>>(),
    })))
}

async fn list_peers(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Query(query): Query<Pagination>,
) -> Result<Json<Value>, ApiError> {
    let user = authenticated_scoped_user(&state, &headers, "devices:read").await?;
    peers_response(
        &state.db,
        &state.peer_map,
        query,
        (!user.is_admin).then_some(user.name),
        None,
    )
    .await
}

async fn list_groups(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Query(query): Query<Pagination>,
) -> Result<Json<Value>, ApiError> {
    let user = authenticated_scoped_user(&state, &headers, "groups:read").await?;
    let current = query.current.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(100).clamp(1, 200);
    let (groups, total) = state
        .db
        .list_accessible_device_groups(&user.name, page_size, (current - 1) * page_size)
        .await
        .map_err(|error| {
            log::error!("Failed to list accessible device groups: {}", error);
            ApiError::internal()
        })?;
    Ok(Json(json!({
        "total": total,
        "data": groups,
        "current": current,
    })))
}

async fn list_admin_device_groups(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Query(query): Query<Pagination>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&state, &headers, "groups:read").await?;
    let current = query.current.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(100).clamp(1, 200);
    let (groups, total) = state
        .db
        .list_device_groups(page_size, (current - 1) * page_size)
        .await
        .map_err(|error| {
            log::error!("Failed to list device groups: {}", error);
            ApiError::internal()
        })?;
    Ok(Json(json!({
        "total": total,
        "data": groups,
        "current": current,
    })))
}

async fn create_device_group(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Json(request): Json<CreateDeviceGroup>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let actor = require_admin(&state, &headers, "groups:write").await?;
    validate_device_group(&request.name, &request.description)?;
    let id = state
        .db
        .create_device_group(request.name.trim(), request.description.trim())
        .await
        .map_err(device_group_write_error)?;
    record_admin_audit(
        &state,
        &actor,
        "create",
        "device_group",
        &id.to_string(),
        "Created device group",
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": id,
            "name": request.name.trim(),
            "description": request.description.trim(),
            "device_count": 0,
        })),
    ))
}

async fn update_device_group(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(request): Json<UpdateDeviceGroup>,
) -> Result<StatusCode, ApiError> {
    let actor = require_admin(&state, &headers, "groups:write").await?;
    validate_device_group(&request.name, &request.description)?;
    let updated = state
        .db
        .update_device_group(id, request.name.trim(), request.description.trim())
        .await
        .map_err(device_group_write_error)?;
    if !updated {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Device group not found",
        ));
    }
    record_admin_audit(
        &state,
        &actor,
        "update",
        "device_group",
        &id.to_string(),
        "Updated device group",
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_device_group(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let actor = require_admin(&state, &headers, "groups:write").await?;
    let deleted = state.db.delete_device_group(id).await.map_err(|error| {
        log::error!("Failed to delete device group: {}", error);
        ApiError::internal()
    })?;
    if !deleted {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Device group not found",
        ));
    }
    record_admin_audit(
        &state,
        &actor,
        "delete",
        "device_group",
        &id.to_string(),
        "Deleted device group",
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_device_group_peers(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&state, &headers, "groups:read").await?;
    let peers = state
        .db
        .list_device_group_peers(id)
        .await
        .map_err(|error| {
            log::error!("Failed to list device group members: {}", error);
            ApiError::internal()
        })?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Device group not found"))?;
    Ok(Json(json!({ "device_ids": peers })))
}

async fn update_device_group_peers(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(request): Json<UpdateDeviceGroupPeers>,
) -> Result<StatusCode, ApiError> {
    let actor = require_admin(&state, &headers, "groups:write").await?;
    if request.device_ids.len() > 2000 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "A device group can contain at most 2000 devices",
        ));
    }
    let mut unique_ids = HashSet::with_capacity(request.device_ids.len());
    for device_id in &request.device_ids {
        if device_id.trim().is_empty()
            || device_id.len() > crate::peer::MAX_PEER_ID_LEN
            || !unique_ids.insert(device_id)
        {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "Invalid or duplicate device ID",
            ));
        }
        if state
            .db
            .get_peer(device_id)
            .await
            .map_err(|error| {
                log::error!("Failed to validate device group member: {}", error);
                ApiError::internal()
            })?
            .is_none()
        {
            return Err(ApiError::new(StatusCode::BAD_REQUEST, "Device not found"));
        }
    }
    let updated = state
        .db
        .set_device_group_peers(id, &request.device_ids)
        .await
        .map_err(|error| {
            log::error!("Failed to update device group members: {}", error);
            ApiError::internal()
        })?;
    if !updated {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Device group not found",
        ));
    }
    record_admin_audit(
        &state,
        &actor,
        "replace_members",
        "device_group",
        &id.to_string(),
        "Replaced device group devices",
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn validate_device_group(name: &str, description: &str) -> Result<(), ApiError> {
    let name = name.trim();
    if name.is_empty() || name.len() > 100 || name.chars().any(char::is_control) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Device group name must be 1-100 bytes and contain no control characters",
        ));
    }
    if description.len() > 300 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Device group description must be 300 bytes or fewer",
        ));
    }
    Ok(())
}

fn device_group_write_error(error: hbb_common::anyhow::Error) -> ApiError {
    if let Some(sqlx::Error::Database(database_error)) = error.downcast_ref::<sqlx::Error>() {
        if database_error.code().as_deref() == Some("2067")
            || database_error.code().as_deref() == Some("1555")
        {
            return ApiError::new(StatusCode::CONFLICT, "Device group name already exists");
        }
    }
    log::error!("Failed to save device group: {}", error);
    ApiError::internal()
}

async fn list_accessible_user_groups(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Query(query): Query<Pagination>,
) -> Result<Json<Value>, ApiError> {
    let user = authenticated_scoped_user(&state, &headers, "groups:read").await?;
    let current = query.current.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(100).clamp(1, 200);
    let (groups, total) = state
        .db
        .list_accessible_user_groups(user.id, page_size, (current - 1) * page_size)
        .await
        .map_err(|error| {
            log::error!("Failed to list accessible user groups: {}", error);
            ApiError::internal()
        })?;
    Ok(Json(json!({
        "total": total,
        "data": groups,
        "current": current,
    })))
}

async fn list_admin_user_groups(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Query(query): Query<Pagination>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&state, &headers, "groups:read").await?;
    let current = query.current.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(100).clamp(1, 200);
    let (groups, total) = state
        .db
        .list_user_groups(page_size, (current - 1) * page_size)
        .await
        .map_err(|error| {
            log::error!("Failed to list user groups: {}", error);
            ApiError::internal()
        })?;
    Ok(Json(json!({
        "total": total,
        "data": groups,
        "current": current,
    })))
}

async fn create_user_group(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Json(request): Json<CreateUserGroup>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let actor = require_admin(&state, &headers, "groups:write").await?;
    validate_user_group(&request.name, &request.description)?;
    let id = state
        .db
        .create_user_group(request.name.trim(), request.description.trim())
        .await
        .map_err(user_group_write_error)?;
    record_admin_audit(
        &state,
        &actor,
        "create",
        "user_group",
        &id.to_string(),
        "Created user group",
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": id,
            "name": request.name.trim(),
            "description": request.description.trim(),
            "member_count": 0,
        })),
    ))
}

async fn update_user_group(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(request): Json<UpdateUserGroup>,
) -> Result<StatusCode, ApiError> {
    let actor = require_admin(&state, &headers, "groups:write").await?;
    validate_user_group(&request.name, &request.description)?;
    let updated = state
        .db
        .update_user_group(id, request.name.trim(), request.description.trim())
        .await
        .map_err(user_group_write_error)?;
    if !updated {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "User group not found"));
    }
    record_admin_audit(
        &state,
        &actor,
        "update",
        "user_group",
        &id.to_string(),
        "Updated user group",
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_user_group(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let actor = require_admin(&state, &headers, "groups:write").await?;
    let deleted = state.db.delete_user_group(id).await.map_err(|error| {
        log::error!("Failed to delete user group: {}", error);
        ApiError::internal()
    })?;
    if !deleted {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "User group not found"));
    }
    record_admin_audit(
        &state,
        &actor,
        "delete",
        "user_group",
        &id.to_string(),
        "Deleted user group",
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_user_group_members(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&state, &headers, "groups:read").await?;
    let user_ids = state
        .db
        .list_user_group_members(id)
        .await
        .map_err(|error| {
            log::error!("Failed to list user group members: {}", error);
            ApiError::internal()
        })?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "User group not found"))?;
    Ok(Json(json!({ "user_ids": user_ids })))
}

async fn update_user_group_members(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(request): Json<UpdateUserGroupMembers>,
) -> Result<StatusCode, ApiError> {
    let actor = require_admin(&state, &headers, "groups:write").await?;
    if request.user_ids.len() > 2000 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "A user group can contain at most 2000 users",
        ));
    }
    let mut unique_ids = HashSet::with_capacity(request.user_ids.len());
    for user_id in &request.user_ids {
        if *user_id <= 0 || !unique_ids.insert(*user_id) {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "Invalid or duplicate user ID",
            ));
        }
        let exists = state
            .db
            .get_user_by_id(*user_id)
            .await
            .map_err(|error| {
                log::error!("Failed to validate user group member: {}", error);
                ApiError::internal()
            })?
            .is_some_and(|user| user.status == 1);
        if !exists {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "Active user not found",
            ));
        }
    }
    let updated = state
        .db
        .set_user_group_members(id, &request.user_ids)
        .await
        .map_err(|error| {
            log::error!("Failed to update user group members: {}", error);
            ApiError::internal()
        })?;
    if !updated {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "User group not found"));
    }
    record_admin_audit(
        &state,
        &actor,
        "replace_members",
        "user_group",
        &id.to_string(),
        "Replaced user group members",
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn validate_user_group(name: &str, description: &str) -> Result<(), ApiError> {
    let name = name.trim();
    if name.is_empty() || name.len() > 100 || name.chars().any(char::is_control) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "User group name must be 1-100 bytes and contain no control characters",
        ));
    }
    if description.len() > 300 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "User group description must be 300 bytes or fewer",
        ));
    }
    Ok(())
}

fn user_group_write_error(error: hbb_common::anyhow::Error) -> ApiError {
    if let Some(sqlx::Error::Database(database_error)) = error.downcast_ref::<sqlx::Error>() {
        if database_error.code().as_deref() == Some("2067")
            || database_error.code().as_deref() == Some("1555")
        {
            return ApiError::new(StatusCode::CONFLICT, "User group name already exists");
        }
    }
    log::error!("Failed to save user group: {}", error);
    ApiError::internal()
}

async fn list_accessible_address_books(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Query(query): Query<Pagination>,
) -> Result<Json<Value>, ApiError> {
    let user = authenticated_scoped_user(&state, &headers, "address_books:read").await?;
    let current = query.current.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(100).clamp(1, 200);
    let offset = current.saturating_sub(1).saturating_mul(page_size);
    let listing = if user.is_admin {
        state.db.list_address_books(page_size, offset).await
    } else {
        state
            .db
            .list_accessible_address_books(user.id, page_size, offset)
            .await
    };
    let (books, total) = listing.map_err(|error| {
        log::error!("Failed to list accessible address books: {}", error);
        ApiError::internal()
    })?;
    Ok(Json(json!({
        "total": total,
        "data": books,
        "current": current,
    })))
}

async fn list_personal_address_books(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Query(query): Query<Pagination>,
) -> Result<Json<Value>, ApiError> {
    let user = authenticated_scoped_user(&state, &headers, "address_books:read").await?;
    let current = query.current.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(100).clamp(1, 200);
    let offset = current.saturating_sub(1).saturating_mul(page_size);
    let (books, total) = state
        .db
        .list_personal_address_books(user.id, page_size, offset)
        .await
        .map_err(|error| {
            log::error!("Failed to list personal address books: {}", error);
            ApiError::internal()
        })?;
    Ok(Json(json!({
        "total": total,
        "data": books,
        "current": current,
    })))
}

async fn create_personal_address_book(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Json(request): Json<AddressBookRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let actor = authenticated_scoped_user(&state, &headers, "address_books:write").await?;
    validate_address_book(&request.name, &request.description)?;
    let id = state
        .db
        .create_personal_address_book(actor.id, request.name.trim(), request.description.trim())
        .await
        .map_err(address_book_write_error)?;
    record_admin_audit(
        &state,
        &actor,
        "create",
        "address_book",
        &id.to_string(),
        "Created personal address book",
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": id,
            "name": request.name.trim(),
            "description": request.description.trim(),
            "permission": "manage",
            "entry_count": 0,
            "is_personal": true,
        })),
    ))
}

async fn update_personal_address_book(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(request): Json<AddressBookRequest>,
) -> Result<StatusCode, ApiError> {
    let actor = authenticated_scoped_user(&state, &headers, "address_books:write").await?;
    validate_address_book(&request.name, &request.description)?;
    let updated = state
        .db
        .update_personal_address_book(
            actor.id,
            id,
            request.name.trim(),
            request.description.trim(),
        )
        .await
        .map_err(address_book_write_error)?;
    if !updated {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Personal address book not found",
        ));
    }
    record_admin_audit(
        &state,
        &actor,
        "update",
        "address_book",
        &id.to_string(),
        "Updated personal address book",
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_personal_address_book(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let actor = authenticated_scoped_user(&state, &headers, "address_books:write").await?;
    let deleted = state
        .db
        .delete_personal_address_book(actor.id, id)
        .await
        .map_err(|error| {
            log::error!("Failed to delete personal address book: {}", error);
            ApiError::internal()
        })?;
    if !deleted {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Personal address book not found",
        ));
    }
    record_admin_audit(
        &state,
        &actor,
        "delete",
        "address_book",
        &id.to_string(),
        "Deleted personal address book",
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_admin_address_books(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Query(query): Query<Pagination>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&state, &headers, "address_books:read").await?;
    let current = query.current.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(100).clamp(1, 200);
    let offset = current.saturating_sub(1).saturating_mul(page_size);
    let (books, total) = state
        .db
        .list_address_books(page_size, offset)
        .await
        .map_err(|error| {
            log::error!("Failed to list address books: {}", error);
            ApiError::internal()
        })?;
    Ok(Json(json!({
        "total": total,
        "data": books,
        "current": current,
    })))
}

async fn create_address_book(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Json(request): Json<AddressBookRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let actor = require_admin(&state, &headers, "address_books:write").await?;
    validate_address_book(&request.name, &request.description)?;
    let id = state
        .db
        .create_address_book(request.name.trim(), request.description.trim())
        .await
        .map_err(address_book_write_error)?;
    record_admin_audit(
        &state,
        &actor,
        "create",
        "address_book",
        &id.to_string(),
        "Created shared address book",
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": id,
            "name": request.name.trim(),
            "description": request.description.trim(),
            "permission": "manage",
            "entry_count": 0,
        })),
    ))
}

async fn update_address_book(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(request): Json<AddressBookRequest>,
) -> Result<StatusCode, ApiError> {
    let actor = require_admin(&state, &headers, "address_books:write").await?;
    validate_address_book(&request.name, &request.description)?;
    let updated = state
        .db
        .update_address_book(id, request.name.trim(), request.description.trim())
        .await
        .map_err(address_book_write_error)?;
    if !updated {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Address book not found",
        ));
    }
    record_admin_audit(
        &state,
        &actor,
        "update",
        "address_book",
        &id.to_string(),
        "Updated shared address book",
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_address_book(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let actor = require_admin(&state, &headers, "address_books:write").await?;
    let deleted = state.db.delete_address_book(id).await.map_err(|error| {
        log::error!("Failed to delete address book: {}", error);
        ApiError::internal()
    })?;
    if !deleted {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Address book not found",
        ));
    }
    record_admin_audit(
        &state,
        &actor,
        "delete",
        "address_book",
        &id.to_string(),
        "Deleted shared address book",
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_accessible_address_book_entries(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    require_address_book_access(&state, &headers, id, "read").await?;
    address_book_entries_response(&state.db, id).await
}

async fn address_book_entries_response(db: &Database, id: i64) -> Result<Json<Value>, ApiError> {
    let entries = db
        .list_address_book_entries(id)
        .await
        .map_err(|error| {
            log::error!("Failed to list address book entries: {}", error);
            ApiError::internal()
        })?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Address book not found"))?;
    let mut data = Vec::with_capacity(entries.len());
    for entry in entries {
        let tags = serde_json::from_str::<Vec<String>>(&entry.tags).map_err(|error| {
            log::error!("Failed to decode address book tags: {}", error);
            ApiError::internal()
        })?;
        data.push(json!({
            "id": entry.id,
            "device_id": entry.device_id,
            "alias": entry.alias,
            "note": entry.note,
            "tags": tags,
        }));
    }
    Ok(Json(json!({ "data": data })))
}

async fn create_address_book_entry(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(request): Json<AddressBookEntryRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let actor = require_address_book_access(&state, &headers, id, "write").await?;
    let tags = validate_address_book_entry(&request)?;
    let entry_id = state
        .db
        .create_address_book_entry(
            id,
            request.device_id.trim(),
            request.alias.trim(),
            request.note.trim(),
            &tags,
        )
        .await
        .map_err(address_book_write_error)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Address book not found"))?;
    record_admin_audit(
        &state,
        &actor,
        "create",
        "address_book_entry",
        &entry_id.to_string(),
        "Created address book entry",
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": entry_id,
            "device_id": request.device_id.trim(),
            "alias": request.alias.trim(),
            "note": request.note.trim(),
            "tags": request.tags,
        })),
    ))
}

async fn update_address_book_entry(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path((id, entry_id)): Path<(i64, i64)>,
    Json(request): Json<AddressBookEntryRequest>,
) -> Result<StatusCode, ApiError> {
    let actor = require_address_book_access(&state, &headers, id, "write").await?;
    let tags = validate_address_book_entry(&request)?;
    let updated = state
        .db
        .update_address_book_entry(
            id,
            entry_id,
            request.device_id.trim(),
            request.alias.trim(),
            request.note.trim(),
            &tags,
        )
        .await
        .map_err(address_book_write_error)?;
    if !updated {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Address book entry not found",
        ));
    }
    record_admin_audit(
        &state,
        &actor,
        "update",
        "address_book_entry",
        &entry_id.to_string(),
        "Updated address book entry",
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_address_book_entry(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path((id, entry_id)): Path<(i64, i64)>,
) -> Result<StatusCode, ApiError> {
    let actor = require_address_book_access(&state, &headers, id, "write").await?;
    let deleted = state
        .db
        .delete_address_book_entry(id, entry_id)
        .await
        .map_err(|error| {
            log::error!("Failed to delete address book entry: {}", error);
            ApiError::internal()
        })?;
    if !deleted {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Address book entry not found",
        ));
    }
    record_admin_audit(
        &state,
        &actor,
        "delete",
        "address_book_entry",
        &entry_id.to_string(),
        "Deleted address book entry",
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_address_book_permissions(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    require_shared_address_book_access(&state, &headers, id).await?;
    let permissions = state
        .db
        .list_address_book_permissions(id)
        .await
        .map_err(|error| {
            log::error!("Failed to list address book permissions: {}", error);
            ApiError::internal()
        })?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Address book not found"))?;
    Ok(Json(json!({ "permissions": permissions })))
}

async fn update_address_book_permissions(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(request): Json<AddressBookPermissionsRequest>,
) -> Result<StatusCode, ApiError> {
    let actor = require_shared_address_book_access(&state, &headers, id).await?;
    if request.permissions.len() > 2000 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "An address book can have at most 2000 permission rules",
        ));
    }
    let mut subjects = HashSet::with_capacity(request.permissions.len());
    for permission in &request.permissions {
        if !matches!(permission.access.as_str(), "read" | "write" | "manage")
            || !subjects.insert((permission.subject_type.as_str(), permission.subject_id))
        {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "Invalid or duplicate address book permission",
            ));
        }
        match permission.subject_type.as_str() {
            "everyone" if permission.subject_id == 0 => {}
            "user" if permission.subject_id > 0 => {
                let active = state
                    .db
                    .get_user_by_id(permission.subject_id)
                    .await
                    .map_err(|error| {
                        log::error!("Failed to validate address book user: {}", error);
                        ApiError::internal()
                    })?
                    .is_some();
                if !active {
                    return Err(ApiError::new(
                        StatusCode::BAD_REQUEST,
                        "Active user not found",
                    ));
                }
            }
            "group" if permission.subject_id > 0 => {
                let exists = state
                    .db
                    .list_user_group_members(permission.subject_id)
                    .await
                    .map_err(|error| {
                        log::error!("Failed to validate address book user group: {}", error);
                        ApiError::internal()
                    })?
                    .is_some();
                if !exists {
                    return Err(ApiError::new(
                        StatusCode::BAD_REQUEST,
                        "User group not found",
                    ));
                }
            }
            _ => {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "Invalid address book permission subject",
                ));
            }
        }
    }
    let updated = state
        .db
        .set_address_book_permissions(id, &request.permissions)
        .await
        .map_err(|error| {
            log::error!("Failed to update address book permissions: {}", error);
            ApiError::internal()
        })?;
    if !updated {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Address book not found",
        ));
    }
    record_admin_audit(
        &state,
        &actor,
        "replace_permissions",
        "address_book",
        &id.to_string(),
        "Replaced address book sharing permissions",
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn require_address_book_access(
    state: &ApiState,
    headers: &HeaderMap,
    book_id: i64,
    required: &str,
) -> Result<User, ApiError> {
    let required_scope = if required == "read" {
        "address_books:read"
    } else {
        "address_books:write"
    };
    let user = authenticated_scoped_user(state, headers, required_scope).await?;
    let owner = state
        .db
        .address_book_owner(book_id)
        .await
        .map_err(|error| {
            log::error!("Failed to determine address book owner: {}", error);
            ApiError::internal()
        })?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Address book not found"))?;
    if let Some(owner_id) = owner {
        if owner_id == user.id {
            return Ok(user);
        }
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Address book access denied",
        ));
    }
    if user.is_admin {
        return Ok(user);
    }
    let permission = state
        .db
        .address_book_permission(book_id, user.id)
        .await
        .map_err(|error| {
            log::error!("Failed to authorize address book access: {}", error);
            ApiError::internal()
        })?;
    let permission_level = permission
        .as_deref()
        .map(address_book_permission_level)
        .unwrap_or(0);
    if permission_level < address_book_permission_level(required) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Address book access denied",
        ));
    }
    Ok(user)
}

async fn require_shared_address_book_access(
    state: &ApiState,
    headers: &HeaderMap,
    book_id: i64,
) -> Result<User, ApiError> {
    let user = require_address_book_access(state, headers, book_id, "manage").await?;
    let owner = state
        .db
        .address_book_owner(book_id)
        .await
        .map_err(|error| {
            log::error!("Failed to determine address book owner: {}", error);
            ApiError::internal()
        })?;
    if owner != Some(None) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Personal address books cannot be shared",
        ));
    }
    Ok(user)
}

fn address_book_permission_level(permission: &str) -> u8 {
    match permission {
        "read" => 1,
        "write" => 2,
        "manage" => 3,
        _ => 0,
    }
}

fn validate_address_book(name: &str, description: &str) -> Result<(), ApiError> {
    let name = name.trim();
    if name.is_empty() || name.len() > 100 || name.chars().any(char::is_control) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Address book name must be 1-100 bytes and contain no control characters",
        ));
    }
    if description.len() > 300 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Address book description must be 300 bytes or fewer",
        ));
    }
    Ok(())
}

fn validate_address_book_entry(request: &AddressBookEntryRequest) -> Result<String, ApiError> {
    let device_id = request.device_id.trim();
    if device_id.is_empty() || device_id.len() > crate::peer::MAX_PEER_ID_LEN {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Address book device ID must be 1-100 bytes",
        ));
    }
    if request.alias.len() > 100 || request.note.len() > 300 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Address book alias or note is too long",
        ));
    }
    if request.tags.len() > 20
        || request
            .tags
            .iter()
            .any(|tag| tag.trim().is_empty() || tag.len() > 50)
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Address book entries support up to 20 tags of 1-50 bytes",
        ));
    }
    serde_json::to_string(
        &request
            .tags
            .iter()
            .map(|tag| tag.trim())
            .collect::<Vec<_>>(),
    )
    .map_err(|error| {
        log::error!("Failed to encode address book tags: {}", error);
        ApiError::internal()
    })
}

fn address_book_write_error(error: hbb_common::anyhow::Error) -> ApiError {
    if let Some(sqlx::Error::Database(database_error)) = error.downcast_ref::<sqlx::Error>() {
        if database_error.code().as_deref() == Some("2067")
            || database_error.code().as_deref() == Some("1555")
        {
            return ApiError::new(
                StatusCode::CONFLICT,
                "Address book name or device ID already exists",
            );
        }
    }
    log::error!("Failed to save address book: {}", error);
    ApiError::internal()
}

async fn list_admin_peers(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Query(query): Query<Pagination>,
) -> Result<Json<Value>, ApiError> {
    let access = require_resource_access(&state, &headers, "devices:read").await?;
    let group_ids = (!access.user.is_admin).then_some(access.device_group_ids.as_slice());
    peers_response(&state.db, &state.peer_map, query, None, group_ids).await
}

async fn list_admin_online_devices(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Query(query): Query<Pagination>,
) -> Result<Json<Value>, ApiError> {
    require_admin_session(&state, &headers).await?;
    let current = query.current.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(100).clamp(1, 200);
    let online = state.peer_map.online_peer_ids().await;
    let online_seconds = online
        .iter()
        .cloned()
        .collect::<std::collections::HashMap<_, _>>();
    let online_ids = online.into_iter().map(|(id, _)| id).collect::<Vec<_>>();
    let (peers, total) = state
        .db
        .list_peers_by_ids(
            &online_ids,
            page_size,
            current.saturating_sub(1).saturating_mul(page_size),
        )
        .await
        .map_err(|error| {
            log::error!("Failed to list live online devices: {}", error);
            ApiError::internal()
        })?;
    let data = peers
        .into_iter()
        .map(|peer| {
            let user = peer
                .user
                .as_deref()
                .map(String::from_utf8_lossy)
                .unwrap_or_default()
                .into_owned();
            json!({
                "id": peer.id,
                "info": serde_json::from_str::<Value>(&peer.info).unwrap_or_else(|_| json!({})),
                "user": user,
                "note": peer.note,
                "last_seen_seconds": online_seconds.get(&peer.id).copied().unwrap_or_default(),
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "data": data,
        "total": total,
        "current": current,
        "pageSize": page_size,
        "observation": "hbbs registration within the last 30 seconds; this is not an active remote session",
    })))
}

async fn list_admin_audit_logs(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Query(query): Query<AuditLogQuery>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&state, &headers, "audit:read").await?;
    let actor = query
        .actor
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let action = query
        .action
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let resource_type = query
        .resource_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if actor.is_some_and(|value| value.len() > 64)
        || action.is_some_and(|value| !valid_audit_action(value))
        || resource_type.is_some_and(|value| !valid_audit_resource_type(value))
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Invalid audit log filter",
        ));
    }
    let current = query.current.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).clamp(1, 200);
    let offset = current.saturating_sub(1).saturating_mul(page_size);
    let (logs, total) = state
        .db
        .list_admin_audit_logs(actor, action, resource_type, page_size, offset)
        .await
        .map_err(|error| {
            log::error!("Failed to list administrator audit logs: {}", error);
            ApiError::internal()
        })?;
    Ok(Json(
        json!({ "total": total, "data": logs, "current": current }),
    ))
}

fn default_task_max_runs() -> i64 {
    1
}

fn validate_automation_task(request: &AutomationTaskRequest) -> Result<String, ApiError> {
    let name = request.name.trim();
    if name.is_empty()
        || name.len() > 100
        || request.description.len() > 500
        || !(0..=2_592_000).contains(&request.interval_seconds)
        || !(1..=1000).contains(&request.max_runs)
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Invalid task metadata or schedule limits",
        ));
    }

    if request.script.trim().is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Task script cannot be empty",
        ));
    }
    Ok(request.script.clone())
}

fn automation_task_script_source(stored: &str) -> String {
    let Some(source) = legacy_automation_script_source(stored) else {
        return stored.to_owned();
    };
    source
}

fn legacy_automation_script_source(stored: &str) -> Option<String> {
    let value: Value = serde_json::from_str(stored).ok()?;
    let script = value.as_object()?;
    if script.len() != 2 || script.get("version") != Some(&json!(1)) {
        return None;
    }
    let steps = script.get("steps")?.as_array()?;
    let mut lines = Vec::with_capacity(steps.len());
    for step in steps {
        let step = step.as_object()?;
        match step.get("action")?.as_str()? {
            "wait" if step.len() == 2 => {
                let milliseconds = step.get("milliseconds")?.as_u64()?;
                lines.push(format!("wait({milliseconds})"));
            }
            action @ ("ocr_find" | "click_text") if step.len() == 2 => {
                let text = step.get("text")?.as_str()?;
                let text = serde_json::to_string(text).ok()?;
                lines.push(format!("{action}({text})"));
            }
            "click" if step.len() == 3 => {
                let x = step.get("x")?.as_f64()?;
                let y = step.get("y")?.as_f64()?;
                lines.push(format!("click({x}, {y})"));
            }
            _ => return None,
        }
    }
    Some(lines.join("\n"))
}

async fn list_admin_automation_tasks(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    require_admin_session(&state, &headers).await?;
    let tasks = state
        .db
        .list_automation_tasks(false)
        .await
        .map_err(|error| {
            log::error!("Failed to list automation tasks: {}", error);
            ApiError::internal()
        })?;
    let data = tasks
        .into_iter()
        .map(|task| {
            json!({
                "id": task.id,
                "name": task.name,
                "description": task.description,
                "script": automation_task_script_source(&task.script),
                "published": task.published,
                "interval_seconds": task.interval_seconds,
                "max_runs": task.max_runs,
                "created_by": task.created_by,
                "created_at": task.created_at,
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({ "data": data })))
}

async fn create_automation_task(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Json(request): Json<AutomationTaskRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let actor = require_admin_session(&state, &headers).await?;
    let script = validate_automation_task(&request)?;
    let id = state
        .db
        .create_automation_task(
            request.name.trim(),
            request.description.trim(),
            &script,
            request.interval_seconds,
            request.max_runs,
            &actor.name,
        )
        .await
        .map_err(|error| {
            log::error!("Failed to create automation task: {}", error);
            ApiError::internal()
        })?;
    if request.published {
        state
            .db
            .update_automation_task(
                id,
                request.name.trim(),
                request.description.trim(),
                &script,
                true,
                request.interval_seconds,
                request.max_runs,
            )
            .await
            .map_err(|error| {
                log::error!("Failed to publish automation task {}: {}", id, error);
                ApiError::internal()
            })?;
    }
    record_admin_audit(
        &state,
        &actor,
        "create",
        "automation_task",
        &id.to_string(),
        "Created an automation task",
    )
    .await?;
    Ok((StatusCode::CREATED, Json(json!({ "id": id }))))
}

async fn update_automation_task(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(request): Json<AutomationTaskRequest>,
) -> Result<StatusCode, ApiError> {
    let actor = require_admin_session(&state, &headers).await?;
    let script = validate_automation_task(&request)?;
    if !state
        .db
        .update_automation_task(
            id,
            request.name.trim(),
            request.description.trim(),
            &script,
            request.published,
            request.interval_seconds,
            request.max_runs,
        )
        .await
        .map_err(|error| {
            log::error!("Failed to update automation task {}: {}", id, error);
            ApiError::internal()
        })?
    {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "Task not found"));
    }
    record_admin_audit(
        &state,
        &actor,
        "update",
        "automation_task",
        &id.to_string(),
        "Updated an automation task",
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_automation_task(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let actor = require_admin_session(&state, &headers).await?;
    if !state.db.delete_automation_task(id).await.map_err(|error| {
        log::error!("Failed to delete automation task {}: {}", id, error);
        ApiError::internal()
    })? {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "Task not found"));
    }
    record_admin_audit(
        &state,
        &actor,
        "delete",
        "automation_task",
        &id.to_string(),
        "Deleted an automation task",
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_admin_automation_executions(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Query(query): Query<AutomationTaskQuery>,
) -> Result<Json<Value>, ApiError> {
    require_admin_session(&state, &headers).await?;
    let current = query.current.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(50).clamp(1, 200);
    let (data, total) = state
        .db
        .list_automation_executions(
            query.task_id,
            page_size,
            current.saturating_sub(1).saturating_mul(page_size),
        )
        .await
        .map_err(|error| {
            log::error!("Failed to list automation executions: {}", error);
            ApiError::internal()
        })?;
    Ok(Json(
        json!({ "data": data, "total": total, "current": current }),
    ))
}

async fn verify_automation_device(
    state: &ApiState,
    headers: &HeaderMap,
    identity: &AutomationDeviceIdentity,
) -> Result<User, ApiError> {
    if identity.id.trim().is_empty() || identity.id.len() > 100 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Invalid device identity",
        ));
    }
    let user = authenticated_user(state, headers).await?;
    let uuid = base64::decode(&identity.uuid)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "Invalid device identity"))?;
    let peer = state
        .db
        .get_peer(&identity.id)
        .await
        .map_err(|error| {
            log::error!("Failed to verify automation device: {}", error);
            ApiError::internal()
        })?
        .filter(|peer| {
            peer.uuid == uuid
                && peer.user.as_deref() == Some(user.name.as_bytes())
                && peer.status != Some(0)
        })
        .ok_or_else(|| {
            ApiError::new(StatusCode::FORBIDDEN, "Device is not bound to this account")
        })?;
    let _ = peer;
    Ok(user)
}

async fn list_available_automation_tasks(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Query(identity): Query<AutomationDeviceIdentity>,
) -> Result<Json<Value>, ApiError> {
    let user = verify_automation_device(&state, &headers, &identity).await?;
    let tasks = state
        .db
        .list_automation_tasks(true)
        .await
        .map_err(|error| {
            log::error!("Failed to list published automation tasks: {}", error);
            ApiError::internal()
        })?;
    let mut available_tasks = Vec::with_capacity(tasks.len());
    for task in tasks {
        let (used_runs, next_run_at, can_run) = state
            .db
            .automation_task_usage(task.id, &identity.id, task.max_runs, task.interval_seconds)
            .await
            .map_err(|error| {
                log::error!("Failed to read automation task usage: {}", error);
                ApiError::internal()
            })?;
        available_tasks.push(json!({
            "id": task.id,
            "name": task.name,
            "description": task.description,
            "script": automation_task_script_source(&task.script),
            "intervalSeconds": task.interval_seconds,
            "maxRuns": task.max_runs,
            "usedRuns": used_runs,
            "nextRunAt": next_run_at,
            "canRun": can_run,
        }));
    }
    Ok(Json(json!({ "data": available_tasks, "user": user.name })))
}

async fn start_automation_execution(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(task_id): Path<i64>,
    Json(identity): Json<AutomationDeviceIdentity>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let user = verify_automation_device(&state, &headers, &identity).await?;
    let task = state
        .db
        .get_automation_task(task_id)
        .await
        .map_err(|error| {
            log::error!("Failed to load automation task: {}", error);
            ApiError::internal()
        })?
        .filter(|task| task.published)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Published task not found"))?;
    let execution_id = state
        .db
        .start_automation_execution(task.id, &identity.id, &user.name)
        .await
        .map_err(|error| {
            log::error!("Failed to start automation task: {}", error);
            ApiError::internal()
        })?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::CONFLICT,
                "Task run limit reached or schedule interval has not elapsed",
            )
        })?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "executionId": execution_id })),
    ))
}

async fn finish_automation_execution(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(execution_id): Path<i64>,
    Json(request): Json<AutomationExecutionResult>,
) -> Result<StatusCode, ApiError> {
    let user = verify_automation_device(
        &state,
        &headers,
        &AutomationDeviceIdentity {
            id: request.id.clone(),
            uuid: request.uuid,
        },
    )
    .await?;
    if !matches!(
        request.status.as_str(),
        "succeeded" | "failed" | "cancelled"
    ) || request.result.len() > 4096
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Invalid task execution result",
        ));
    }
    if !state
        .db
        .finish_automation_execution(
            execution_id,
            &request.id,
            &user.name,
            &request.status,
            &request.result,
        )
        .await
        .map_err(|error| {
            log::error!("Failed to finish automation execution: {}", error);
            ApiError::internal()
        })?
    {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Active task execution not found",
        ));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn list_admin_api_tokens(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let actor = require_admin_session(&state, &headers).await?;
    let tokens = state.db.list_api_tokens(actor.id).await.map_err(|error| {
        log::error!("Failed to list API tokens: {}", error);
        ApiError::internal()
    })?;
    let data = tokens
        .into_iter()
        .map(|token| {
            let scopes = serde_json::from_str::<Vec<String>>(&token.scopes).map_err(|error| {
                log::error!("Failed to decode API token scopes: {}", error);
                ApiError::internal()
            })?;
            Ok(json!({
                "id": token.id,
                "name": token.name,
                "token_prefix": token.token_prefix,
                "scopes": scopes,
                "expires_at": token.expires_at,
                "created_at": token.created_at,
                "last_used_at": token.last_used_at,
                "revoked_at": token.revoked_at,
            }))
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Json(json!({ "data": data })))
}

async fn list_admin_delegated_roles(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    require_admin_session(&state, &headers).await?;
    let roles = state.db.list_delegated_roles().await.map_err(|error| {
        log::error!("Failed to list delegated roles: {}", error);
        ApiError::internal()
    })?;
    let data = roles
        .into_iter()
        .map(|(role, user_ids)| delegated_role_payload(role, user_ids))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(json!({ "data": data })))
}

async fn create_admin_delegated_role(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Json(request): Json<DelegatedRoleRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let actor = require_admin_session(&state, &headers).await?;
    let fields = validate_delegated_role_request(&state, &request).await?;
    let id = state
        .db
        .create_delegated_role(
            &fields.name,
            &fields.description,
            &fields.permissions,
            &fields.user_group_ids,
            &fields.device_group_ids,
            &request.user_ids,
        )
        .await
        .map_err(delegated_role_write_error)?;
    record_admin_audit(
        &state,
        &actor,
        "create",
        "delegated_role",
        &id.to_string(),
        "Created delegated administrator role",
    )
    .await?;
    let role = state
        .db
        .list_delegated_roles()
        .await
        .map_err(|_| ApiError::internal())?
        .into_iter()
        .find(|(role, _)| role.id == id)
        .ok_or_else(ApiError::internal)?;
    Ok((
        StatusCode::CREATED,
        Json(delegated_role_payload(role.0, role.1)?),
    ))
}

async fn update_admin_delegated_role(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(request): Json<DelegatedRoleRequest>,
) -> Result<StatusCode, ApiError> {
    let actor = require_admin_session(&state, &headers).await?;
    let fields = validate_delegated_role_request(&state, &request).await?;
    let updated = state
        .db
        .update_delegated_role(
            id,
            &fields.name,
            &fields.description,
            &fields.permissions,
            &fields.user_group_ids,
            &fields.device_group_ids,
            &request.user_ids,
        )
        .await
        .map_err(delegated_role_write_error)?;
    if !updated {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Delegated role not found",
        ));
    }
    record_admin_audit(
        &state,
        &actor,
        "update",
        "delegated_role",
        &id.to_string(),
        "Updated delegated administrator role",
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_admin_delegated_role(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let actor = require_admin_session(&state, &headers).await?;
    if !state.db.delete_delegated_role(id).await.map_err(|error| {
        log::error!("Failed to delete delegated role: {}", error);
        ApiError::internal()
    })? {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "Delegated role not found",
        ));
    }
    record_admin_audit(
        &state,
        &actor,
        "delete",
        "delegated_role",
        &id.to_string(),
        "Deleted delegated administrator role",
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

struct ValidatedDelegatedRole {
    name: String,
    description: String,
    permissions: String,
    user_group_ids: String,
    device_group_ids: String,
}

async fn validate_delegated_role_request(
    state: &ApiState,
    request: &DelegatedRoleRequest,
) -> Result<ValidatedDelegatedRole, ApiError> {
    let name = request.name.trim();
    if name.is_empty() || name.len() > 100 || name.chars().any(char::is_control) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Role name must be 1-100 bytes and contain no control characters",
        ));
    }
    if request.description.len() > 300 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Role description must be 300 bytes or fewer",
        ));
    }
    const ALLOWED: [&str; 4] = ["users:read", "users:write", "devices:read", "devices:write"];
    let mut permissions = HashSet::with_capacity(request.permissions.len());
    if request.permissions.is_empty()
        || request.permissions.len() > ALLOWED.len()
        || request.permissions.iter().any(|permission| {
            !ALLOWED.contains(&permission.as_str()) || !permissions.insert(permission)
        })
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Only unique user and device read/write permissions can be delegated",
        ));
    }
    if request.user_group_ids.len() > 500
        || request.device_group_ids.len() > 500
        || request.user_ids.len() > 5000
        || request
            .user_group_ids
            .iter()
            .chain(request.device_group_ids.iter())
            .any(|id| *id <= 0)
        || request.user_ids.iter().any(|id| *id <= 0)
        || has_duplicates(&request.user_group_ids)
        || has_duplicates(&request.device_group_ids)
        || has_duplicates(&request.user_ids)
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Invalid or duplicate role scope or member IDs",
        ));
    }
    let has_user_permission = request
        .permissions
        .iter()
        .any(|permission| permission.starts_with("users:"));
    let has_device_permission = request
        .permissions
        .iter()
        .any(|permission| permission.starts_with("devices:"));
    if (has_user_permission && request.user_group_ids.is_empty())
        || (!has_user_permission && !request.user_group_ids.is_empty())
        || (has_device_permission && request.device_group_ids.is_empty())
        || (!has_device_permission && !request.device_group_ids.is_empty())
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Each delegated resource permission requires matching explicit group scopes",
        ));
    }
    if !state
        .db
        .delegated_role_group_ids_exist(&request.user_group_ids, &request.device_group_ids)
        .await
        .map_err(|error| {
            log::error!("Failed to validate delegated role group scopes: {}", error);
            ApiError::internal()
        })?
        || !state
            .db
            .delegated_role_member_ids_exist(&request.user_ids)
            .await
            .map_err(|error| {
                log::error!("Failed to validate delegated role members: {}", error);
                ApiError::internal()
            })?
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Role references a group or user that does not exist",
        ));
    }
    Ok(ValidatedDelegatedRole {
        name: name.to_owned(),
        description: request.description.trim().to_owned(),
        permissions: serde_json::to_string(&request.permissions)
            .map_err(|_| ApiError::internal())?,
        user_group_ids: serde_json::to_string(&request.user_group_ids)
            .map_err(|_| ApiError::internal())?,
        device_group_ids: serde_json::to_string(&request.device_group_ids)
            .map_err(|_| ApiError::internal())?,
    })
}

fn has_duplicates<T: Eq + std::hash::Hash>(values: &[T]) -> bool {
    let mut unique = HashSet::with_capacity(values.len());
    values.iter().any(|value| !unique.insert(value))
}

fn delegated_role_write_error(error: hbb_common::anyhow::Error) -> ApiError {
    if let Some(sqlx::Error::Database(database_error)) = error.downcast_ref::<sqlx::Error>() {
        if database_error.code().as_deref() == Some("2067")
            || database_error.code().as_deref() == Some("1555")
        {
            return ApiError::new(StatusCode::CONFLICT, "Delegated role name already exists");
        }
    }
    log::error!("Failed to save delegated role: {}", error);
    ApiError::internal()
}

fn delegated_role_payload(role: DelegatedRole, user_ids: Vec<i64>) -> Result<Value, ApiError> {
    let permissions = serde_json::from_str::<Vec<String>>(&role.permissions).map_err(|error| {
        log::error!("Failed to decode delegated role permissions: {}", error);
        ApiError::internal()
    })?;
    let user_group_ids =
        serde_json::from_str::<Vec<i64>>(&role.user_group_ids).map_err(|error| {
            log::error!(
                "Failed to decode delegated role user group scopes: {}",
                error
            );
            ApiError::internal()
        })?;
    let device_group_ids =
        serde_json::from_str::<Vec<i64>>(&role.device_group_ids).map_err(|error| {
            log::error!(
                "Failed to decode delegated role device group scopes: {}",
                error
            );
            ApiError::internal()
        })?;
    Ok(json!({
        "id": role.id,
        "name": role.name,
        "description": role.description,
        "permissions": permissions,
        "user_group_ids": user_group_ids,
        "device_group_ids": device_group_ids,
        "user_ids": user_ids,
        "created_at": role.created_at,
    }))
}

async fn create_admin_api_token(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Json(request): Json<CreateApiTokenRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let actor = require_admin_session(&state, &headers).await?;
    let name = request.name.trim();
    if name.is_empty() || name.len() > 80 || name.chars().any(char::is_control) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Token name must be 1-80 bytes and contain no control characters",
        ));
    }
    if !(1..=365).contains(&request.expires_in_days) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Token expiration must be between 1 and 365 days",
        ));
    }
    let allowed_scopes = [
        "users:read",
        "users:write",
        "devices:read",
        "devices:write",
        "groups:read",
        "groups:write",
        "address_books:read",
        "address_books:write",
        "audit:read",
    ];
    let mut unique_scopes = HashSet::with_capacity(request.scopes.len());
    if request.scopes.is_empty()
        || request.scopes.len() > allowed_scopes.len()
        || request
            .scopes
            .iter()
            .any(|scope| !allowed_scopes.contains(&scope.as_str()) || !unique_scopes.insert(scope))
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Select one or more valid, unique token scopes",
        ));
    }
    let expires_at = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::days(request.expires_in_days))
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Invalid token expiration"))?
        .to_rfc3339();
    let token = format!("rdc_{}", uuid::Uuid::new_v4().simple());
    let token_prefix = token.chars().take(12).collect::<String>();
    let token_hash = format!("{:x}", Sha256::digest(token.as_bytes()));
    let scopes_json = serde_json::to_string(&request.scopes).map_err(|error| {
        log::error!("Failed to encode API token scopes: {}", error);
        ApiError::internal()
    })?;
    let id = state
        .db
        .create_api_token(
            actor.id,
            name,
            &token_prefix,
            &token_hash,
            &scopes_json,
            &expires_at,
        )
        .await
        .map_err(|error| {
            log::error!("Failed to create API token: {}", error);
            ApiError::internal()
        })?;
    if let Err(error) = record_admin_audit(
        &state,
        &actor,
        "create",
        "api_token",
        &id.to_string(),
        "Created an API token",
    )
    .await
    {
        if let Err(revoke_error) = state.db.revoke_api_token(actor.id, id).await {
            log::error!("Failed to revoke unaudited API token: {}", revoke_error);
        }
        return Err(error);
    }
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": id,
            "name": name,
            "token": token,
            "token_prefix": token_prefix,
            "scopes": request.scopes,
            "expires_at": expires_at,
        })),
    ))
}

async fn revoke_admin_api_token(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let actor = require_admin_session(&state, &headers).await?;
    let revoked = state
        .db
        .revoke_api_token(actor.id, id)
        .await
        .map_err(|error| {
            log::error!("Failed to revoke API token: {}", error);
            ApiError::internal()
        })?;
    if !revoked {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "API token not found"));
    }
    record_admin_audit(
        &state,
        &actor,
        "delete",
        "api_token",
        &id.to_string(),
        "Revoked an API token",
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdatePeer {
    #[serde(default)]
    user: String,
    #[serde(default)]
    note: String,
}

async fn update_peer(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<UpdatePeer>,
) -> Result<StatusCode, ApiError> {
    let access = require_resource_access(&state, &headers, "devices:write").await?;
    let actor = access.user;
    if id.trim().is_empty() || id.len() > crate::peer::MAX_PEER_ID_LEN {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "Invalid device ID"));
    }
    if request.note.len() > 300 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Device note must be 300 bytes or fewer",
        ));
    }
    if !actor.is_admin {
        let expected_owner = request.user.trim();
        let updated = state
            .db
            .update_peer_note_in_groups(
                &id,
                request.note.trim(),
                (!expected_owner.is_empty()).then_some(expected_owner),
                &access.device_group_ids,
            )
            .await
            .map_err(|error| {
                log::error!("Failed to update delegated device note: {}", error);
                ApiError::internal()
            })?;
        if !updated {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "Device not found"));
        }
        record_admin_audit(
            &state,
            &actor,
            "update",
            "device",
            &id,
            "Updated device note",
        )
        .await?;
        return Ok(StatusCode::NO_CONTENT);
    }
    let owner = request.user.trim();
    let owner = if owner.is_empty() {
        None
    } else {
        let user = state
            .db
            .get_user_by_name(owner)
            .await
            .map_err(|error| {
                log::error!("Failed to query device owner: {}", error);
                ApiError::internal()
            })?
            .filter(|user| user.status == 1)
            .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Active user not found"))?;
        Some(user.name)
    };
    let updated = state
        .db
        .update_peer_owner(&id, owner.as_deref(), request.note.trim())
        .await
        .map_err(|error| {
            log::error!("Failed to update device owner: {}", error);
            ApiError::internal()
        })?;
    if !updated {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "Device not found"));
    }
    record_admin_audit(
        &state,
        &actor,
        "update",
        "device",
        &id,
        "Updated device owner or note",
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn peers_response(
    db: &Database,
    peer_map: &PeerMap,
    query: Pagination,
    owner: Option<String>,
    group_ids: Option<&[i64]>,
) -> Result<Json<Value>, ApiError> {
    let current = query.current.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(100).clamp(1, 200);
    let (peers, total) = if let Some(group_ids) = group_ids {
        db.list_peers_in_groups(
            group_ids,
            query.status,
            page_size,
            current.saturating_sub(1).saturating_mul(page_size),
        )
        .await
    } else {
        db.list_peers(
            owner.as_deref(),
            query.status,
            page_size,
            current.saturating_sub(1).saturating_mul(page_size),
        )
        .await
    }
    .map_err(|error| {
        log::error!("Failed to list devices: {}", error);
        ApiError::internal()
    })?;
    let mut data = Vec::with_capacity(peers.len());
    for peer in peers {
        let user = peer
            .user
            .as_deref()
            .map(String::from_utf8_lossy)
            .unwrap_or_default()
            .into_owned();
        let info = serde_json::from_str::<Value>(&peer.info).unwrap_or_else(|_| json!({}));
        let online = peer_map.is_online(&peer.id).await;
        let ip = peer_map.online_ip(&peer.id).await.unwrap_or_default();
        data.push(json!({
            "id": peer.id,
            "info": info,
            "status": peer.status.unwrap_or(1),
            "online": online,
            "ip": ip,
            "user": user,
            "user_name": user,
            "device_group_name": "",
            "note": peer.note,
        }));
    }
    Ok(Json(json!({ "total": total, "data": data })))
}

async fn create_user(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Json(request): Json<CreateUser>,
) -> Result<(StatusCode, Json<UserPayload>), ApiError> {
    let actor = require_admin(&state, &headers, "users:write").await?;
    validate_name(&request.name)?;
    validate_email(&request.email)?;
    validate_password(&request.password)?;
    let password_hash = hash(request.password, DEFAULT_COST).map_err(|error| {
        log::error!("Failed to hash new user password: {}", error);
        ApiError::internal()
    })?;
    let id = state
        .db
        .create_user(
            request.name.trim(),
            request.display_name.trim(),
            request.email.trim(),
            &password_hash,
            request.is_admin,
        )
        .await
        .map_err(database_write_error)?;
    record_admin_audit(
        &state,
        &actor,
        "create",
        "user",
        &id.to_string(),
        "Created user account",
    )
    .await?;
    let user = state
        .db
        .get_user_by_id(id)
        .await
        .map_err(|error| {
            log::error!("Failed to read newly-created user: {}", error);
            ApiError::internal()
        })?
        .ok_or_else(ApiError::internal)?;
    Ok((StatusCode::CREATED, Json(user.into())))
}

async fn update_user(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(request): Json<UpdateUser>,
) -> Result<Json<UserPayload>, ApiError> {
    let access = require_resource_access(&state, &headers, "users:write").await?;
    let actor = access.user;
    if request.status != 0 && request.status != 1 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Status must be 0 or 1",
        ));
    }
    validate_email(&request.email)?;
    if let Some(password) = &request.password {
        validate_password(password)?;
    }
    if !actor.is_admin {
        if request.is_admin || request.status != 1 {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "Delegated administrators cannot change account status or administrator privileges",
            ));
        }
        let password_hash = request
            .password
            .map(|password| hash(password, DEFAULT_COST))
            .transpose()
            .map_err(|error| {
                log::error!("Failed to hash delegated account password: {}", error);
                ApiError::internal()
            })?;
        let updated = state
            .db
            .update_user_in_groups(
                id,
                request.display_name.trim(),
                request.email.trim(),
                password_hash.as_deref(),
                &access.user_group_ids,
            )
            .await
            .map_err(database_write_error)?;
        if !updated {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "User not found"));
        }
        record_admin_audit(
            &state,
            &actor,
            "update",
            "user",
            &id.to_string(),
            "Updated user profile",
        )
        .await?;
        let user = state
            .db
            .get_user_by_id(id)
            .await
            .map_err(|_| ApiError::internal())?
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "User not found"))?;
        return Ok(Json(user.into()));
    }
    let target = state
        .db
        .get_user_by_id(id)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "User not found"))?;
    if target.is_admin
        && target.status == 1
        && (request.status == 0 || !request.is_admin)
        && state
            .db
            .count_admins()
            .await
            .map_err(|_| ApiError::internal())?
            <= 1
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "At least one active administrator is required",
        ));
    }
    if actor.id == id && (request.status == 0 || !request.is_admin) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "You cannot disable or demote your own account",
        ));
    }
    state
        .db
        .update_user(
            id,
            request.display_name.trim(),
            request.email.trim(),
            request.is_admin,
            request.status,
        )
        .await
        .map_err(database_write_error)?;
    if let Some(password) = request.password {
        let password_hash = hash(password, DEFAULT_COST).map_err(|_| ApiError::internal())?;
        state
            .db
            .update_user_password(id, &password_hash)
            .await
            .map_err(database_write_error)?;
    }
    record_admin_audit(
        &state,
        &actor,
        "update",
        "user",
        &id.to_string(),
        "Updated user account",
    )
    .await?;
    let user = state
        .db
        .get_user_by_id(id)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "User not found"))?;
    Ok(Json(user.into()))
}

async fn delete_user(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let actor = require_admin(&state, &headers, "users:write").await?;
    let target = state
        .db
        .get_user_by_id(id)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "User not found"))?;
    if actor.id == id {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "You cannot delete your own account",
        ));
    }
    if target.is_admin
        && target.status == 1
        && state
            .db
            .count_admins()
            .await
            .map_err(|_| ApiError::internal())?
            <= 1
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "At least one active administrator is required",
        ));
    }
    state
        .db
        .delete_user(id)
        .await
        .map_err(database_write_error)?;
    record_admin_audit(
        &state,
        &actor,
        "delete",
        "user",
        &id.to_string(),
        "Deleted user account",
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn require_admin(
    state: &ApiState,
    headers: &HeaderMap,
    required_scope: &str,
) -> Result<User, ApiError> {
    let user = authenticated_scoped_user(state, headers, required_scope).await?;
    if !user.is_admin {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "Admin required!"));
    }
    Ok(user)
}

struct ResourceAccess {
    user: User,
    user_group_ids: Vec<i64>,
    device_group_ids: Vec<i64>,
}

async fn require_resource_access(
    state: &ApiState,
    headers: &HeaderMap,
    required_scope: &str,
) -> Result<ResourceAccess, ApiError> {
    let user = authenticated_scoped_user(state, headers, required_scope).await?;
    if user.is_admin {
        return Ok(ResourceAccess {
            user,
            user_group_ids: Vec::new(),
            device_group_ids: Vec::new(),
        });
    }
    let roles = state
        .db
        .delegated_access_for_user(user.id)
        .await
        .map_err(|error| {
            log::error!("Failed to load delegated access roles: {}", error);
            ApiError::internal()
        })?;
    let mut user_group_ids = HashSet::new();
    let mut device_group_ids = HashSet::new();
    let mut scope_allowed = false;
    for role in roles {
        let permissions =
            serde_json::from_str::<Vec<String>>(&role.permissions).map_err(|error| {
                log::error!("Invalid persisted delegated role permissions: {}", error);
                ApiError::internal()
            })?;
        let user_scopes =
            serde_json::from_str::<Vec<i64>>(&role.user_group_ids).map_err(|error| {
                log::error!("Invalid persisted delegated user group scope: {}", error);
                ApiError::internal()
            })?;
        let device_scopes =
            serde_json::from_str::<Vec<i64>>(&role.device_group_ids).map_err(|error| {
                log::error!("Invalid persisted delegated device group scope: {}", error);
                ApiError::internal()
            })?;
        if permissions.iter().any(|permission| {
            !matches!(
                permission.as_str(),
                "users:read" | "users:write" | "devices:read" | "devices:write"
            )
        }) {
            log::error!("Persisted delegated role contains an unsupported permission");
            return Err(ApiError::internal());
        }
        let role_allows_scope = permissions.iter().any(|permission| {
            permission == required_scope
                || (required_scope.ends_with(":read")
                    && permission.strip_suffix(":write") == required_scope.strip_suffix(":read"))
        });
        if role_allows_scope {
            scope_allowed = true;
            if required_scope.starts_with("users:") {
                user_group_ids.extend(user_scopes);
            } else {
                device_group_ids.extend(device_scopes);
            }
        }
    }
    if !scope_allowed {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Delegated role permission is insufficient",
        ));
    }
    let groups = if required_scope.starts_with("users:") {
        &user_group_ids
    } else {
        &device_group_ids
    };
    if groups.is_empty() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Delegated role has no resource group scope",
        ));
    }
    let mut user_group_ids = user_group_ids.into_iter().collect::<Vec<_>>();
    let mut device_group_ids = device_group_ids.into_iter().collect::<Vec<_>>();
    user_group_ids.sort_unstable();
    device_group_ids.sort_unstable();
    Ok(ResourceAccess {
        user,
        user_group_ids,
        device_group_ids,
    })
}

async fn require_admin_session(state: &ApiState, headers: &HeaderMap) -> Result<User, ApiError> {
    let user = authenticated_user(state, headers).await?;
    if !user.is_admin {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "Admin required!"));
    }
    Ok(user)
}

async fn authenticated_scoped_user(
    state: &ApiState,
    headers: &HeaderMap,
    required_scope: &str,
) -> Result<User, ApiError> {
    let token = authorization_token(headers)?;
    if token.starts_with("rdc_") {
        let token_hash = format!("{:x}", Sha256::digest(token.as_bytes()));
        let token_auth = state
            .db
            .authenticate_api_token(&token_hash)
            .await
            .map_err(|error| {
                log::error!("Failed to authenticate API token: {}", error);
                ApiError::internal()
            })?
            .ok_or_else(|| {
                ApiError::new(StatusCode::UNAUTHORIZED, "Invalid or expired API token")
            })?;
        let user = state
            .db
            .get_user_by_id(token_auth.owner_id)
            .await
            .map_err(|error| {
                log::error!("Failed to load API token owner: {}", error);
                ApiError::internal()
            })?
            .filter(|user| user.status == 1 && user.is_admin)
            .ok_or_else(|| {
                ApiError::new(StatusCode::UNAUTHORIZED, "API token owner is unavailable")
            })?;
        let scopes = serde_json::from_str::<Vec<String>>(&token_auth.scopes).map_err(|error| {
            log::error!("Failed to decode API token scopes: {}", error);
            ApiError::internal()
        })?;
        if !api_token_scope_allows(&scopes, required_scope) {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "API token scope is insufficient",
            ));
        }
        return Ok(user);
    }
    authenticated_user(state, headers).await
}

fn api_token_scope_allows(scopes: &[String], required_scope: &str) -> bool {
    scopes.iter().any(|scope| {
        scope == required_scope
            || (required_scope.ends_with(":read")
                && scope.strip_suffix(":write") == required_scope.strip_suffix(":read"))
    })
}

async fn record_admin_audit(
    state: &ApiState,
    actor: &User,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    summary: &str,
) -> Result<(), ApiError> {
    state
        .db
        .insert_admin_audit_log(
            actor.id,
            &actor.name,
            action,
            resource_type,
            resource_id,
            summary,
        )
        .await
        .map_err(|error| {
            log::error!(
                "Failed to record admin audit action '{}' on {} {}: {}",
                action,
                resource_type,
                resource_id,
                error
            );
            ApiError::internal()
        })
}

fn valid_audit_action(action: &str) -> bool {
    matches!(
        action,
        "create" | "update" | "delete" | "replace_members" | "replace_permissions"
    )
}

fn valid_audit_resource_type(resource_type: &str) -> bool {
    matches!(
        resource_type,
        "user"
            | "device"
            | "device_group"
            | "user_group"
            | "address_book"
            | "address_book_entry"
            | "delegated_role"
            | "api_token"
            | "automation_task"
    )
}

async fn authenticated_user(state: &ApiState, headers: &HeaderMap) -> Result<User, ApiError> {
    let token = authorization_token(headers)?;
    if token.starts_with("rdc_") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "API tokens are limited to scoped administrator endpoints",
        ));
    }
    let mut validation = Validation::default();
    validation.required_spec_claims.remove("exp");
    validation.validate_exp = false;
    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|_| ApiError::new(StatusCode::UNAUTHORIZED, "Invalid access token"))?
    .claims;
    let user = state
        .db
        .get_user_by_name(&claims.sub)
        .await
        .map_err(|error| {
            log::error!("Failed to query authenticated user: {}", error);
            ApiError::internal()
        })?;
    user.filter(|user| user.status == 1)
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "Account is disabled"))
}

fn authorization_token(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .or_else(|| {
            headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("access_token "))
        })
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "Authentication required"))
}

fn validate_name(name: &str) -> Result<(), ApiError> {
    let name = name.trim();
    if name.len() < 3
        || name.len() > 64
        || !name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Username must be 3-64 characters and use only letters, numbers, dots, underscores, or hyphens",
        ));
    }
    Ok(())
}

fn validate_email(email: &str) -> Result<(), ApiError> {
    let email = email.trim();
    let mut parts = email.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    if email.len() > 254
        || local.is_empty()
        || domain.is_empty()
        || parts.next().is_some()
        || email.chars().any(char::is_whitespace)
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Invalid email address",
        ));
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<(), ApiError> {
    if password.len() < 8 || password.len() > 72 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Password must be 8-72 bytes",
        ));
    }
    Ok(())
}

fn database_write_error(error: hbb_common::anyhow::Error) -> ApiError {
    if let Some(sqlx::Error::Database(database_error)) = error.downcast_ref::<sqlx::Error>() {
        if database_error.code().as_deref() == Some("2067")
            || database_error.code().as_deref() == Some("1555")
        {
            return ApiError::new(StatusCode::CONFLICT, "Username or email already exists");
        }
    }
    log::error!("User database write failed: {}", error);
    ApiError::internal()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn validates_user_fields() {
        assert!(validate_name("alice").is_ok());
        assert!(validate_name("a").is_err());
        assert!(validate_name("has space").is_err());
        assert!(validate_name("bad@name").is_err());
        assert!(validate_email("alice@example.com").is_ok());
        assert!(validate_email("not-an-email").is_err());
        assert!(validate_email("alice@@example.com").is_err());
        assert!(validate_password("long-enough-password").is_ok());
        assert!(validate_password("short").is_err());
    }

    #[test]
    fn automation_scripts_accept_full_python_source() {
        let task = |script| AutomationTaskRequest {
            name: "Text task".to_owned(),
            description: String::new(),
            script,
            published: true,
            interval_seconds: 60,
            max_runs: 3,
        };
        assert!(validate_automation_task(&task(
            "import os\nvalue = 2\nfor _ in range(value):\n    wait(200)\nresult = os.getcwd()"
                .to_owned(),
        ))
        .is_ok());
        assert!(
            validate_automation_task(&task(format!("{}\nresult = True", "#".repeat(32_768))))
                .is_ok()
        );
        assert!(validate_automation_task(&task(" \n".to_owned())).is_err());
    }

    #[test]
    fn converts_preexisting_json_task_steps_to_python_source() {
        let stored = r#"{"version":1,"steps":[{"action":"ocr_find","text":"确定"},{"action":"click","x":0.5,"y":0.4},{"action":"wait","milliseconds":500}]}"#;
        assert_eq!(
            automation_task_script_source(stored),
            "ocr_find(\"确定\")\nclick(0.5, 0.4)\nwait(500)"
        );
    }

    #[test]
    fn public_registration_creates_login_ready_non_admin_accounts() {
        public_registration_flow();
    }

    #[tokio::main(flavor = "current_thread")]
    async fn public_registration_flow() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let db = Database::new(file.path().to_str().unwrap()).await.unwrap();
        let state = ApiState {
            db: db.clone(),
            jwt_secret: "registration-test-secret".to_owned(),
            peer_map: PeerMap::with_database(db.clone()),
            started_at: Instant::now(),
            api_address: "127.0.0.1:21114".parse().unwrap(),
            rendezvous_address: "127.0.0.1:21116".parse().unwrap(),
            relay_servers: Vec::new(),
        };

        let registration = serde_json::from_value(json!({
            "name": "new-user",
            "email": "new-user@example.com",
            "password": "a-long-registration-password",
            "is_admin": true,
        }))
        .unwrap();
        let (status, response) = register_user(Extension(state.clone()), Json(registration))
            .await
            .unwrap();
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(response["message"], "Account created");

        let user = db.get_user_by_name("new-user").await.unwrap().unwrap();
        assert!(!user.is_admin);
        assert!(verify("a-long-registration-password", &user.password_hash).unwrap());

        let login_response = login(
            Extension(state.clone()),
            Json(LoginRequest {
                username: "new-user".to_owned(),
                password: "a-long-registration-password".to_owned(),
                id: String::new(),
                uuid: String::new(),
                device_info: Value::Null,
                auto_login: false,
                r#type: "account".to_owned(),
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(login_response["user"]["name"], "new-user");
        assert_eq!(login_response["user"]["is_admin"], false);

        let duplicate = register_user(
            Extension(state.clone()),
            Json(RegisterUserRequest {
                name: "new-user".to_owned(),
                email: "another@example.com".to_owned(),
                password: "a-long-registration-password".to_owned(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(duplicate.status, StatusCode::CONFLICT);

        let invalid = register_user(
            Extension(state),
            Json(RegisterUserRequest {
                name: "bad".to_owned(),
                email: "not-an-email".to_owned(),
                password: "short".to_owned(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(invalid.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn validates_device_group_fields() {
        assert!(validate_device_group("Engineering", "Remote lab").is_ok());
        assert!(validate_device_group(" ", "").is_err());
        assert!(validate_device_group("Control\nGroup", "").is_err());
        assert!(validate_device_group("Valid", &"x".repeat(301)).is_err());
    }

    #[test]
    fn validates_user_group_fields() {
        assert!(validate_user_group("Engineering", "Research team").is_ok());
        assert!(validate_user_group(" ", "").is_err());
        assert!(validate_user_group("Control\nGroup", "").is_err());
        assert!(validate_user_group("Valid", &"x".repeat(301)).is_err());
    }

    #[test]
    fn server_status_is_admin_only_and_reports_live_resource_counts() {
        server_status_api_flow();
    }

    #[tokio::main(flavor = "current_thread")]
    async fn server_status_api_flow() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let db = Database::new(file.path().to_str().unwrap()).await.unwrap();
        db.create_user(
            "admin",
            "Admin",
            "admin@example.com",
            &hash("admin-test-password", DEFAULT_COST).unwrap(),
            true,
        )
        .await
        .unwrap();
        db.create_user(
            "member",
            "Member",
            "member@example.com",
            &hash("member-test-password", DEFAULT_COST).unwrap(),
            false,
        )
        .await
        .unwrap();
        db.create_user_group("Operators", "").await.unwrap();
        db.create_device_group("Workstations", "").await.unwrap();
        db.insert_peer("known-device", b"device-uuid", b"device-key", "{}")
            .await
            .unwrap();
        let peer_map = PeerMap::with_database(db.clone());
        peer_map
            .get_or("known-device")
            .await
            .write()
            .await
            .last_reg_time = Instant::now();
        let state = ApiState {
            db,
            jwt_secret: "server-status-test-secret".to_owned(),
            peer_map,
            started_at: Instant::now(),
            api_address: "0.0.0.0:21114".parse().unwrap(),
            rendezvous_address: "0.0.0.0:21116".parse().unwrap(),
            relay_servers: vec!["relay.example.test:21117".to_owned()],
        };
        let admin_headers = signed_test_headers(&state, "admin");
        let member_headers = signed_test_headers(&state, "member");
        assert_eq!(
            get_admin_server_status(Extension(state.clone()), HeaderMap::new())
                .await
                .unwrap_err()
                .status,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            get_admin_server_status(Extension(state.clone()), member_headers)
                .await
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );

        let status = get_admin_server_status(Extension(state), admin_headers)
            .await
            .unwrap()
            .0;
        assert_eq!(status["api_address"], "0.0.0.0:21114");
        assert_eq!(status["rendezvous_address"], "0.0.0.0:21116");
        assert_eq!(status["relay_servers"], json!(["relay.example.test:21117"]));
        assert_eq!(status["resources"]["total_users"], 2);
        assert_eq!(status["resources"]["active_users"], 2);
        assert_eq!(status["resources"]["total_devices"], 1);
        assert_eq!(status["resources"]["online_devices"], 1);
        assert_eq!(status["resources"]["device_groups"], 1);
        assert_eq!(status["resources"]["user_groups"], 1);
    }

    #[test]
    fn online_device_monitor_is_admin_only_and_excludes_stale_registrations() {
        online_device_monitor_api_flow();
    }

    #[tokio::main(flavor = "current_thread")]
    async fn online_device_monitor_api_flow() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let db = Database::new(file.path().to_str().unwrap()).await.unwrap();
        db.create_user(
            "admin",
            "Admin",
            "admin@example.com",
            &hash("admin-test-password", DEFAULT_COST).unwrap(),
            true,
        )
        .await
        .unwrap();
        db.insert_peer("online-device", b"online-uuid", b"online-key", "{}")
            .await
            .unwrap();
        db.insert_peer("stale-device", b"stale-uuid", b"stale-key", "{}")
            .await
            .unwrap();
        let peer_map = PeerMap::with_database(db.clone());
        peer_map
            .get_or("online-device")
            .await
            .write()
            .await
            .last_reg_time = Instant::now();
        peer_map
            .get_or("stale-device")
            .await
            .write()
            .await
            .last_reg_time = Instant::now() - std::time::Duration::from_secs(31);
        let state = ApiState {
            db,
            jwt_secret: "online-device-test-secret".to_owned(),
            peer_map,
            started_at: Instant::now(),
            api_address: "127.0.0.1:21114".parse().unwrap(),
            rendezvous_address: "127.0.0.1:21116".parse().unwrap(),
            relay_servers: Vec::new(),
        };
        assert_eq!(
            list_admin_online_devices(
                Extension(state.clone()),
                HeaderMap::new(),
                Query(Pagination {
                    current: Some(1),
                    page_size: Some(100),
                    status: None,
                }),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::UNAUTHORIZED
        );
        let response = list_admin_online_devices(
            Extension(state.clone()),
            signed_test_headers(&state, "admin"),
            Query(Pagination {
                current: Some(1),
                page_size: Some(100),
                status: None,
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(response["total"], 1);
        assert_eq!(response["data"][0]["id"], "online-device");
        assert_eq!(
            response["observation"],
            "hbbs registration within the last 30 seconds; this is not an active remote session"
        );
    }

    #[test]
    fn delegated_roles_persist_and_enforce_group_scoped_access() {
        delegated_role_api_flow();
    }

    #[tokio::main(flavor = "current_thread")]
    async fn delegated_role_api_flow() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let db = Database::new(file.path().to_str().unwrap()).await.unwrap();
        db.create_user(
            "admin",
            "Admin",
            "admin@example.com",
            &hash("admin-test-password", DEFAULT_COST).unwrap(),
            true,
        )
        .await
        .unwrap();
        let delegated_id = db
            .create_user(
                "delegate",
                "Delegate",
                "delegate@example.com",
                &hash("delegate-test-password", DEFAULT_COST).unwrap(),
                false,
            )
            .await
            .unwrap();
        let scoped_user_id = db
            .create_user(
                "scoped",
                "Scoped",
                "scoped@example.com",
                &hash("scoped-test-password", DEFAULT_COST).unwrap(),
                false,
            )
            .await
            .unwrap();
        let outside_user_id = db
            .create_user(
                "outside",
                "Outside",
                "outside@example.com",
                &hash("outside-test-password", DEFAULT_COST).unwrap(),
                false,
            )
            .await
            .unwrap();
        let user_group_id = db.create_user_group("Scoped users", "").await.unwrap();
        db.set_user_group_members(user_group_id, &[scoped_user_id])
            .await
            .unwrap();
        let readonly_group_id = db.create_user_group("Read-only users", "").await.unwrap();
        db.set_user_group_members(readonly_group_id, &[outside_user_id])
            .await
            .unwrap();
        let device_group_id = db.create_device_group("Scoped devices", "").await.unwrap();
        let outside_device_group_id = db.create_device_group("Other devices", "").await.unwrap();
        for (id, byte) in [("scoped-device", 1_u8), ("outside-device", 2_u8)] {
            db.insert_peer(id, &[byte; 16], &[byte; 32], "{}")
                .await
                .unwrap();
        }
        db.set_device_group_peers(device_group_id, &["scoped-device".to_owned()])
            .await
            .unwrap();
        db.set_device_group_peers(outside_device_group_id, &["outside-device".to_owned()])
            .await
            .unwrap();
        let state = ApiState {
            db: db.clone(),
            jwt_secret: "delegated-role-test-secret".to_owned(),
            peer_map: PeerMap::with_database(db.clone()),
            started_at: Instant::now(),
            api_address: "127.0.0.1:21114".parse().unwrap(),
            rendezvous_address: "127.0.0.1:21116".parse().unwrap(),
            relay_servers: Vec::new(),
        };
        let admin_headers = signed_test_headers(&state, "admin");
        let delegated_headers = signed_test_headers(&state, "delegate");
        let ordinary_headers = signed_test_headers(&state, "scoped");
        let role_request = DelegatedRoleRequest {
            name: "Scoped operators".to_owned(),
            description: "Only selected groups".to_owned(),
            permissions: vec![
                "users:read".to_owned(),
                "users:write".to_owned(),
                "devices:read".to_owned(),
                "devices:write".to_owned(),
            ],
            user_group_ids: vec![user_group_id],
            device_group_ids: vec![device_group_id],
            user_ids: vec![delegated_id],
        };
        let (status, created) = create_admin_delegated_role(
            Extension(state.clone()),
            admin_headers.clone(),
            Json(role_request),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(created["user_ids"], json!([delegated_id]));
        let role_id = created["id"].as_i64().unwrap();
        let login_response = login(
            Extension(state.clone()),
            Json(LoginRequest {
                username: "delegate".to_owned(),
                password: "delegate-test-password".to_owned(),
                id: String::new(),
                uuid: String::new(),
                device_info: json!({}),
                auto_login: false,
                r#type: String::new(),
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(login_response["user"]["is_delegated_admin"], true);
        assert_eq!(
            login_response["user"]["delegated_permissions"],
            json!(["devices:read", "devices:write", "users:read", "users:write"])
        );
        assert!(
            current_user(Extension(state.clone()), delegated_headers.clone(), None)
                .await
                .unwrap()
                .0
                .is_delegated_admin
        );
        assert_eq!(
            current_user(Extension(state.clone()), delegated_headers.clone(), None)
                .await
                .unwrap()
                .0
                .delegated_permissions,
            vec!["devices:read", "devices:write", "users:read", "users:write"]
        );
        assert_eq!(
            create_admin_delegated_role(
                Extension(state.clone()),
                delegated_headers.clone(),
                Json(DelegatedRoleRequest {
                    name: "forbidden".to_owned(),
                    description: String::new(),
                    permissions: Vec::new(),
                    user_group_ids: Vec::new(),
                    device_group_ids: Vec::new(),
                    user_ids: vec![delegated_id],
                }),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            update_admin_delegated_role(
                Extension(state.clone()),
                delegated_headers.clone(),
                Path(role_id),
                Json(DelegatedRoleRequest {
                    name: "attempted member escalation".to_owned(),
                    description: String::new(),
                    permissions: vec!["users:read".to_owned()],
                    user_group_ids: vec![readonly_group_id],
                    device_group_ids: Vec::new(),
                    user_ids: vec![outside_user_id],
                }),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::FORBIDDEN
        );
        db.create_delegated_role(
            "Read-only role",
            "",
            r#"["users:read"]"#,
            &serde_json::to_string(&vec![readonly_group_id]).unwrap(),
            "[]",
            &[delegated_id],
        )
        .await
        .unwrap();
        db.create_delegated_role(
            "Read-only device role",
            "",
            r#"["devices:read"]"#,
            "[]",
            &serde_json::to_string(&vec![outside_device_group_id]).unwrap(),
            &[delegated_id],
        )
        .await
        .unwrap();
        let persisted = list_admin_delegated_roles(Extension(state.clone()), admin_headers.clone())
            .await
            .unwrap()
            .0;
        let persisted_role = persisted["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|role| role["name"] == "Scoped operators")
            .unwrap();
        assert_eq!(persisted_role["user_group_ids"], json!([user_group_id]));
        assert_eq!(persisted_role["device_group_ids"], json!([device_group_id]));

        assert_eq!(
            list_admin_delegated_roles(Extension(state.clone()), delegated_headers.clone(),)
                .await
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            create_admin_delegated_role(
                Extension(state.clone()),
                admin_headers.clone(),
                Json(DelegatedRoleRequest {
                    name: "forbidden permission".to_owned(),
                    description: String::new(),
                    permissions: vec!["audit:read".to_owned()],
                    user_group_ids: Vec::new(),
                    device_group_ids: Vec::new(),
                    user_ids: vec![delegated_id],
                }),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            list_admin_api_tokens(Extension(state.clone()), delegated_headers.clone())
                .await
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            list_admin_audit_logs(
                Extension(state.clone()),
                delegated_headers.clone(),
                Query(AuditLogQuery {
                    current: None,
                    page_size: None,
                    actor: None,
                    action: None,
                    resource_type: None,
                }),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            list_admin_users(
                Extension(state.clone()),
                ordinary_headers,
                Query(Pagination {
                    current: Some(1),
                    page_size: Some(100),
                    status: None,
                }),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::FORBIDDEN
        );

        let users = list_admin_users(
            Extension(state.clone()),
            delegated_headers.clone(),
            Query(Pagination {
                current: Some(1),
                page_size: Some(100),
                status: None,
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(users["total"], 2);
        let visible_user_ids = users["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|user| user["id"].as_i64().unwrap())
            .collect::<HashSet<_>>();
        assert!(visible_user_ids.contains(&scoped_user_id));
        assert!(visible_user_ids.contains(&outside_user_id));
        assert_eq!(
            list_admin_device_groups(
                Extension(state.clone()),
                delegated_headers.clone(),
                Query(Pagination {
                    current: Some(1),
                    page_size: Some(100),
                    status: None,
                }),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::FORBIDDEN
        );

        let devices = list_admin_peers(
            Extension(state.clone()),
            delegated_headers.clone(),
            Query(Pagination {
                current: Some(1),
                page_size: Some(100),
                status: None,
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(devices["total"], 2);
        let visible_device_ids = devices["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|device| device["id"].as_str().unwrap())
            .collect::<HashSet<_>>();
        assert!(visible_device_ids.contains("scoped-device"));
        assert!(visible_device_ids.contains("outside-device"));

        update_user(
            Extension(state.clone()),
            delegated_headers.clone(),
            Path(scoped_user_id),
            Json(UpdateUser {
                email: "updated@example.com".to_owned(),
                display_name: "Updated".to_owned(),
                is_admin: false,
                status: 1,
                password: None,
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            update_user(
                Extension(state.clone()),
                delegated_headers.clone(),
                Path(outside_user_id),
                Json(UpdateUser {
                    email: "outside-updated@example.com".to_owned(),
                    display_name: "Outside".to_owned(),
                    is_admin: false,
                    status: 1,
                    password: None,
                }),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            update_user(
                Extension(state.clone()),
                delegated_headers.clone(),
                Path(scoped_user_id),
                Json(UpdateUser {
                    email: "promote@example.com".to_owned(),
                    display_name: "Promote".to_owned(),
                    is_admin: true,
                    status: 1,
                    password: None,
                }),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::FORBIDDEN
        );

        update_peer(
            Extension(state.clone()),
            delegated_headers.clone(),
            Path("scoped-device".to_owned()),
            Json(UpdatePeer {
                user: String::new(),
                note: "within scope".to_owned(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            update_peer(
                Extension(state.clone()),
                delegated_headers.clone(),
                Path("outside-device".to_owned()),
                Json(UpdatePeer {
                    user: String::new(),
                    note: "outside scope".to_owned(),
                }),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            update_peer(
                Extension(state.clone()),
                delegated_headers.clone(),
                Path("scoped-device".to_owned()),
                Json(UpdatePeer {
                    user: "scoped".to_owned(),
                    note: "transfer attempt".to_owned(),
                }),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            state
                .db
                .get_peer("outside-device")
                .await
                .unwrap()
                .unwrap()
                .note,
            ""
        );
    }

    #[test]
    fn api_token_write_scopes_include_read_access_only_within_their_resource() {
        let scopes = vec!["users:write".to_owned()];
        assert!(api_token_scope_allows(&scopes, "users:read"));
        assert!(api_token_scope_allows(&scopes, "users:write"));
        assert!(!api_token_scope_allows(&scopes, "devices:read"));
        assert!(!api_token_scope_allows(&scopes, "audit:read"));
    }

    #[test]
    fn validates_address_book_fields_and_permission_levels() {
        assert!(validate_address_book("Shared", "Team devices").is_ok());
        assert!(validate_address_book(" ", "").is_err());
        assert!(validate_address_book("Bad\nName", "").is_err());
        assert!(validate_address_book("Valid", &"x".repeat(301)).is_err());
        assert_eq!(address_book_permission_level("read"), 1);
        assert_eq!(address_book_permission_level("write"), 2);
        assert_eq!(address_book_permission_level("manage"), 3);
        assert_eq!(address_book_permission_level("unknown"), 0);
        assert!(validate_address_book_entry(&AddressBookEntryRequest {
            device_id: "device".to_owned(),
            alias: String::new(),
            note: String::new(),
            tags: vec!["team".to_owned()],
        })
        .is_ok());
        assert!(validate_address_book_entry(&AddressBookEntryRequest {
            device_id: String::new(),
            alias: String::new(),
            note: String::new(),
            tags: Vec::new(),
        })
        .is_err());
    }

    #[test]
    fn user_groups_are_admin_managed_and_account_scoped() {
        user_group_api_flow();
    }

    #[tokio::main(flavor = "current_thread")]
    async fn user_group_api_flow() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let db = Database::new(file.path().to_str().unwrap()).await.unwrap();
        db.create_user(
            "admin",
            "Admin",
            "admin@example.com",
            &hash("admin-test-password", DEFAULT_COST).unwrap(),
            true,
        )
        .await
        .unwrap();
        let alice_id = db
            .create_user(
                "alice",
                "Alice",
                "alice@example.com",
                &hash("alice-test-password", DEFAULT_COST).unwrap(),
                false,
            )
            .await
            .unwrap();
        db.create_user(
            "bob",
            "Bob",
            "bob@example.com",
            &hash("bob-test-password", DEFAULT_COST).unwrap(),
            false,
        )
        .await
        .unwrap();
        let state = ApiState {
            db: db.clone(),
            jwt_secret: "user-group-test-secret".to_owned(),
            peer_map: PeerMap::with_database(db),
            started_at: Instant::now(),
            api_address: "127.0.0.1:21114".parse().unwrap(),
            rendezvous_address: "127.0.0.1:21116".parse().unwrap(),
            relay_servers: Vec::new(),
        };
        let admin_headers = test_auth_headers(&state, "admin");

        assert_eq!(
            list_admin_user_groups(
                Extension(state.clone()),
                test_auth_headers(&state, "alice"),
                Query(Pagination {
                    current: Some(1),
                    page_size: Some(100),
                    status: None,
                }),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::FORBIDDEN
        );

        let (created_status, created) = create_user_group(
            Extension(state.clone()),
            admin_headers.clone(),
            Json(CreateUserGroup {
                name: "Engineering".to_owned(),
                description: "Product team".to_owned(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(created_status, StatusCode::CREATED);
        let group_id = created["id"].as_i64().unwrap();
        assert_eq!(
            create_user_group(
                Extension(state.clone()),
                admin_headers.clone(),
                Json(CreateUserGroup {
                    name: "engineering".to_owned(),
                    description: String::new(),
                }),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::CONFLICT
        );
        assert_eq!(
            update_user_group_members(
                Extension(state.clone()),
                admin_headers.clone(),
                Path(group_id),
                Json(UpdateUserGroupMembers {
                    user_ids: vec![alice_id, i64::MAX],
                }),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            list_user_group_members(
                Extension(state.clone()),
                admin_headers.clone(),
                Path(group_id),
            )
            .await
            .unwrap()
            .0["user_ids"],
            json!([])
        );

        update_user_group_members(
            Extension(state.clone()),
            admin_headers.clone(),
            Path(group_id),
            Json(UpdateUserGroupMembers {
                user_ids: vec![alice_id],
            }),
        )
        .await
        .unwrap();
        let groups = list_accessible_user_groups(
            Extension(state.clone()),
            test_auth_headers(&state, "alice"),
            Query(Pagination {
                current: Some(1),
                page_size: Some(100),
                status: None,
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(groups["total"], 1);
        assert_eq!(groups["data"][0]["member_count"], 1);
        let groups = list_accessible_user_groups(
            Extension(state.clone()),
            test_auth_headers(&state, "bob"),
            Query(Pagination {
                current: Some(1),
                page_size: Some(100),
                status: None,
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(groups["total"], 0);

        assert_eq!(
            state
                .db
                .list_user_groups(100, 0)
                .await
                .unwrap()
                .0
                .iter()
                .map(|group| group.id)
                .collect::<Vec<_>>(),
            vec![group_id]
        );
        update_user_group(
            Extension(state.clone()),
            admin_headers.clone(),
            Path(group_id),
            Json(UpdateUserGroup {
                name: "Research".to_owned(),
                description: "Updated".to_owned(),
            }),
        )
        .await
        .unwrap();
        let updated_groups = state.db.list_user_groups(100, 0).await.unwrap().0;
        assert_eq!(updated_groups[0].name, "Research");
        assert_eq!(updated_groups[0].description, "Updated");
        state.db.delete_user(alice_id).await.unwrap();
        assert_eq!(
            state.db.list_user_group_members(group_id).await.unwrap(),
            Some(Vec::new())
        );
        delete_user_group(Extension(state.clone()), admin_headers, Path(group_id))
            .await
            .unwrap();
        assert_eq!(
            state.db.list_user_group_members(group_id).await.unwrap(),
            None
        );
    }

    #[test]
    fn device_groups_are_admin_managed_and_account_scoped() {
        device_group_api_flow();
    }

    #[tokio::main(flavor = "current_thread")]
    async fn device_group_api_flow() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let db = Database::new(file.path().to_str().unwrap()).await.unwrap();
        db.create_user(
            "admin",
            "Admin",
            "admin@example.com",
            &hash("admin-test-password", DEFAULT_COST).unwrap(),
            true,
        )
        .await
        .unwrap();
        db.create_user(
            "alice",
            "Alice",
            "alice@example.com",
            &hash("alice-test-password", DEFAULT_COST).unwrap(),
            false,
        )
        .await
        .unwrap();
        db.create_user(
            "bob",
            "Bob",
            "bob@example.com",
            &hash("bob-test-password", DEFAULT_COST).unwrap(),
            false,
        )
        .await
        .unwrap();
        db.insert_peer("alice-device", b"alice-uuid", b"key", "{}")
            .await
            .unwrap();
        db.update_peer_owner("alice-device", Some("alice"), "")
            .await
            .unwrap();
        let state = ApiState {
            db: db.clone(),
            jwt_secret: "device-group-test-secret".to_owned(),
            peer_map: PeerMap::with_database(db),
            started_at: Instant::now(),
            api_address: "127.0.0.1:21114".parse().unwrap(),
            rendezvous_address: "127.0.0.1:21116".parse().unwrap(),
            relay_servers: Vec::new(),
        };
        let admin_headers = test_auth_headers(&state, "admin");
        let alice_headers = test_auth_headers(&state, "alice");
        let bob_headers = test_auth_headers(&state, "bob");

        assert_eq!(
            list_admin_device_groups(
                Extension(state.clone()),
                alice_headers,
                Query(Pagination {
                    current: Some(1),
                    page_size: Some(100),
                    status: None,
                }),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::FORBIDDEN
        );

        let (created_status, created) = create_device_group(
            Extension(state.clone()),
            admin_headers.clone(),
            Json(CreateDeviceGroup {
                name: "Lab".to_owned(),
                description: "Test device group".to_owned(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(created_status, StatusCode::CREATED);
        let group_id = created["id"].as_i64().unwrap();
        assert_eq!(
            create_device_group(
                Extension(state.clone()),
                admin_headers.clone(),
                Json(CreateDeviceGroup {
                    name: "lab".to_owned(),
                    description: String::new(),
                }),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::CONFLICT
        );
        assert_eq!(
            update_device_group_peers(
                Extension(state.clone()),
                admin_headers.clone(),
                Path(group_id),
                Json(UpdateDeviceGroupPeers {
                    device_ids: vec!["alice-device".to_owned(), "missing-device".to_owned()],
                }),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            list_device_group_peers(
                Extension(state.clone()),
                admin_headers.clone(),
                Path(group_id),
            )
            .await
            .unwrap()
            .0["device_ids"],
            json!([])
        );

        update_device_group_peers(
            Extension(state.clone()),
            admin_headers.clone(),
            Path(group_id),
            Json(UpdateDeviceGroupPeers {
                device_ids: vec!["alice-device".to_owned()],
            }),
        )
        .await
        .unwrap();
        let listing = list_admin_device_groups(
            Extension(state.clone()),
            admin_headers.clone(),
            Query(Pagination {
                current: Some(1),
                page_size: Some(100),
                status: None,
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(listing["data"][0]["device_count"], 1);
        assert_eq!(
            list_groups(
                Extension(state.clone()),
                test_auth_headers(&state, "alice"),
                Query(Pagination {
                    current: Some(1),
                    page_size: Some(100),
                    status: None,
                }),
            )
            .await
            .unwrap()
            .0["total"],
            1
        );
        assert_eq!(
            list_groups(
                Extension(state.clone()),
                bob_headers,
                Query(Pagination {
                    current: Some(1),
                    page_size: Some(100),
                    status: None,
                }),
            )
            .await
            .unwrap()
            .0["total"],
            0
        );

        update_device_group(
            Extension(state.clone()),
            admin_headers.clone(),
            Path(group_id),
            Json(UpdateDeviceGroup {
                name: "Research".to_owned(),
                description: "Updated".to_owned(),
            }),
        )
        .await
        .unwrap();
        delete_device_group(Extension(state.clone()), admin_headers, Path(group_id))
            .await
            .unwrap();
        assert_eq!(
            state.db.list_device_group_peers(group_id).await.unwrap(),
            None
        );
    }

    #[test]
    fn address_books_enforce_acl_inheritance_and_write_access() {
        address_book_api_flow();
    }

    #[test]
    fn personal_address_books_are_owner_scoped_and_removed_with_their_owner() {
        personal_address_book_api_flow();
    }

    #[test]
    fn api_tokens_are_scoped_owner_bound_and_revocable() {
        api_token_api_flow();
    }

    #[tokio::main(flavor = "current_thread")]
    async fn api_token_api_flow() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let db = Database::new(file.path().to_str().unwrap()).await.unwrap();
        let admin_id = db
            .create_user(
                "admin",
                "Admin",
                "admin@example.com",
                &hash("admin-test-password", DEFAULT_COST).unwrap(),
                true,
            )
            .await
            .unwrap();
        db.create_user(
            "other-admin",
            "Other Admin",
            "other-admin@example.com",
            &hash("other-test-password", DEFAULT_COST).unwrap(),
            true,
        )
        .await
        .unwrap();
        let state = ApiState {
            db: db.clone(),
            jwt_secret: "api-token-test-secret".to_owned(),
            peer_map: PeerMap::with_database(db.clone()),
            started_at: Instant::now(),
            api_address: "127.0.0.1:21114".parse().unwrap(),
            rendezvous_address: "127.0.0.1:21116".parse().unwrap(),
            relay_servers: Vec::new(),
        };
        let admin_headers = test_auth_headers(&state, "admin");
        assert_eq!(
            create_admin_api_token(
                Extension(state.clone()),
                admin_headers.clone(),
                Json(CreateApiTokenRequest {
                    name: "Invalid".to_owned(),
                    scopes: vec!["admin:*".to_owned()],
                    expires_in_days: 30,
                }),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::BAD_REQUEST
        );
        let (status, created) = create_admin_api_token(
            Extension(state.clone()),
            admin_headers.clone(),
            Json(CreateApiTokenRequest {
                name: "Automation".to_owned(),
                scopes: vec!["users:read".to_owned(), "address_books:read".to_owned()],
                expires_in_days: 30,
            }),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::CREATED);
        let secret = created.0["token"].as_str().unwrap().to_owned();
        let token_id = created.0["id"].as_i64().unwrap();
        assert_eq!(created.0["token_prefix"], &secret[..12]);
        let token_audit = list_admin_audit_logs(
            Extension(state.clone()),
            admin_headers.clone(),
            Query(AuditLogQuery {
                current: Some(1),
                page_size: Some(20),
                actor: None,
                action: Some("create".to_owned()),
                resource_type: Some("api_token".to_owned()),
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(token_audit["total"], 1);
        assert_eq!(token_audit["data"][0]["summary"], "Created an API token");
        assert!(!token_audit["data"][0]["summary"]
            .as_str()
            .unwrap()
            .contains(&secret));

        let mut token_headers = HeaderMap::new();
        token_headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {secret}").parse().unwrap(),
        );
        assert!(list_admin_users(
            Extension(state.clone()),
            token_headers.clone(),
            Query(Pagination {
                current: Some(1),
                page_size: Some(20),
                status: None,
            }),
        )
        .await
        .is_ok());
        assert!(require_admin(&state, &token_headers, "users:read")
            .await
            .is_ok());
        assert!(
            authenticated_scoped_user(&state, &token_headers, "address_books:read")
                .await
                .is_ok()
        );
        assert_eq!(
            require_admin(&state, &token_headers, "users:write")
                .await
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            require_admin(&state, &token_headers, "devices:read")
                .await
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            authenticated_user(&state, &token_headers)
                .await
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );

        let listed = list_admin_api_tokens(Extension(state.clone()), admin_headers.clone())
            .await
            .unwrap()
            .0;
        assert_eq!(listed["data"].as_array().unwrap().len(), 1);
        assert!(listed["data"][0].get("token").is_none());
        assert_eq!(listed["data"][0]["scopes"][0], "users:read");
        assert_eq!(
            list_admin_api_tokens(
                Extension(state.clone()),
                test_auth_headers(&state, "other-admin"),
            )
            .await
            .unwrap()
            .0["data"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            revoke_admin_api_token(
                Extension(state.clone()),
                test_auth_headers(&state, "other-admin"),
                Path(token_id),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            revoke_admin_api_token(Extension(state.clone()), admin_headers, Path(token_id),)
                .await
                .unwrap(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            require_admin(&state, &token_headers, "users:read")
                .await
                .unwrap_err()
                .status,
            StatusCode::UNAUTHORIZED
        );
        let expired_hash = format!("{:x}", Sha256::digest(b"expired-token"));
        db.create_api_token(
            admin_id,
            "Expired",
            "rdc_expired",
            &expired_hash,
            r#"["users:read"]"#,
            "2000-01-01T00:00:00+00:00",
        )
        .await
        .unwrap();
        assert!(db
            .authenticate_api_token(&expired_hash)
            .await
            .unwrap()
            .is_none());
        assert!(db.get_user_by_id(admin_id).await.unwrap().is_some());
    }

    #[tokio::main(flavor = "current_thread")]
    async fn personal_address_book_api_flow() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let db = Database::new(file.path().to_str().unwrap()).await.unwrap();
        db.create_user(
            "admin",
            "Admin",
            "admin@example.com",
            &hash("admin-test-password", DEFAULT_COST).unwrap(),
            true,
        )
        .await
        .unwrap();
        let alice_id = db
            .create_user(
                "alice",
                "Alice",
                "alice@example.com",
                &hash("alice-test-password", DEFAULT_COST).unwrap(),
                false,
            )
            .await
            .unwrap();
        db.create_user(
            "bob",
            "Bob",
            "bob@example.com",
            &hash("bob-test-password", DEFAULT_COST).unwrap(),
            false,
        )
        .await
        .unwrap();
        let state = ApiState {
            db: db.clone(),
            jwt_secret: "personal-address-book-test-secret".to_owned(),
            peer_map: PeerMap::with_database(db.clone()),
            started_at: Instant::now(),
            api_address: "127.0.0.1:21114".parse().unwrap(),
            rendezvous_address: "127.0.0.1:21116".parse().unwrap(),
            relay_servers: Vec::new(),
        };
        let alice_headers = test_auth_headers(&state, "alice");
        let bob_headers = test_auth_headers(&state, "bob");
        let admin_headers = test_auth_headers(&state, "admin");

        let (status, book) = create_personal_address_book(
            Extension(state.clone()),
            alice_headers.clone(),
            Json(AddressBookRequest {
                name: "Private".to_owned(),
                description: "Alice devices".to_owned(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(book["is_personal"], true);
        let book_id = book["id"].as_i64().unwrap();
        assert_eq!(
            update_personal_address_book(
                Extension(state.clone()),
                alice_headers.clone(),
                Path(book_id),
                Json(AddressBookRequest {
                    name: "Private updated".to_owned(),
                    description: "Updated description".to_owned(),
                }),
            )
            .await
            .unwrap(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            list_personal_address_books(
                Extension(state.clone()),
                alice_headers.clone(),
                Query(Pagination {
                    current: Some(1),
                    page_size: Some(100),
                    status: None,
                }),
            )
            .await
            .unwrap()
            .0["total"],
            1
        );
        for headers in [bob_headers.clone(), admin_headers.clone()] {
            assert_eq!(
                list_personal_address_books(
                    Extension(state.clone()),
                    headers,
                    Query(Pagination {
                        current: Some(1),
                        page_size: Some(100),
                        status: None,
                    }),
                )
                .await
                .unwrap()
                .0["total"],
                0
            );
        }
        assert_eq!(
            list_accessible_address_books(
                Extension(state.clone()),
                admin_headers.clone(),
                Query(Pagination {
                    current: Some(1),
                    page_size: Some(100),
                    status: None,
                }),
            )
            .await
            .unwrap()
            .0["total"],
            0
        );
        let (entry_status, entry) = create_address_book_entry(
            Extension(state.clone()),
            alice_headers.clone(),
            Path(book_id),
            Json(AddressBookEntryRequest {
                device_id: "alice-device".to_owned(),
                alias: "Laptop".to_owned(),
                note: String::new(),
                tags: Vec::new(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(entry_status, StatusCode::CREATED);
        for headers in [bob_headers.clone(), admin_headers.clone()] {
            assert_eq!(
                list_accessible_address_book_entries(
                    Extension(state.clone()),
                    headers,
                    Path(book_id),
                )
                .await
                .unwrap_err()
                .status,
                StatusCode::FORBIDDEN
            );
        }
        assert_eq!(
            list_address_book_permissions(
                Extension(state.clone()),
                alice_headers.clone(),
                Path(book_id),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            update_personal_address_book(
                Extension(state.clone()),
                bob_headers,
                Path(book_id),
                Json(AddressBookRequest {
                    name: "Stolen".to_owned(),
                    description: String::new(),
                }),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::NOT_FOUND
        );
        let entry_id = entry["id"].as_i64().unwrap();
        assert_eq!(
            delete_address_book_entry(
                Extension(state.clone()),
                alice_headers.clone(),
                Path((book_id, entry_id)),
            )
            .await
            .unwrap(),
            StatusCode::NO_CONTENT
        );
        let (status, disposable_book) = create_personal_address_book(
            Extension(state.clone()),
            alice_headers.clone(),
            Json(AddressBookRequest {
                name: "Disposable".to_owned(),
                description: String::new(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::CREATED);
        let disposable_id = disposable_book["id"].as_i64().unwrap();
        assert_eq!(
            delete_personal_address_book(
                Extension(state.clone()),
                alice_headers,
                Path(disposable_id),
            )
            .await
            .unwrap(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            state.db.address_book_owner(disposable_id).await.unwrap(),
            None
        );

        state.db.delete_user(alice_id).await.unwrap();
        assert_eq!(
            state
                .db
                .list_personal_address_books(alice_id, 100, 0)
                .await
                .unwrap()
                .1,
            0
        );
    }

    #[tokio::main(flavor = "current_thread")]
    async fn address_book_api_flow() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let db = Database::new(file.path().to_str().unwrap()).await.unwrap();
        db.create_user(
            "admin",
            "Admin",
            "admin@example.com",
            &hash("admin-test-password", DEFAULT_COST).unwrap(),
            true,
        )
        .await
        .unwrap();
        let alice_id = db
            .create_user(
                "alice",
                "Alice",
                "alice@example.com",
                &hash("alice-test-password", DEFAULT_COST).unwrap(),
                false,
            )
            .await
            .unwrap();
        db.create_user(
            "bob",
            "Bob",
            "bob@example.com",
            &hash("bob-test-password", DEFAULT_COST).unwrap(),
            false,
        )
        .await
        .unwrap();
        let state = ApiState {
            db: db.clone(),
            jwt_secret: "address-book-test-secret".to_owned(),
            peer_map: PeerMap::with_database(db),
            started_at: Instant::now(),
            api_address: "127.0.0.1:21114".parse().unwrap(),
            rendezvous_address: "127.0.0.1:21116".parse().unwrap(),
            relay_servers: Vec::new(),
        };
        let admin_headers = test_auth_headers(&state, "admin");
        let alice_headers = test_auth_headers(&state, "alice");
        let bob_headers = test_auth_headers(&state, "bob");
        let (status, book) = create_address_book(
            Extension(state.clone()),
            admin_headers.clone(),
            Json(AddressBookRequest {
                name: "Shared".to_owned(),
                description: "Team devices".to_owned(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::CREATED);
        let book_id = book["id"].as_i64().unwrap();
        assert_eq!(
            list_admin_audit_logs(
                Extension(state.clone()),
                admin_headers.clone(),
                Query(AuditLogQuery {
                    current: Some(1),
                    page_size: Some(20),
                    actor: Some("admin".to_owned()),
                    action: Some("create".to_owned()),
                    resource_type: Some("address_book".to_owned()),
                }),
            )
            .await
            .unwrap()
            .0["data"][0]["summary"],
            "Created shared address book"
        );
        assert_eq!(
            list_admin_audit_logs(
                Extension(state.clone()),
                test_auth_headers(&state, "alice"),
                Query(AuditLogQuery {
                    current: Some(1),
                    page_size: Some(20),
                    actor: None,
                    action: None,
                    resource_type: None,
                }),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            list_admin_audit_logs(
                Extension(state.clone()),
                admin_headers.clone(),
                Query(AuditLogQuery {
                    current: Some(1),
                    page_size: Some(20),
                    actor: None,
                    action: Some("invalid".to_owned()),
                    resource_type: None,
                }),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            list_accessible_address_books(
                Extension(state.clone()),
                admin_headers.clone(),
                Query(Pagination {
                    current: Some(1),
                    page_size: Some(100),
                    status: None,
                }),
            )
            .await
            .unwrap()
            .0["data"][0]["permission"],
            "manage"
        );
        let group_id = state
            .db
            .create_user_group("Engineering", "Research team")
            .await
            .unwrap();
        state
            .db
            .set_user_group_members(group_id, &[alice_id])
            .await
            .unwrap();
        assert_eq!(
            update_address_book_permissions(
                Extension(state.clone()),
                admin_headers.clone(),
                Path(book_id),
                Json(AddressBookPermissionsRequest {
                    permissions: vec![AddressBookPermission {
                        subject_type: "group".to_owned(),
                        subject_id: group_id,
                        access: "read".to_owned(),
                    }],
                }),
            )
            .await
            .unwrap(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            list_accessible_address_books(
                Extension(state.clone()),
                alice_headers.clone(),
                Query(Pagination {
                    current: Some(1),
                    page_size: Some(100),
                    status: None,
                }),
            )
            .await
            .unwrap()
            .0["data"][0]["permission"],
            "read"
        );
        assert_eq!(
            list_accessible_address_books(
                Extension(state.clone()),
                bob_headers.clone(),
                Query(Pagination {
                    current: Some(1),
                    page_size: Some(100),
                    status: None,
                }),
            )
            .await
            .unwrap()
            .0["total"],
            0
        );
        assert_eq!(
            create_address_book_entry(
                Extension(state.clone()),
                alice_headers.clone(),
                Path(book_id),
                Json(AddressBookEntryRequest {
                    device_id: "alice-device".to_owned(),
                    alias: "Workstation".to_owned(),
                    note: String::new(),
                    tags: vec!["team".to_owned()],
                }),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            update_address_book_permissions(
                Extension(state.clone()),
                admin_headers.clone(),
                Path(book_id),
                Json(AddressBookPermissionsRequest {
                    permissions: vec![AddressBookPermission {
                        subject_type: "group".to_owned(),
                        subject_id: group_id,
                        access: "write".to_owned(),
                    }],
                }),
            )
            .await
            .unwrap(),
            StatusCode::NO_CONTENT
        );
        let (entry_status, entry) = create_address_book_entry(
            Extension(state.clone()),
            alice_headers.clone(),
            Path(book_id),
            Json(AddressBookEntryRequest {
                device_id: "alice-device".to_owned(),
                alias: "Workstation".to_owned(),
                note: "Office".to_owned(),
                tags: vec!["team".to_owned()],
            }),
        )
        .await
        .unwrap();
        assert_eq!(entry_status, StatusCode::CREATED);
        assert_eq!(entry["tags"], json!(["team"]));
        let entry_id = entry["id"].as_i64().unwrap();
        assert_eq!(
            update_address_book_entry(
                Extension(state.clone()),
                alice_headers.clone(),
                Path((book_id, entry_id)),
                Json(AddressBookEntryRequest {
                    device_id: "alice-device".to_owned(),
                    alias: "Office workstation".to_owned(),
                    note: "Updated".to_owned(),
                    tags: vec!["team".to_owned(), "office".to_owned()],
                }),
            )
            .await
            .unwrap(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            update_address_book_entry(
                Extension(state.clone()),
                bob_headers.clone(),
                Path((book_id, entry_id)),
                Json(AddressBookEntryRequest {
                    device_id: "alice-device".to_owned(),
                    alias: String::new(),
                    note: String::new(),
                    tags: Vec::new(),
                }),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            create_address_book_entry(
                Extension(state.clone()),
                bob_headers.clone(),
                Path(book_id),
                Json(AddressBookEntryRequest {
                    device_id: "bob-device".to_owned(),
                    alias: String::new(),
                    note: String::new(),
                    tags: Vec::new(),
                }),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            update_address_book_permissions(
                Extension(state.clone()),
                admin_headers.clone(),
                Path(book_id),
                Json(AddressBookPermissionsRequest {
                    permissions: vec![AddressBookPermission {
                        subject_type: "group".to_owned(),
                        subject_id: group_id,
                        access: "manage".to_owned(),
                    }],
                }),
            )
            .await
            .unwrap(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            list_address_book_permissions(
                Extension(state.clone()),
                alice_headers.clone(),
                Path(book_id),
            )
            .await
            .unwrap()
            .0["permissions"][0]["access"],
            "manage"
        );
        assert_eq!(
            update_address_book_permissions(
                Extension(state.clone()),
                alice_headers.clone(),
                Path(book_id),
                Json(AddressBookPermissionsRequest {
                    permissions: vec![AddressBookPermission {
                        subject_type: "user".to_owned(),
                        subject_id: i64::MAX,
                        access: "manage".to_owned(),
                    }],
                }),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            list_accessible_address_book_entries(
                Extension(state.clone()),
                bob_headers.clone(),
                Path(book_id),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::FORBIDDEN
        );
        update_address_book_permissions(
            Extension(state.clone()),
            admin_headers.clone(),
            Path(book_id),
            Json(AddressBookPermissionsRequest {
                permissions: vec![
                    AddressBookPermission {
                        subject_type: "group".to_owned(),
                        subject_id: group_id,
                        access: "manage".to_owned(),
                    },
                    AddressBookPermission {
                        subject_type: "everyone".to_owned(),
                        subject_id: 0,
                        access: "read".to_owned(),
                    },
                ],
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            list_accessible_address_books(
                Extension(state.clone()),
                alice_headers.clone(),
                Query(Pagination {
                    current: Some(1),
                    page_size: Some(100),
                    status: None,
                }),
            )
            .await
            .unwrap()
            .0["data"][0]["permission"],
            "manage"
        );
        assert_eq!(
            list_accessible_address_books(
                Extension(state.clone()),
                bob_headers.clone(),
                Query(Pagination {
                    current: Some(1),
                    page_size: Some(100),
                    status: None,
                }),
            )
            .await
            .unwrap()
            .0["data"][0]["permission"],
            "read"
        );
        assert_eq!(
            list_accessible_address_book_entries(
                Extension(state.clone()),
                bob_headers,
                Path(book_id),
            )
            .await
            .unwrap()
            .0["data"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            list_accessible_address_book_entries(
                Extension(state.clone()),
                admin_headers,
                Path(book_id),
            )
            .await
            .unwrap()
            .0["data"][0]["id"],
            entry_id
        );
        assert_eq!(
            delete_address_book_entry(
                Extension(state.clone()),
                alice_headers,
                Path((book_id, entry_id)),
            )
            .await
            .unwrap(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            state
                .db
                .list_address_book_entries(book_id)
                .await
                .unwrap()
                .unwrap()
                .len(),
            0
        );
    }

    fn test_auth_headers(state: &ApiState, username: &str) -> HeaderMap {
        let token = encode(
            &Header::default(),
            &Claims {
                sub: username.to_owned(),
                exp: Some(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as usize
                        + 3600,
                ),
            },
            &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        headers
    }

    fn signed_test_headers(state: &ApiState, username: &str) -> HeaderMap {
        let token = encode(
            &Header::default(),
            &Claims {
                sub: username.to_owned(),
                exp: Some(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as usize
                        + 3600,
                ),
            },
            &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        headers
    }

    #[test]
    fn user_payload_does_not_serialize_password_hash() {
        let user = User {
            id: 7,
            name: "alice".to_owned(),
            display_name: "Alice".to_owned(),
            email: "alice@example.com".to_owned(),
            avatar: String::new(),
            note: String::new(),
            password_hash: "secret-hash".to_owned(),
            is_admin: false,
            status: 1,
            created_at: Utc::now().to_rfc3339(),
        };
        let payload = serde_json::to_value(UserPayload::from(user)).unwrap();
        assert!(payload.get("password_hash").is_none());
    }

    #[test]
    fn account_login_returns_token_and_user_listing_requires_admin() {
        account_login_flow();
    }

    #[tokio::main(flavor = "current_thread")]
    async fn account_login_flow() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let db = Database::new(file.path().to_str().unwrap()).await.unwrap();
        let secret = db.get_or_create_api_secret().await.unwrap();
        assert_eq!(secret, db.get_or_create_api_secret().await.unwrap());
        let device_uuid = b"test-device-uuid";
        db.insert_peer("test-device", device_uuid, b"device-key", "{}")
            .await
            .unwrap();
        let password_hash = hash("a-long-test-password", DEFAULT_COST).unwrap();
        db.create_user("alice", "Alice", "alice@example.com", &password_hash, false)
            .await
            .unwrap();
        let peer_map = PeerMap::with_database(db.clone());
        {
            let peer = peer_map.get_or("test-device").await;
            let mut peer = peer.write().await;
            peer.last_reg_time = std::time::Instant::now();
            peer.info.ip = "192.0.2.10".to_owned();
        }
        let state = ApiState {
            db: db.clone(),
            jwt_secret: "test-secret".to_owned(),
            peer_map,
            started_at: Instant::now(),
            api_address: "127.0.0.1:21114".parse().unwrap(),
            rendezvous_address: "127.0.0.1:21116".parse().unwrap(),
            relay_servers: Vec::new(),
        };
        let response = login(
            Extension(state.clone()),
            Json(LoginRequest {
                username: "alice".to_owned(),
                password: "a-long-test-password".to_owned(),
                id: "test-device".to_owned(),
                uuid: base64::encode(device_uuid),
                device_info: Value::Null,
                auto_login: true,
                r#type: "account".to_owned(),
            }),
        )
        .await
        .unwrap()
        .0;
        let token = response["access_token"].as_str().unwrap();
        assert_eq!(response["type"], "access_token");
        assert!(decode::<Claims>(
            token,
            &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
            &{
                let mut validation = Validation::default();
                validation.required_spec_claims.remove("exp");
                validation
            },
        )
        .unwrap()
        .claims
        .exp
        .is_none());
        assert!(response["user"]["id"].is_number());
        assert_eq!(response["user"]["name"], "alice");
        assert!(response["user"].get("password_hash").is_none());
        assert_eq!(
            db.get_peer("test-device").await.unwrap().unwrap().user,
            Some(b"alice".to_vec())
        );

        let pending_device_id = "not-yet-registered";
        let pending_device_uuid = b"not-yet-registered-uuid";
        let unregistered_login = login(
            Extension(state.clone()),
            Json(LoginRequest {
                username: "alice".to_owned(),
                password: "a-long-test-password".to_owned(),
                id: pending_device_id.to_owned(),
                uuid: base64::encode(pending_device_uuid),
                device_info: Value::Null,
                auto_login: true,
                r#type: "account".to_owned(),
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(unregistered_login["type"], "access_token");
        assert!(db.get_peer("not-yet-registered").await.unwrap().is_none());

        let mismatched_identity = login(
            Extension(state.clone()),
            Json(LoginRequest {
                username: "alice".to_owned(),
                password: "a-long-test-password".to_owned(),
                id: "test-device".to_owned(),
                uuid: base64::encode(b"wrong-device-uuid"),
                device_info: Value::Null,
                auto_login: true,
                r#type: "account".to_owned(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(mismatched_identity.status, StatusCode::FORBIDDEN);
        assert_eq!(
            db.get_peer("test-device").await.unwrap().unwrap().user,
            Some(b"alice".to_vec())
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        let current = current_user(
            Extension(state.clone()),
            headers.clone(),
            Some(Json(DeviceIdentity {
                id: "test-device".to_owned(),
                uuid: base64::encode(device_uuid),
            })),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(current.name, "alice");
        let expired_token = encode(
            &Header::default(),
            &Claims {
                sub: "alice".to_owned(),
                exp: Some(0),
            },
            &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
        )
        .unwrap();
        let mut expired_headers = HeaderMap::new();
        expired_headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("access_token {expired_token}").parse().unwrap(),
        );
        assert_eq!(
            current_user(Extension(state.clone()), expired_headers, None)
                .await
                .unwrap()
                .0
                .name,
            "alice"
        );
        let peers = list_peers(
            Extension(state.clone()),
            headers.clone(),
            Query(Pagination {
                current: Some(1),
                page_size: Some(100),
                status: Some(1),
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(peers["total"], 1);
        assert_eq!(peers["data"][0]["id"], "test-device");
        assert_eq!(peers["data"][0]["user"], "alice");
        assert_eq!(peers["data"][0]["online"], true);
        assert_eq!(peers["data"][0]["ip"], "192.0.2.10");
        {
            let peer = state.peer_map.get_or("test-device").await;
            peer.write().await.last_reg_time = Instant::now() - std::time::Duration::from_secs(60);
        }
        let offline_peers = list_peers(
            Extension(state.clone()),
            headers.clone(),
            Query(Pagination {
                current: Some(1),
                page_size: Some(100),
                status: Some(1),
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(offline_peers["data"][0]["online"], false);
        assert_eq!(offline_peers["data"][0]["ip"], "");
        state
            .peer_map
            .get_or("test-device")
            .await
            .write()
            .await
            .last_reg_time = Instant::now();
        assert_eq!(
            list_groups(
                Extension(state.clone()),
                headers.clone(),
                Query(Pagination {
                    current: Some(1),
                    page_size: Some(100),
                    status: None,
                }),
            )
            .await
            .unwrap()
            .0["total"],
            0
        );
        assert_eq!(
            list_admin_peers(
                Extension(state.clone()),
                headers.clone(),
                Query(Pagination {
                    current: Some(1),
                    page_size: Some(100),
                    status: None,
                }),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            update_peer(
                Extension(state.clone()),
                headers.clone(),
                Path("test-device".to_owned()),
                Json(UpdatePeer {
                    user: String::new(),
                    note: String::new(),
                }),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::FORBIDDEN
        );

        let bob_password_hash = hash("another-long-test-password", DEFAULT_COST).unwrap();
        state
            .db
            .create_user("bob", "Bob", "bob@example.com", &bob_password_hash, false)
            .await
            .unwrap();
        let pending_claim_denied = login(
            Extension(state.clone()),
            Json(LoginRequest {
                username: "bob".to_owned(),
                password: "another-long-test-password".to_owned(),
                id: pending_device_id.to_owned(),
                uuid: base64::encode(pending_device_uuid),
                device_info: Value::Null,
                auto_login: true,
                r#type: "account".to_owned(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(pending_claim_denied.status, StatusCode::FORBIDDEN);

        let bob_token = encode(
            &Header::default(),
            &Claims {
                sub: "bob".to_owned(),
                exp: Some(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as usize
                        + 3600,
                ),
            },
            &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
        )
        .unwrap();
        let mut bob_headers = HeaderMap::new();
        bob_headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {bob_token}").parse().unwrap(),
        );
        let bob_peers = list_peers(
            Extension(state.clone()),
            bob_headers,
            Query(Pagination {
                current: Some(1),
                page_size: Some(100),
                status: Some(1),
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(bob_peers["total"], 0);
        let admin_device = state.peer_map.get_or("stale-device").await;
        admin_device.write().await.last_reg_time =
            std::time::Instant::now() - std::time::Duration::from_secs(31);
        state
            .db
            .insert_peer("stale-device", b"stale-uuid", b"stale-key", "{}")
            .await
            .unwrap();
        state
            .db
            .update_peer_owner("stale-device", Some("alice"), "")
            .await
            .unwrap();
        let alice_peers = list_peers(
            Extension(state.clone()),
            headers.clone(),
            Query(Pagination {
                current: Some(1),
                page_size: Some(100),
                status: Some(1),
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(alice_peers["total"], 2);
        assert_eq!(alice_peers["data"][0]["id"], "stale-device");
        assert_eq!(alice_peers["data"][0]["online"], false);

        let denied = login(
            Extension(state.clone()),
            Json(LoginRequest {
                username: "bob".to_owned(),
                password: "another-long-test-password".to_owned(),
                id: "test-device".to_owned(),
                uuid: base64::encode(device_uuid),
                device_info: Value::Null,
                auto_login: true,
                r#type: "account".to_owned(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(denied.status, StatusCode::FORBIDDEN);

        let existing_session_uuid = b"existing-session-uuid";
        state
            .db
            .insert_peer(
                "existing-session-device",
                existing_session_uuid,
                b"existing-session-key",
                "{}",
            )
            .await
            .unwrap();
        current_user(
            Extension(state.clone()),
            headers.clone(),
            Some(Json(DeviceIdentity {
                id: "existing-session-device".to_owned(),
                uuid: base64::encode(existing_session_uuid),
            })),
        )
        .await
        .unwrap();
        assert_eq!(
            state
                .db
                .get_peer("existing-session-device")
                .await
                .unwrap()
                .unwrap()
                .user,
            Some(b"alice".to_vec())
        );

        let mut peer_map = PeerMap::with_database(state.db.clone());
        let peer = peer_map.get_or(pending_device_id).await;
        let registration_result = peer_map
            .update_pk(
                pending_device_id.to_owned(),
                peer,
                "192.0.2.20:21116".parse().unwrap(),
                hbb_common::bytes::Bytes::copy_from_slice(pending_device_uuid),
                hbb_common::bytes::Bytes::from_static(b"new-device-key"),
                "192.0.2.20".to_owned(),
            )
            .await;
        assert_eq!(
            registration_result,
            hbb_common::rendezvous_proto::register_pk_response::Result::OK
        );
        assert_eq!(
            state
                .db
                .get_peer(pending_device_id)
                .await
                .unwrap()
                .unwrap()
                .user,
            Some(b"alice".to_vec())
        );

        let error = list_admin_users(
            Extension(state),
            headers,
            Query(Pagination {
                current: Some(1),
                page_size: Some(100),
                status: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn administrators_can_create_update_and_delete_users() {
        admin_user_crud();
    }

    #[tokio::main(flavor = "current_thread")]
    async fn admin_user_crud() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let db = Database::new(file.path().to_str().unwrap()).await.unwrap();
        let password_hash = hash("a-long-admin-password", DEFAULT_COST).unwrap();
        db.create_user("admin", "Admin", "admin@example.com", &password_hash, true)
            .await
            .unwrap();
        let state = ApiState {
            db: db.clone(),
            jwt_secret: "test-secret".to_owned(),
            peer_map: PeerMap::with_database(db.clone()),
            started_at: Instant::now(),
            api_address: "127.0.0.1:21114".parse().unwrap(),
            rendezvous_address: "127.0.0.1:21116".parse().unwrap(),
            relay_servers: Vec::new(),
        };
        db.insert_peer("admin-device", b"device-uuid", b"device-key", "{}")
            .await
            .unwrap();
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize
            + 3600;
        let token = encode(
            &Header::default(),
            &Claims {
                sub: "admin".to_owned(),
                exp: Some(expires_at),
            },
            &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );

        let (status, created) = create_user(
            Extension(state.clone()),
            headers.clone(),
            Json(CreateUser {
                name: "alice".to_owned(),
                email: "alice@example.com".to_owned(),
                password: "a-long-user-password".to_owned(),
                display_name: "Alice".to_owned(),
                is_admin: false,
            }),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::CREATED);

        assert_eq!(
            update_peer(
                Extension(state.clone()),
                headers.clone(),
                Path("admin-device".to_owned()),
                Json(UpdatePeer {
                    user: "alice".to_owned(),
                    note: "Office workstation".to_owned(),
                }),
            )
            .await
            .unwrap(),
            StatusCode::NO_CONTENT
        );
        let listed = list_admin_peers(
            Extension(state.clone()),
            headers.clone(),
            Query(Pagination {
                current: Some(1),
                page_size: Some(100),
                status: None,
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(listed["total"], 1);
        assert_eq!(listed["data"][0]["user"], "alice");
        assert_eq!(listed["data"][0]["note"], "Office workstation");

        let updated = update_user(
            Extension(state.clone()),
            headers.clone(),
            Path(created.id),
            Json(UpdateUser {
                email: "alice@example.com".to_owned(),
                display_name: "Alice Updated".to_owned(),
                is_admin: false,
                status: 0,
                password: None,
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(updated.display_name, "Alice Updated");
        assert_eq!(updated.status, 0);

        assert_eq!(
            delete_user(Extension(state), headers, Path(created.id))
                .await
                .unwrap(),
            StatusCode::NO_CONTENT
        );
        assert!(db.get_user_by_id(created.id).await.unwrap().is_none());
        assert_eq!(
            db.get_peer("admin-device").await.unwrap().unwrap().user,
            None
        );
    }
}
