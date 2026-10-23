use crate::{
    common::get_arg_opt,
    database::{Database, User},
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
use std::{
    net::{IpAddr, SocketAddr},
    time::{SystemTime, UNIX_EPOCH},
};
use tower_http::cors::CorsLayer;

#[derive(Clone)]
struct ApiState {
    db: Database,
    jwt_secret: String,
    peer_map: PeerMap,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
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
struct Pagination {
    current: Option<i64>,
    #[serde(rename = "pageSize")]
    page_size: Option<i64>,
    status: Option<i64>,
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

#[derive(Serialize)]
struct UserPayload {
    id: i64,
    name: String,
    display_name: String,
    email: String,
    avatar: String,
    note: String,
    is_admin: bool,
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
            status: user.status,
        }
    }
}

pub(crate) async fn start(
    peer_map: PeerMap,
    bind_addr: Option<IpAddr>,
    port: u16,
) -> hbb_common::ResultType<tokio::task::JoinHandle<hbb_common::ResultType<()>>> {
    let db = peer_map.db.clone();
    let jwt_secret = db.get_or_create_api_secret().await?;
    bootstrap_admin(&db).await?;
    let state = ApiState {
        db,
        jwt_secret,
        peer_map,
    };
    let app = Router::new()
        .route("/api/login", post(login))
        .route("/api/login-options", get(login_options))
        .route("/api/currentUser", post(current_user))
        .route("/api/logout", post(logout))
        .route("/api/users", get(list_users))
        .route("/api/peers", get(list_peers))
        .route("/api/device-group/accessible", get(list_groups))
        .route("/api/admin/peers", get(list_admin_peers))
        .route("/api/admin/peers/:id", put(update_peer))
        .route("/api/admin/users", get(list_admin_users).post(create_user))
        .route("/api/admin/users/:id", put(update_user).delete(delete_user))
        .layer(Extension(state))
        .layer(CorsLayer::permissive());
    let address = SocketAddr::new(bind_addr.unwrap_or(IpAddr::from([0, 0, 0, 0])), port);
    let listener = tokio::net::TcpListener::bind(address).await?;
    let listener = listener.into_std()?;
    log::info!("User API listening on http://{}", address);
    let server = axum::Server::from_tcp(listener)?;
    Ok(tokio::spawn(async move {
        server
            .serve(app.into_make_service())
            .await
            .map_err(Into::into)
    }))
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
        if request.id.trim() != request.id
            || request.id.len() > crate::peer::MAX_PEER_ID_LEN
            || request.uuid.len() > 512
        {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "Invalid device identity",
            ));
        }
        let uuid = base64::decode(&request.uuid)
            .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "Invalid device identity"))?;
        let claimed = state
            .db
            .claim_peer(&request.id, &uuid, &user.name)
            .await
            .map_err(|error| {
                log::error!("Failed to claim login device: {}", error);
                ApiError::internal()
            })?;
        if !claimed {
            let peer = state.db.get_peer(&request.id).await.map_err(|error| {
                log::error!("Failed to verify login device: {}", error);
                ApiError::internal()
            })?;
            let message = match peer {
                Some(peer) if peer.uuid == uuid => "Device belongs to another account",
                _ => "Device identity is not registered on this server",
            };
            return Err(ApiError::new(StatusCode::FORBIDDEN, message));
        }
    }
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApiError::internal())?
        .as_secs() as usize
        + 8 * 60 * 60;
    let token = encode(
        &Header::default(),
        &Claims {
            sub: user.name.clone(),
            exp: expires_at,
        },
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    )
    .map_err(|error| {
        log::error!("Failed to create API access token: {}", error);
        ApiError::internal()
    })?;
    Ok(Json(json!({
        "type": "access_token",
        "access_token": token,
        "user": UserPayload::from(user),
    })))
}

async fn login_options() -> Json<Vec<String>> {
    Json(Vec::new())
}

async fn current_user(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
) -> Result<Json<UserPayload>, ApiError> {
    let user = authenticated_user(&state, &headers).await?;
    Ok(Json(user.into()))
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
    let user = authenticated_user(&state, &headers).await?;
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
    require_admin(&state, &headers).await?;
    users_response(&state.db, query, false, None).await
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
    let user = authenticated_user(&state, &headers).await?;
    peers_response(
        &state.db,
        &state.peer_map,
        query,
        (!user.is_admin).then_some(user.name),
    )
    .await
}

async fn list_groups(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Query(query): Query<Pagination>,
) -> Result<Json<Value>, ApiError> {
    authenticated_user(&state, &headers).await?;
    let current = query.current.unwrap_or(1).max(1);
    Ok(Json(json!({ "total": 0, "data": [], "current": current })))
}

async fn list_admin_peers(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Query(query): Query<Pagination>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&state, &headers).await?;
    peers_response(&state.db, &state.peer_map, query, None).await
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
    require_admin(&state, &headers).await?;
    if id.trim().is_empty() || id.len() > crate::peer::MAX_PEER_ID_LEN {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "Invalid device ID"));
    }
    if request.note.len() > 300 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Device note must be 300 bytes or fewer",
        ));
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
    Ok(StatusCode::NO_CONTENT)
}

async fn peers_response(
    db: &Database,
    peer_map: &PeerMap,
    query: Pagination,
    owner: Option<String>,
) -> Result<Json<Value>, ApiError> {
    let current = query.current.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(100).clamp(1, 200);
    let (peers, total) = db
        .list_peers(
            owner.as_deref(),
            query.status,
            page_size,
            (current - 1) * page_size,
        )
        .await
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
        data.push(json!({
            "id": peer.id,
            "info": info,
            "status": peer.status.unwrap_or(1),
            "online": online,
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
    require_admin(&state, &headers).await?;
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
    let actor = require_admin(&state, &headers).await?;
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
    let actor = require_admin(&state, &headers).await?;
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
    Ok(StatusCode::NO_CONTENT)
}

async fn require_admin(state: &ApiState, headers: &HeaderMap) -> Result<User, ApiError> {
    let user = authenticated_user(state, headers).await?;
    if !user.is_admin {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "Admin required!"));
    }
    Ok(user)
}

async fn authenticated_user(state: &ApiState, headers: &HeaderMap) -> Result<User, ApiError> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .or_else(|| {
            headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("access_token "))
        })
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "Authentication required"))?;
    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
        &Validation::default(),
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
        peer_map
            .get_or("test-device")
            .await
            .write()
            .await
            .last_reg_time = std::time::Instant::now();
        let state = ApiState {
            db: db.clone(),
            jwt_secret: "test-secret".to_owned(),
            peer_map,
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
        assert!(response["user"]["id"].is_number());
        assert_eq!(response["user"]["name"], "alice");
        assert!(response["user"].get("password_hash").is_none());
        assert_eq!(
            db.get_peer("test-device").await.unwrap().unwrap().user,
            Some(b"alice".to_vec())
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        let current = current_user(Extension(state.clone()), headers.clone())
            .await
            .unwrap()
            .0;
        assert_eq!(current.name, "alice");
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
        let bob_token = encode(
            &Header::default(),
            &Claims {
                sub: "bob".to_owned(),
                exp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as usize
                    + 3600,
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
                exp: expires_at,
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
