use async_trait::async_trait;
use hbb_common::{log, ResultType};
use serde::{Deserialize, Serialize};
use sqlx::{
    sqlite::SqliteConnectOptions, ConnectOptions, Connection, Error as SqlxError, QueryBuilder,
    Sqlite, SqliteConnection,
};
use std::{ops::DerefMut, str::FromStr};
//use sqlx::postgres::PgPoolOptions;
//use sqlx::mysql::MySqlPoolOptions;

type Pool = deadpool::managed::Pool<DbPool>;

pub struct DbPool {
    url: String,
}

#[async_trait]
impl deadpool::managed::Manager for DbPool {
    type Type = SqliteConnection;
    type Error = SqlxError;
    async fn create(&self) -> Result<SqliteConnection, SqlxError> {
        let mut opt = SqliteConnectOptions::from_str(&self.url).unwrap();
        opt.log_statements(log::LevelFilter::Debug);
        SqliteConnection::connect_with(&opt).await
    }
    async fn recycle(
        &self,
        obj: &mut SqliteConnection,
    ) -> deadpool::managed::RecycleResult<SqlxError> {
        Ok(obj.ping().await?)
    }
}

#[derive(Clone)]
pub struct Database {
    pool: Pool,
}

#[derive(Default, sqlx::FromRow)]
pub struct Peer {
    pub guid: Vec<u8>,
    pub id: String,
    pub uuid: Vec<u8>,
    pub pk: Vec<u8>,
    pub user: Option<Vec<u8>>,
    pub info: String,
    pub status: Option<i64>,
    pub note: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PeerClaimResult {
    Claimed,
    Pending,
    OwnedByAnotherAccount,
    IdentityMismatch,
    PendingForAnotherAccount,
}

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct User {
    pub id: i64,
    pub name: String,
    pub display_name: String,
    pub email: String,
    pub avatar: String,
    pub note: String,
    pub password_hash: String,
    pub is_admin: bool,
    pub status: i64,
    pub created_at: String,
}

#[derive(Clone, Debug, Serialize, sqlx::FromRow)]
pub struct DeviceGroup {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub device_count: i64,
}

#[derive(Clone, Debug, Serialize, sqlx::FromRow)]
pub struct UserGroup {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub member_count: i64,
}

#[derive(Clone, Debug, Serialize, sqlx::FromRow)]
pub struct AddressBook {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub permission: String,
    pub entry_count: i64,
    pub is_personal: bool,
}

#[derive(Clone, Debug, Serialize, sqlx::FromRow)]
pub struct AddressBookEntry {
    pub id: i64,
    pub device_id: String,
    pub alias: String,
    pub note: String,
    pub tags: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct AddressBookPermission {
    pub subject_type: String,
    pub subject_id: i64,
    pub access: String,
}

#[derive(Clone, Debug, Serialize, sqlx::FromRow)]
pub struct AuditLog {
    pub id: i64,
    pub actor_id: i64,
    pub actor_name: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub summary: String,
    pub created_at: String,
}

#[derive(Clone, Debug, Serialize, sqlx::FromRow)]
pub struct ApiToken {
    pub id: i64,
    pub name: String,
    pub token_prefix: String,
    pub scopes: String,
    pub expires_at: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
}

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct ApiTokenAuth {
    pub owner_id: i64,
    pub scopes: String,
}

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct DelegatedRole {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub permissions: String,
    pub user_group_ids: String,
    pub device_group_ids: String,
    pub created_at: String,
}

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct DelegatedRoleAccess {
    pub permissions: String,
    pub user_group_ids: String,
    pub device_group_ids: String,
}

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct ServiceResourceCounts {
    pub total_users: i64,
    pub active_users: i64,
    pub total_devices: i64,
    pub device_groups: i64,
    pub user_groups: i64,
}

impl Database {
    pub async fn new(url: &str) -> ResultType<Database> {
        if !std::path::Path::new(url).exists() {
            std::fs::File::create(url).ok();
        }
        let n: usize = crate::common::get_arg_or("MAX_DATABASE_CONNECTIONS", "1".to_owned())
            .parse()
            .unwrap_or(1);
        log::debug!("MAX_DATABASE_CONNECTIONS={}", n);
        let pool = Pool::new(
            DbPool {
                url: url.to_owned(),
            },
            n,
        );
        let _ = pool.get().await?; // test
        let db = Database { pool };
        db.create_tables().await?;
        Ok(db)
    }

    async fn create_tables(&self) -> ResultType<()> {
        sqlx::query!(
            "
            create table if not exists peer (
                guid blob primary key not null,
                id varchar(100) not null,
                uuid blob not null,
                pk blob not null,
                created_at datetime not null default(current_timestamp),
                user blob,
                status tinyint,
                note varchar(300),
                info text not null
            ) without rowid;
            create unique index if not exists index_peer_id on peer (id);
            create index if not exists index_peer_user on peer (user);
            create index if not exists index_peer_created_at on peer (created_at);
            create index if not exists index_peer_status on peer (status);

        "
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        sqlx::query(
            "create table if not exists pending_peer_claims (
                id varchar(253) primary key not null,
                uuid blob not null,
                user blob not null,
                created_at datetime not null default(current_timestamp)
            ) without rowid;",
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        sqlx::query(
            "create table if not exists users (
                id integer primary key autoincrement,
                name varchar(64) not null collate nocase unique,
                display_name varchar(128) not null default '',
                email varchar(254) not null collate nocase unique,
                avatar text not null default '',
                note varchar(300) not null default '',
                password_hash varchar(100) not null,
                is_admin integer not null default 0,
                status integer not null default 1,
                created_at datetime not null default(current_timestamp)
            );
            create index if not exists index_users_status on users (status);
            create table if not exists app_config (
                key varchar(100) primary key not null,
                value text not null
            );
            create table if not exists device_groups (
                id integer primary key autoincrement,
                name varchar(100) not null collate nocase unique,
                description varchar(300) not null default '',
                created_at datetime not null default(current_timestamp)
            );
            create table if not exists device_group_peers (
                group_id integer not null,
                peer_id varchar(100) not null,
                primary key (group_id, peer_id)
            );
            create index if not exists index_device_group_peers_peer_id
                on device_group_peers (peer_id);
            create table if not exists user_groups (
                id integer primary key autoincrement,
                name varchar(100) not null collate nocase unique,
                description varchar(300) not null default '',
                created_at datetime not null default(current_timestamp)
            );
            create table if not exists user_group_members (
                group_id integer not null,
                user_id integer not null,
                primary key (group_id, user_id)
            );
            create index if not exists index_user_group_members_user_id
                on user_group_members (user_id);
            create table if not exists address_books (
                id integer primary key autoincrement,
                name varchar(100) not null collate nocase,
                description varchar(300) not null default '',
                owner_id integer,
                created_at datetime not null default(current_timestamp)
            );
            create table if not exists address_book_entries (
                id integer primary key autoincrement,
                book_id integer not null,
                device_id varchar(100) not null,
                alias varchar(100) not null default '',
                note varchar(300) not null default '',
                tags text not null default '[]',
                unique (book_id, device_id)
            );
            create index if not exists index_address_book_entries_book_id
                on address_book_entries (book_id);
            create table if not exists address_book_permissions (
                book_id integer not null,
                subject_type varchar(20) not null,
                subject_id integer not null default 0,
                access varchar(20) not null,
                primary key (book_id, subject_type, subject_id)
            );
            create index if not exists index_address_book_permissions_subject
                on address_book_permissions (subject_type, subject_id);
            create table if not exists admin_audit_logs (
                id integer primary key autoincrement,
                actor_id integer not null,
                actor_name varchar(64) not null,
                action varchar(40) not null,
                resource_type varchar(40) not null,
                resource_id varchar(200) not null,
                summary varchar(300) not null,
                created_at datetime not null default(current_timestamp)
            );
            create index if not exists index_admin_audit_logs_created_at
                on admin_audit_logs (created_at);
            create index if not exists index_admin_audit_logs_actor
                on admin_audit_logs (actor_name, created_at);
            create table if not exists api_tokens (
                id integer primary key autoincrement,
                owner_id integer not null,
                name varchar(80) not null,
                token_prefix varchar(16) not null,
                token_hash varchar(64) not null unique,
                scopes text not null,
                expires_at datetime not null,
                created_at datetime not null default(current_timestamp),
                last_used_at datetime,
                revoked_at datetime
            );
            create index if not exists index_api_tokens_owner
                on api_tokens (owner_id, created_at);
            create table if not exists delegated_roles (
                id integer primary key autoincrement,
                name varchar(100) not null collate nocase unique,
                description varchar(300) not null default '',
                permissions text not null,
                user_group_ids text not null,
                device_group_ids text not null,
                created_at datetime not null default(current_timestamp)
            );
            create table if not exists delegated_role_members (
                role_id integer not null,
                user_id integer not null,
                primary key (role_id, user_id)
            );
            create index if not exists index_delegated_role_members_user
                on delegated_role_members (user_id);",
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        self.migrate_address_book_owners().await?;
        sqlx::query(
            "create unique index if not exists index_address_books_shared_name \
               on address_books(name collate nocase) where owner_id is null;
             create unique index if not exists index_address_books_personal_name \
               on address_books(owner_id, name collate nocase) where owner_id is not null;",
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    async fn migrate_address_book_owners(&self) -> ResultType<()> {
        let has_owner_column: i64 = sqlx::query_scalar(
            "select count(*) from pragma_table_info('address_books') where name = 'owner_id'",
        )
        .fetch_one(self.pool.get().await?.deref_mut())
        .await?;
        if has_owner_column != 0 {
            return Ok(());
        }

        let mut conn = self.pool.get().await?;
        let mut tx = conn.begin().await?;
        sqlx::query("alter table address_books rename to address_books_legacy")
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "create table address_books (
                id integer primary key autoincrement,
                name varchar(100) not null collate nocase,
                description varchar(300) not null default '',
                owner_id integer,
                created_at datetime not null default(current_timestamp)
            )",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "insert into address_books(id, name, description, created_at) \
             select id, name, description, created_at from address_books_legacy",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query("drop table address_books_legacy")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn get_peer(&self, id: &str) -> ResultType<Option<Peer>> {
        Ok(sqlx::query_as!(
            Peer,
            "select guid, id, uuid, pk, user, status, info, coalesce(note, '') as \"note!\" from peer where id = ?",
            id
        )
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?)
    }

    pub async fn list_peers(
        &self,
        owner: Option<&str>,
        status: Option<i64>,
        limit: i64,
        offset: i64,
    ) -> ResultType<(Vec<Peer>, i64)> {
        let owner = owner.map(str::as_bytes);
        let mut conn = self.pool.get().await?;
        let peers = sqlx::query_as::<_, Peer>(
            "select guid, id, uuid, pk, user, status, info, coalesce(note, '') as note \
             from peer \
             where (? is null or user = ?) \
               and (? is null or coalesce(status, 1) = ?) \
             order by id limit ? offset ?",
        )
        .bind(owner)
        .bind(owner)
        .bind(status)
        .bind(status)
        .bind(limit)
        .bind(offset)
        .fetch_all(conn.deref_mut())
        .await?;
        let total = sqlx::query_scalar::<_, i64>(
            "select count(*) from peer \
             where (? is null or user = ?) \
               and (? is null or coalesce(status, 1) = ?)",
        )
        .bind(owner)
        .bind(owner)
        .bind(status)
        .bind(status)
        .fetch_one(conn.deref_mut())
        .await?;
        Ok((peers, total))
    }

    pub async fn list_peers_by_ids(
        &self,
        ids: &[String],
        limit: i64,
        offset: i64,
    ) -> ResultType<(Vec<Peer>, i64)> {
        if ids.is_empty() {
            return Ok((Vec::new(), 0));
        }
        let encoded_ids = serde_json::to_string(ids)?;
        let mut conn = self.pool.get().await?;
        let peers = sqlx::query_as::<_, Peer>(
            "select guid, id, uuid, pk, user, status, info, coalesce(note, '') as note \
             from peer where id in (select value from json_each(?)) \
             order by id limit ? offset ?",
        )
        .bind(&encoded_ids)
        .bind(limit)
        .bind(offset)
        .fetch_all(conn.deref_mut())
        .await?;
        let total = sqlx::query_scalar::<_, i64>(
            "select count(*) from peer where id in (select value from json_each(?))",
        )
        .bind(encoded_ids)
        .fetch_one(conn.deref_mut())
        .await?;
        Ok((peers, total))
    }

    pub async fn claim_or_defer_peer(
        &self,
        id: &str,
        uuid: &[u8],
        owner: &str,
    ) -> ResultType<PeerClaimResult> {
        let owner = owner.as_bytes();
        let mut conn = self.pool.get().await?;
        let mut tx = conn.begin().await?;
        let peer = sqlx::query_as::<_, (Vec<u8>, Option<Vec<u8>>)>(
            "select uuid, user from peer where id = ?",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let result = if let Some((registered_uuid, registered_owner)) = peer {
            if registered_uuid != uuid {
                PeerClaimResult::IdentityMismatch
            } else if let Some(registered_owner) = registered_owner {
                if registered_owner == owner {
                    PeerClaimResult::Claimed
                } else {
                    PeerClaimResult::OwnedByAnotherAccount
                }
            } else {
                sqlx::query("update peer set user = ? where id = ? and uuid = ? and user is null")
                    .bind(owner)
                    .bind(id)
                    .bind(uuid)
                    .execute(&mut *tx)
                    .await?;
                PeerClaimResult::Claimed
            }
        } else {
            let pending_owner = sqlx::query_scalar::<_, Vec<u8>>(
                "select user from pending_peer_claims where id = ?",
            )
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
            match pending_owner {
                Some(pending_owner) if pending_owner != owner => {
                    PeerClaimResult::PendingForAnotherAccount
                }
                Some(_) => {
                    sqlx::query("update pending_peer_claims set uuid = ? where id = ?")
                        .bind(uuid)
                        .bind(id)
                        .execute(&mut *tx)
                        .await?;
                    PeerClaimResult::Pending
                }
                None => {
                    sqlx::query("insert into pending_peer_claims(id, uuid, user) values(?, ?, ?)")
                        .bind(id)
                        .bind(uuid)
                        .bind(owner)
                        .execute(&mut *tx)
                        .await?;
                    PeerClaimResult::Pending
                }
            }
        };
        tx.commit().await?;
        Ok(result)
    }

    pub async fn update_peer_owner(
        &self,
        id: &str,
        owner: Option<&str>,
        note: &str,
    ) -> ResultType<bool> {
        let result = sqlx::query("update peer set user = ?, note = ? where id = ?")
            .bind(owner.map(str::as_bytes))
            .bind(note)
            .bind(id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn insert_peer(
        &self,
        id: &str,
        uuid: &[u8],
        pk: &[u8],
        info: &str,
    ) -> ResultType<Vec<u8>> {
        let guid = uuid::Uuid::new_v4().as_bytes().to_vec();
        let mut conn = self.pool.get().await?;
        let mut tx = conn.begin().await?;
        let owner = sqlx::query_scalar::<_, Vec<u8>>(
            "select pending.user from pending_peer_claims pending \
             join users on cast(users.name as blob) = pending.user and users.status = 1 \
             where pending.id = ? and pending.uuid = ?",
        )
        .bind(id)
        .bind(uuid)
        .fetch_optional(&mut *tx)
        .await?;
        sqlx::query("insert into peer(guid, id, uuid, pk, user, info) values(?, ?, ?, ?, ?, ?)")
            .bind(&guid)
            .bind(id)
            .bind(uuid)
            .bind(pk)
            .bind(owner)
            .bind(info)
            .execute(&mut *tx)
            .await?;
        sqlx::query("delete from pending_peer_claims where id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(guid)
    }

    pub async fn update_pk(
        &self,
        guid: &Vec<u8>,
        id: &str,
        uuid: &[u8],
        pk: &[u8],
        info: &str,
    ) -> ResultType<()> {
        let mut conn = self.pool.get().await?;
        let mut tx = conn.begin().await?;
        sqlx::query(
            "update peer set id = ?, pk = ?, info = ?, \
             user = coalesce(user, ( \
                 select pending.user from pending_peer_claims pending \
                 join users on cast(users.name as blob) = pending.user and users.status = 1 \
                 where pending.id = ? and pending.uuid = ? \
             )) where guid = ?",
        )
        .bind(id)
        .bind(pk)
        .bind(info)
        .bind(id)
        .bind(uuid)
        .bind(guid)
        .execute(&mut *tx)
        .await?;
        sqlx::query("delete from pending_peer_claims where id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn get_user_by_name(&self, name: &str) -> ResultType<Option<User>> {
        Ok(sqlx::query_as::<_, User>(
            "select id, name, display_name, email, avatar, note, password_hash, is_admin, status, created_at from users where name = ? or email = ?",
        )
        .bind(name)
        .bind(name)
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?)
    }

    pub async fn get_user_by_id(&self, id: i64) -> ResultType<Option<User>> {
        Ok(sqlx::query_as::<_, User>(
            "select id, name, display_name, email, avatar, note, password_hash, is_admin, status, created_at from users where id = ?",
        )
        .bind(id)
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?)
    }

    pub async fn list_users(
        &self,
        status: Option<i64>,
        limit: i64,
        offset: i64,
    ) -> ResultType<(Vec<User>, i64)> {
        let mut conn = self.pool.get().await?;
        let (users, total) = if let Some(status) = status {
            let users = sqlx::query_as::<_, User>(
                "select id, name, display_name, email, avatar, note, password_hash, is_admin, status, created_at from users where status = ? order by id limit ? offset ?",
            )
            .bind(status)
            .bind(limit)
            .bind(offset)
            .fetch_all(conn.deref_mut())
            .await?;
            let total: i64 = sqlx::query_scalar("select count(*) from users where status = ?")
                .bind(status)
                .fetch_one(conn.deref_mut())
                .await?;
            (users, total)
        } else {
            let users = sqlx::query_as::<_, User>(
                "select id, name, display_name, email, avatar, note, password_hash, is_admin, status, created_at from users order by id limit ? offset ?",
            )
            .bind(limit)
            .bind(offset)
            .fetch_all(conn.deref_mut())
            .await?;
            let total: i64 = sqlx::query_scalar("select count(*) from users")
                .fetch_one(conn.deref_mut())
                .await?;
            (users, total)
        };
        Ok((users, total))
    }

    pub async fn list_users_in_groups(
        &self,
        group_ids: &[i64],
        status: Option<i64>,
        limit: i64,
        offset: i64,
    ) -> ResultType<(Vec<User>, i64)> {
        if group_ids.is_empty() {
            return Ok((Vec::new(), 0));
        }
        let mut conn = self.pool.get().await?;
        let group_placeholders = vec!["?"; group_ids.len()].join(", ");
        let users_sql = format!(
            "select id, name, display_name, email, avatar, note, password_hash, is_admin, status, created_at from users where (? is null or status = ?) and exists (select 1 from user_group_members gm where gm.user_id = users.id and gm.group_id in ({group_placeholders})) order by id limit ? offset ?"
        );
        let mut users_query = sqlx::query_as::<_, User>(&users_sql)
            .bind(status)
            .bind(status);
        for group_id in group_ids {
            users_query = users_query.bind(group_id);
        }
        let users = users_query
            .bind(limit)
            .bind(offset)
            .fetch_all(conn.deref_mut())
            .await?;

        let count_sql = format!(
            "select count(*) from users where (? is null or status = ?) and exists (select 1 from user_group_members gm where gm.user_id = users.id and gm.group_id in ({group_placeholders}))"
        );
        let mut count_query = sqlx::query_scalar::<_, i64>(&count_sql)
            .bind(status)
            .bind(status);
        for group_id in group_ids {
            count_query = count_query.bind(group_id);
        }
        let total = count_query.fetch_one(conn.deref_mut()).await?;
        Ok((users, total))
    }

    pub async fn list_peers_in_groups(
        &self,
        group_ids: &[i64],
        status: Option<i64>,
        limit: i64,
        offset: i64,
    ) -> ResultType<(Vec<Peer>, i64)> {
        if group_ids.is_empty() {
            return Ok((Vec::new(), 0));
        }
        let mut conn = self.pool.get().await?;
        let group_placeholders = vec!["?"; group_ids.len()].join(", ");
        let peers_sql = format!(
            "select guid, id, uuid, pk, user, status, info, coalesce(note, '') as note from peer where (? is null or coalesce(status, 1) = ?) and exists (select 1 from device_group_peers gp where gp.peer_id = peer.id and gp.group_id in ({group_placeholders})) order by id limit ? offset ?"
        );
        let mut peers_query = sqlx::query_as::<_, Peer>(&peers_sql)
            .bind(status)
            .bind(status);
        for group_id in group_ids {
            peers_query = peers_query.bind(group_id);
        }
        let peers = peers_query
            .bind(limit)
            .bind(offset)
            .fetch_all(conn.deref_mut())
            .await?;

        let count_sql = format!(
            "select count(*) from peer where (? is null or coalesce(status, 1) = ?) and exists (select 1 from device_group_peers gp where gp.peer_id = peer.id and gp.group_id in ({group_placeholders}))"
        );
        let mut count_query = sqlx::query_scalar::<_, i64>(&count_sql)
            .bind(status)
            .bind(status);
        for group_id in group_ids {
            count_query = count_query.bind(group_id);
        }
        let total = count_query.fetch_one(conn.deref_mut()).await?;
        Ok((peers, total))
    }

    pub async fn update_user_in_groups(
        &self,
        id: i64,
        display_name: &str,
        email: &str,
        password_hash: Option<&str>,
        group_ids: &[i64],
    ) -> ResultType<bool> {
        if group_ids.is_empty() {
            return Ok(false);
        }
        let mut query = QueryBuilder::<Sqlite>::new("update users set display_name = ");
        query
            .push_bind(display_name)
            .push(", email = ")
            .push_bind(email)
            .push(", password_hash = coalesce(")
            .push_bind(password_hash)
            .push(", password_hash) where id = ")
            .push_bind(id)
            .push(" and is_admin = 0 and status = 1 and exists (select 1 from user_group_members gm where gm.user_id = users.id and gm.group_id in (");
        for (index, group_id) in group_ids.iter().enumerate() {
            if index > 0 {
                query.push(", ");
            }
            query.push_bind(group_id);
        }
        query.push("))");
        let result = query
            .build()
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn update_peer_note_in_groups(
        &self,
        id: &str,
        note: &str,
        expected_owner: Option<&str>,
        group_ids: &[i64],
    ) -> ResultType<bool> {
        if group_ids.is_empty() {
            return Ok(false);
        }
        let mut query = QueryBuilder::<Sqlite>::new("update peer set note = ");
        let owner_bytes = expected_owner.map(str::as_bytes);
        query
            .push_bind(note)
            .push(" where id = ")
            .push_bind(id)
            .push(" and (( ")
            .push_bind(owner_bytes)
            .push(" is null and user is null) or user = ")
            .push_bind(owner_bytes)
            .push(") and exists (select 1 from device_group_peers gp where gp.peer_id = peer.id and gp.group_id in (");
        for (index, group_id) in group_ids.iter().enumerate() {
            if index > 0 {
                query.push(", ");
            }
            query.push_bind(group_id);
        }
        query.push("))");
        let result = query
            .build()
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn delegated_role_group_ids_exist(
        &self,
        user_group_ids: &[i64],
        device_group_ids: &[i64],
    ) -> ResultType<bool> {
        let user_count: i64 = sqlx::query_scalar(
            "select count(*) from user_groups where id in (select value from json_each(?))",
        )
        .bind(serde_json::to_string(user_group_ids)?)
        .fetch_one(self.pool.get().await?.deref_mut())
        .await?;
        let device_count: i64 = sqlx::query_scalar(
            "select count(*) from device_groups where id in (select value from json_each(?))",
        )
        .bind(serde_json::to_string(device_group_ids)?)
        .fetch_one(self.pool.get().await?.deref_mut())
        .await?;
        Ok(user_count == user_group_ids.len() as i64
            && device_count == device_group_ids.len() as i64)
    }

    pub async fn delegated_role_member_ids_exist(&self, user_ids: &[i64]) -> ResultType<bool> {
        let count: i64 = sqlx::query_scalar(
            "select count(*) from users where id in (select value from json_each(?))",
        )
        .bind(serde_json::to_string(user_ids)?)
        .fetch_one(self.pool.get().await?.deref_mut())
        .await?;
        Ok(count == user_ids.len() as i64)
    }

    pub async fn list_delegated_roles(&self) -> ResultType<Vec<(DelegatedRole, Vec<i64>)>> {
        let mut conn = self.pool.get().await?;
        let roles = sqlx::query_as::<_, DelegatedRole>(
            "select id, name, description, permissions, user_group_ids, device_group_ids, created_at from delegated_roles order by name collate nocase",
        )
        .fetch_all(conn.deref_mut())
        .await?;
        let mut result = Vec::with_capacity(roles.len());
        for role in roles {
            let members = sqlx::query_scalar(
                "select user_id from delegated_role_members where role_id = ? order by user_id",
            )
            .bind(role.id)
            .fetch_all(conn.deref_mut())
            .await?;
            result.push((role, members));
        }
        Ok(result)
    }

    pub async fn create_delegated_role(
        &self,
        name: &str,
        description: &str,
        permissions: &str,
        user_group_ids: &str,
        device_group_ids: &str,
        user_ids: &[i64],
    ) -> ResultType<i64> {
        let mut conn = self.pool.get().await?;
        let mut tx = conn.begin().await?;
        let result = sqlx::query(
            "insert into delegated_roles(name, description, permissions, user_group_ids, device_group_ids) values(?, ?, ?, ?, ?)",
        )
        .bind(name)
        .bind(description)
        .bind(permissions)
        .bind(user_group_ids)
        .bind(device_group_ids)
        .execute(&mut *tx)
        .await?;
        let id = result.last_insert_rowid();
        for user_id in user_ids {
            sqlx::query("insert into delegated_role_members(role_id, user_id) values(?, ?)")
                .bind(id)
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(id)
    }

    pub async fn update_delegated_role(
        &self,
        id: i64,
        name: &str,
        description: &str,
        permissions: &str,
        user_group_ids: &str,
        device_group_ids: &str,
        user_ids: &[i64],
    ) -> ResultType<bool> {
        let mut conn = self.pool.get().await?;
        let mut tx = conn.begin().await?;
        let result = sqlx::query(
            "update delegated_roles set name = ?, description = ?, permissions = ?, user_group_ids = ?, device_group_ids = ? where id = ?",
        )
        .bind(name)
        .bind(description)
        .bind(permissions)
        .bind(user_group_ids)
        .bind(device_group_ids)
        .bind(id)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(false);
        }
        sqlx::query("delete from delegated_role_members where role_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        for user_id in user_ids {
            sqlx::query("insert into delegated_role_members(role_id, user_id) values(?, ?)")
                .bind(id)
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(true)
    }

    pub async fn delete_delegated_role(&self, id: i64) -> ResultType<bool> {
        let mut conn = self.pool.get().await?;
        let mut tx = conn.begin().await?;
        sqlx::query("delete from delegated_role_members where role_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query("delete from delegated_roles where id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn delegated_access_for_user(
        &self,
        user_id: i64,
    ) -> ResultType<Vec<DelegatedRoleAccess>> {
        Ok(sqlx::query_as::<_, DelegatedRoleAccess>(
            "select r.permissions, r.user_group_ids, r.device_group_ids from delegated_roles r join delegated_role_members m on m.role_id = r.id where m.user_id = ?",
        )
        .bind(user_id)
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?)
    }

    pub async fn create_user(
        &self,
        name: &str,
        display_name: &str,
        email: &str,
        password_hash: &str,
        is_admin: bool,
    ) -> ResultType<i64> {
        let result = sqlx::query(
            "insert into users(name, display_name, email, password_hash, is_admin) values(?, ?, ?, ?, ?)",
        )
        .bind(name)
        .bind(display_name)
        .bind(email)
        .bind(password_hash)
        .bind(is_admin)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(result.last_insert_rowid())
    }

    pub async fn update_user(
        &self,
        id: i64,
        display_name: &str,
        email: &str,
        is_admin: bool,
        status: i64,
    ) -> ResultType<()> {
        let mut conn = self.pool.get().await?;
        sqlx::query(
            "update users set display_name = ?, email = ?, is_admin = ?, status = ? where id = ?",
        )
        .bind(display_name)
        .bind(email)
        .bind(is_admin)
        .bind(status)
        .bind(id)
        .execute(conn.deref_mut())
        .await?;
        if status == 0 {
            sqlx::query(
                "delete from pending_peer_claims \
                 where user = cast((select name from users where id = ?) as blob)",
            )
            .bind(id)
            .execute(conn.deref_mut())
            .await?;
        }
        Ok(())
    }

    pub async fn update_user_password(&self, id: i64, password_hash: &str) -> ResultType<()> {
        sqlx::query("update users set password_hash = ? where id = ?")
            .bind(password_hash)
            .bind(id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    pub async fn delete_user(&self, id: i64) -> ResultType<()> {
        let mut conn = self.pool.get().await?;
        let name: Option<String> = sqlx::query_scalar("select name from users where id = ?")
            .bind(id)
            .fetch_optional(conn.deref_mut())
            .await?;
        if let Some(name) = name {
            sqlx::query("update peer set user = null where user = ?")
                .bind(name.as_bytes())
                .execute(conn.deref_mut())
                .await?;
            sqlx::query("delete from pending_peer_claims where user = ?")
                .bind(name.as_bytes())
                .execute(conn.deref_mut())
                .await?;
        }
        sqlx::query(
            "delete from address_book_entries where book_id in \
             (select id from address_books where owner_id = ?)",
        )
        .bind(id)
        .execute(conn.deref_mut())
        .await?;
        sqlx::query(
            "delete from address_book_permissions where book_id in \
             (select id from address_books where owner_id = ?)",
        )
        .bind(id)
        .execute(conn.deref_mut())
        .await?;
        sqlx::query("delete from address_books where owner_id = ?")
            .bind(id)
            .execute(conn.deref_mut())
            .await?;
        sqlx::query("delete from user_group_members where user_id = ?")
            .bind(id)
            .execute(conn.deref_mut())
            .await?;
        sqlx::query("delete from delegated_role_members where user_id = ?")
            .bind(id)
            .execute(conn.deref_mut())
            .await?;
        sqlx::query("delete from api_tokens where owner_id = ?")
            .bind(id)
            .execute(conn.deref_mut())
            .await?;
        sqlx::query("delete from users where id = ?")
            .bind(id)
            .execute(conn.deref_mut())
            .await?;
        Ok(())
    }

    pub async fn count_admins(&self) -> ResultType<i64> {
        Ok(
            sqlx::query_scalar("select count(*) from users where is_admin = 1 and status = 1")
                .fetch_one(self.pool.get().await?.deref_mut())
                .await?,
        )
    }

    pub async fn service_resource_counts(&self) -> ResultType<ServiceResourceCounts> {
        Ok(sqlx::query_as::<_, ServiceResourceCounts>(
            "select \
               (select count(*) from users) as total_users, \
               (select count(*) from users where status = 1) as active_users, \
               (select count(*) from peer) as total_devices, \
               (select count(*) from device_groups) as device_groups, \
               (select count(*) from user_groups) as user_groups",
        )
        .fetch_one(self.pool.get().await?.deref_mut())
        .await?)
    }

    pub async fn list_device_groups(
        &self,
        limit: i64,
        offset: i64,
    ) -> ResultType<(Vec<DeviceGroup>, i64)> {
        let mut conn = self.pool.get().await?;
        let groups = sqlx::query_as::<_, DeviceGroup>(
            "select g.id, g.name, g.description, count(gp.peer_id) as device_count \
             from device_groups g left join device_group_peers gp on gp.group_id = g.id \
             group by g.id order by g.name collate nocase limit ? offset ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(conn.deref_mut())
        .await?;
        let total = sqlx::query_scalar("select count(*) from device_groups")
            .fetch_one(conn.deref_mut())
            .await?;
        Ok((groups, total))
    }

    pub async fn create_device_group(&self, name: &str, description: &str) -> ResultType<i64> {
        let result = sqlx::query("insert into device_groups(name, description) values(?, ?)")
            .bind(name)
            .bind(description)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(result.last_insert_rowid())
    }

    pub async fn update_device_group(
        &self,
        id: i64,
        name: &str,
        description: &str,
    ) -> ResultType<bool> {
        let result = sqlx::query("update device_groups set name = ?, description = ? where id = ?")
            .bind(name)
            .bind(description)
            .bind(id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn delete_device_group(&self, id: i64) -> ResultType<bool> {
        let mut conn = self.pool.get().await?;
        let mut tx = conn.begin().await?;
        let result = sqlx::query("delete from device_groups where id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        if result.rows_affected() == 1 {
            sqlx::query("delete from device_group_peers where group_id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn list_device_group_peers(&self, id: i64) -> ResultType<Option<Vec<String>>> {
        let mut conn = self.pool.get().await?;
        let exists: Option<i64> = sqlx::query_scalar("select id from device_groups where id = ?")
            .bind(id)
            .fetch_optional(conn.deref_mut())
            .await?;
        let Some(_) = exists else {
            return Ok(None);
        };
        let peers = sqlx::query_scalar(
            "select peer_id from device_group_peers where group_id = ? order by peer_id",
        )
        .bind(id)
        .fetch_all(conn.deref_mut())
        .await?;
        Ok(Some(peers))
    }

    pub async fn set_device_group_peers(&self, id: i64, peers: &[String]) -> ResultType<bool> {
        let mut conn = self.pool.get().await?;
        let mut tx = conn.begin().await?;
        let exists: Option<i64> = sqlx::query_scalar("select id from device_groups where id = ?")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
        if exists.is_none() {
            tx.rollback().await?;
            return Ok(false);
        }
        sqlx::query("delete from device_group_peers where group_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        for peer_id in peers {
            sqlx::query("insert into device_group_peers(group_id, peer_id) values(?, ?)")
                .bind(id)
                .bind(peer_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(true)
    }

    pub async fn list_accessible_device_groups(
        &self,
        owner: &str,
        limit: i64,
        offset: i64,
    ) -> ResultType<(Vec<DeviceGroup>, i64)> {
        let mut conn = self.pool.get().await?;
        let owner = owner.as_bytes();
        let groups = sqlx::query_as::<_, DeviceGroup>(
            "select g.id, g.name, g.description, count(gp.peer_id) as device_count \
             from device_groups g \
             join device_group_peers gp on gp.group_id = g.id \
             join peer p on p.id = gp.peer_id \
             where p.user = ? \
             group by g.id order by g.name collate nocase limit ? offset ?",
        )
        .bind(owner)
        .bind(limit)
        .bind(offset)
        .fetch_all(conn.deref_mut())
        .await?;
        let total = sqlx::query_scalar(
            "select count(distinct g.id) from device_groups g \
             join device_group_peers gp on gp.group_id = g.id \
             join peer p on p.id = gp.peer_id where p.user = ?",
        )
        .bind(owner)
        .fetch_one(conn.deref_mut())
        .await?;
        Ok((groups, total))
    }

    pub async fn list_user_groups(
        &self,
        limit: i64,
        offset: i64,
    ) -> ResultType<(Vec<UserGroup>, i64)> {
        let mut conn = self.pool.get().await?;
        let groups = sqlx::query_as::<_, UserGroup>(
            "select g.id, g.name, g.description, count(gm.user_id) as member_count \
             from user_groups g left join user_group_members gm on gm.group_id = g.id \
             group by g.id order by g.name collate nocase limit ? offset ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(conn.deref_mut())
        .await?;
        let total = sqlx::query_scalar("select count(*) from user_groups")
            .fetch_one(conn.deref_mut())
            .await?;
        Ok((groups, total))
    }

    pub async fn create_user_group(&self, name: &str, description: &str) -> ResultType<i64> {
        let result = sqlx::query("insert into user_groups(name, description) values(?, ?)")
            .bind(name)
            .bind(description)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(result.last_insert_rowid())
    }

    pub async fn update_user_group(
        &self,
        id: i64,
        name: &str,
        description: &str,
    ) -> ResultType<bool> {
        let result = sqlx::query("update user_groups set name = ?, description = ? where id = ?")
            .bind(name)
            .bind(description)
            .bind(id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn delete_user_group(&self, id: i64) -> ResultType<bool> {
        let mut conn = self.pool.get().await?;
        let mut tx = conn.begin().await?;
        let result = sqlx::query("delete from user_groups where id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        if result.rows_affected() == 1 {
            sqlx::query("delete from user_group_members where group_id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn list_user_group_members(&self, id: i64) -> ResultType<Option<Vec<i64>>> {
        let mut conn = self.pool.get().await?;
        let exists: Option<i64> = sqlx::query_scalar("select id from user_groups where id = ?")
            .bind(id)
            .fetch_optional(conn.deref_mut())
            .await?;
        if exists.is_none() {
            return Ok(None);
        }
        let members = sqlx::query_scalar(
            "select user_id from user_group_members where group_id = ? order by user_id",
        )
        .bind(id)
        .fetch_all(conn.deref_mut())
        .await?;
        Ok(Some(members))
    }

    pub async fn set_user_group_members(&self, id: i64, members: &[i64]) -> ResultType<bool> {
        let mut conn = self.pool.get().await?;
        let mut tx = conn.begin().await?;
        let exists: Option<i64> = sqlx::query_scalar("select id from user_groups where id = ?")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
        if exists.is_none() {
            tx.rollback().await?;
            return Ok(false);
        }
        sqlx::query("delete from user_group_members where group_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        for member_id in members {
            sqlx::query("insert into user_group_members(group_id, user_id) values(?, ?)")
                .bind(id)
                .bind(member_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(true)
    }

    pub async fn list_accessible_user_groups(
        &self,
        user_id: i64,
        limit: i64,
        offset: i64,
    ) -> ResultType<(Vec<UserGroup>, i64)> {
        let mut conn = self.pool.get().await?;
        let groups = sqlx::query_as::<_, UserGroup>(
            "select g.id, g.name, g.description, count(gm.user_id) as member_count \
             from user_groups g \
             join user_group_members mine on mine.group_id = g.id \
             join user_group_members gm on gm.group_id = g.id \
             where mine.user_id = ? \
             group by g.id order by g.name collate nocase limit ? offset ?",
        )
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(conn.deref_mut())
        .await?;
        let total = sqlx::query_scalar(
            "select count(*) from user_groups g \
             join user_group_members gm on gm.group_id = g.id where gm.user_id = ?",
        )
        .bind(user_id)
        .fetch_one(conn.deref_mut())
        .await?;
        Ok((groups, total))
    }

    pub async fn list_address_books(
        &self,
        limit: i64,
        offset: i64,
    ) -> ResultType<(Vec<AddressBook>, i64)> {
        let mut conn = self.pool.get().await?;
        let books = sqlx::query_as::<_, AddressBook>(
            "select b.id, b.name, b.description, 'manage' as permission, \
             count(e.id) as entry_count, 0 as is_personal \
             from address_books b left join address_book_entries e on e.book_id = b.id \
             where b.owner_id is null \
             group by b.id order by b.name collate nocase limit ? offset ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(conn.deref_mut())
        .await?;
        let total = sqlx::query_scalar("select count(*) from address_books where owner_id is null")
            .fetch_one(conn.deref_mut())
            .await?;
        Ok((books, total))
    }

    pub async fn list_personal_address_books(
        &self,
        owner_id: i64,
        limit: i64,
        offset: i64,
    ) -> ResultType<(Vec<AddressBook>, i64)> {
        let mut conn = self.pool.get().await?;
        let books = sqlx::query_as::<_, AddressBook>(
            "select b.id, b.name, b.description, 'manage' as permission, \
             count(e.id) as entry_count, 1 as is_personal \
             from address_books b left join address_book_entries e on e.book_id = b.id \
             where b.owner_id = ? \
             group by b.id order by b.name collate nocase limit ? offset ?",
        )
        .bind(owner_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(conn.deref_mut())
        .await?;
        let total = sqlx::query_scalar("select count(*) from address_books where owner_id = ?")
            .bind(owner_id)
            .fetch_one(conn.deref_mut())
            .await?;
        Ok((books, total))
    }

    pub async fn list_accessible_address_books(
        &self,
        user_id: i64,
        limit: i64,
        offset: i64,
    ) -> ResultType<(Vec<AddressBook>, i64)> {
        let mut conn = self.pool.get().await?;
        let books = sqlx::query_as::<_, AddressBook>(
            "select b.id, b.name, b.description, \
             case max(case ap.access when 'manage' then 3 when 'write' then 2 when 'read' then 1 else 0 end) \
               when 3 then 'manage' when 2 then 'write' else 'read' end as permission, \
             count(distinct e.id) as entry_count, 0 as is_personal \
             from address_books b \
             join address_book_permissions ap on ap.book_id = b.id \
             left join user_group_members gm on ap.subject_type = 'group' \
               and gm.group_id = ap.subject_id and gm.user_id = ? \
             left join address_book_entries e on e.book_id = b.id \
             where (ap.subject_type = 'everyone' and ap.subject_id = 0) \
               or (ap.subject_type = 'user' and ap.subject_id = ?) \
               or (ap.subject_type = 'group' and gm.user_id = ?) \
             group by b.id order by b.name collate nocase limit ? offset ?",
        )
        .bind(user_id)
        .bind(user_id)
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(conn.deref_mut())
        .await?;
        let total = sqlx::query_scalar(
            "select count(distinct b.id) from address_books b \
             join address_book_permissions ap on ap.book_id = b.id \
             left join user_group_members gm on ap.subject_type = 'group' \
               and gm.group_id = ap.subject_id and gm.user_id = ? \
             where (ap.subject_type = 'everyone' and ap.subject_id = 0) \
               or (ap.subject_type = 'user' and ap.subject_id = ?) \
               or (ap.subject_type = 'group' and gm.user_id = ?)",
        )
        .bind(user_id)
        .bind(user_id)
        .bind(user_id)
        .fetch_one(conn.deref_mut())
        .await?;
        Ok((books, total))
    }

    pub async fn address_book_permission(
        &self,
        book_id: i64,
        user_id: i64,
    ) -> ResultType<Option<String>> {
        let permission = sqlx::query_scalar::<_, String>(
            "select case max(case ap.access when 'manage' then 3 when 'write' then 2 when 'read' then 1 else 0 end) \
             when 3 then 'manage' when 2 then 'write' when 1 then 'read' else '' end \
             from address_book_permissions ap \
             left join user_group_members gm on ap.subject_type = 'group' \
               and gm.group_id = ap.subject_id and gm.user_id = ? \
             where ap.book_id = ? and ( \
               (ap.subject_type = 'everyone' and ap.subject_id = 0) \
               or (ap.subject_type = 'user' and ap.subject_id = ?) \
               or (ap.subject_type = 'group' and gm.user_id = ?))",
        )
        .bind(user_id)
        .bind(book_id)
        .bind(user_id)
        .bind(user_id)
        .fetch_one(self.pool.get().await?.deref_mut())
        .await?;
        Ok((!permission.is_empty()).then_some(permission))
    }

    pub async fn create_address_book(&self, name: &str, description: &str) -> ResultType<i64> {
        let result = sqlx::query(
            "insert into address_books(name, description, owner_id) values(?, ?, null)",
        )
        .bind(name)
        .bind(description)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(result.last_insert_rowid())
    }

    pub async fn create_personal_address_book(
        &self,
        owner_id: i64,
        name: &str,
        description: &str,
    ) -> ResultType<i64> {
        let result =
            sqlx::query("insert into address_books(name, description, owner_id) values(?, ?, ?)")
                .bind(name)
                .bind(description)
                .bind(owner_id)
                .execute(self.pool.get().await?.deref_mut())
                .await?;
        Ok(result.last_insert_rowid())
    }

    pub async fn update_address_book(
        &self,
        id: i64,
        name: &str,
        description: &str,
    ) -> ResultType<bool> {
        let result = sqlx::query("update address_books set name = ?, description = ? where id = ?")
            .bind(name)
            .bind(description)
            .bind(id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn update_personal_address_book(
        &self,
        owner_id: i64,
        id: i64,
        name: &str,
        description: &str,
    ) -> ResultType<bool> {
        let result = sqlx::query(
            "update address_books set name = ?, description = ? \
             where id = ? and owner_id = ?",
        )
        .bind(name)
        .bind(description)
        .bind(id)
        .bind(owner_id)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn delete_personal_address_book(&self, owner_id: i64, id: i64) -> ResultType<bool> {
        let mut conn = self.pool.get().await?;
        let mut tx = conn.begin().await?;
        let result = sqlx::query("delete from address_books where id = ? and owner_id = ?")
            .bind(id)
            .bind(owner_id)
            .execute(&mut *tx)
            .await?;
        if result.rows_affected() == 1 {
            sqlx::query("delete from address_book_entries where book_id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("delete from address_book_permissions where book_id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn address_book_owner(&self, id: i64) -> ResultType<Option<Option<i64>>> {
        Ok(
            sqlx::query_scalar("select owner_id from address_books where id = ?")
                .bind(id)
                .fetch_optional(self.pool.get().await?.deref_mut())
                .await?,
        )
    }

    pub async fn delete_address_book(&self, id: i64) -> ResultType<bool> {
        let mut conn = self.pool.get().await?;
        let mut tx = conn.begin().await?;
        let result = sqlx::query("delete from address_books where id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        if result.rows_affected() == 1 {
            sqlx::query("delete from address_book_entries where book_id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("delete from address_book_permissions where book_id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn list_address_book_entries(
        &self,
        book_id: i64,
    ) -> ResultType<Option<Vec<AddressBookEntry>>> {
        let mut conn = self.pool.get().await?;
        let exists: Option<i64> = sqlx::query_scalar("select id from address_books where id = ?")
            .bind(book_id)
            .fetch_optional(conn.deref_mut())
            .await?;
        if exists.is_none() {
            return Ok(None);
        }
        let entries = sqlx::query_as::<_, AddressBookEntry>(
            "select id, device_id, alias, note, tags from address_book_entries \
             where book_id = ? order by alias collate nocase, device_id",
        )
        .bind(book_id)
        .fetch_all(conn.deref_mut())
        .await?;
        Ok(Some(entries))
    }

    pub async fn create_address_book_entry(
        &self,
        book_id: i64,
        device_id: &str,
        alias: &str,
        note: &str,
        tags: &str,
    ) -> ResultType<Option<i64>> {
        let result = sqlx::query(
            "insert into address_book_entries(book_id, device_id, alias, note, tags) \
             select ?, ?, ?, ?, ? where exists(select 1 from address_books where id = ?)",
        )
        .bind(book_id)
        .bind(device_id)
        .bind(alias)
        .bind(note)
        .bind(tags)
        .bind(book_id)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok((result.rows_affected() == 1).then_some(result.last_insert_rowid()))
    }

    pub async fn update_address_book_entry(
        &self,
        book_id: i64,
        entry_id: i64,
        device_id: &str,
        alias: &str,
        note: &str,
        tags: &str,
    ) -> ResultType<bool> {
        let result = sqlx::query(
            "update address_book_entries set device_id = ?, alias = ?, note = ?, tags = ? \
             where id = ? and book_id = ?",
        )
        .bind(device_id)
        .bind(alias)
        .bind(note)
        .bind(tags)
        .bind(entry_id)
        .bind(book_id)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn delete_address_book_entry(&self, book_id: i64, entry_id: i64) -> ResultType<bool> {
        let result = sqlx::query("delete from address_book_entries where id = ? and book_id = ?")
            .bind(entry_id)
            .bind(book_id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn list_address_book_permissions(
        &self,
        book_id: i64,
    ) -> ResultType<Option<Vec<AddressBookPermission>>> {
        let mut conn = self.pool.get().await?;
        let exists: Option<i64> = sqlx::query_scalar("select id from address_books where id = ?")
            .bind(book_id)
            .fetch_optional(conn.deref_mut())
            .await?;
        if exists.is_none() {
            return Ok(None);
        }
        let permissions = sqlx::query_as::<_, AddressBookPermission>(
            "select subject_type, subject_id, access from address_book_permissions \
             where book_id = ? order by subject_type, subject_id",
        )
        .bind(book_id)
        .fetch_all(conn.deref_mut())
        .await?;
        Ok(Some(permissions))
    }

    pub async fn set_address_book_permissions(
        &self,
        book_id: i64,
        permissions: &[AddressBookPermission],
    ) -> ResultType<bool> {
        let mut conn = self.pool.get().await?;
        let mut tx = conn.begin().await?;
        let exists: Option<i64> = sqlx::query_scalar("select id from address_books where id = ?")
            .bind(book_id)
            .fetch_optional(&mut *tx)
            .await?;
        if exists.is_none() {
            tx.rollback().await?;
            return Ok(false);
        }
        sqlx::query("delete from address_book_permissions where book_id = ?")
            .bind(book_id)
            .execute(&mut *tx)
            .await?;
        for permission in permissions {
            sqlx::query(
                "insert into address_book_permissions(book_id, subject_type, subject_id, access) \
                 values(?, ?, ?, ?)",
            )
            .bind(book_id)
            .bind(&permission.subject_type)
            .bind(permission.subject_id)
            .bind(&permission.access)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(true)
    }

    pub async fn insert_admin_audit_log(
        &self,
        actor_id: i64,
        actor_name: &str,
        action: &str,
        resource_type: &str,
        resource_id: &str,
        summary: &str,
    ) -> ResultType<()> {
        let mut conn = self.pool.get().await?;
        let mut tx = conn.begin().await?;
        sqlx::query(
            "insert into admin_audit_logs \
             (actor_id, actor_name, action, resource_type, resource_id, summary) \
             values (?, ?, ?, ?, ?, ?)",
        )
        .bind(actor_id)
        .bind(actor_name)
        .bind(action)
        .bind(resource_type)
        .bind(resource_id)
        .bind(summary)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "delete from admin_audit_logs \
             where id not in (select id from admin_audit_logs order by id desc limit 100000)",
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn create_api_token(
        &self,
        owner_id: i64,
        name: &str,
        token_prefix: &str,
        token_hash: &str,
        scopes: &str,
        expires_at: &str,
    ) -> ResultType<i64> {
        let result = sqlx::query(
            "insert into api_tokens(owner_id, name, token_prefix, token_hash, scopes, expires_at) \
             values(?, ?, ?, ?, ?, ?)",
        )
        .bind(owner_id)
        .bind(name)
        .bind(token_prefix)
        .bind(token_hash)
        .bind(scopes)
        .bind(expires_at)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(result.last_insert_rowid())
    }

    pub async fn list_api_tokens(&self, owner_id: i64) -> ResultType<Vec<ApiToken>> {
        Ok(sqlx::query_as::<_, ApiToken>(
            "select id, name, token_prefix, scopes, expires_at, created_at, last_used_at, revoked_at \
             from api_tokens where owner_id = ? order by id desc",
        )
        .bind(owner_id)
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?)
    }

    pub async fn revoke_api_token(&self, owner_id: i64, id: i64) -> ResultType<bool> {
        let result = sqlx::query(
            "update api_tokens set revoked_at = current_timestamp \
             where id = ? and owner_id = ? and revoked_at is null",
        )
        .bind(id)
        .bind(owner_id)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn authenticate_api_token(
        &self,
        token_hash: &str,
    ) -> ResultType<Option<ApiTokenAuth>> {
        let mut conn = self.pool.get().await?;
        let mut tx = conn.begin().await?;
        let token = sqlx::query_as::<_, ApiTokenAuth>(
            "select owner_id, scopes from api_tokens \
             where token_hash = ? and revoked_at is null and datetime(expires_at) > datetime('now')",
        )
        .bind(token_hash)
        .fetch_optional(&mut *tx)
        .await?;
        if token.is_some() {
            sqlx::query(
                "update api_tokens set last_used_at = current_timestamp where token_hash = ?",
            )
            .bind(token_hash)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(token)
    }

    pub async fn list_admin_audit_logs(
        &self,
        actor: Option<&str>,
        action: Option<&str>,
        resource_type: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> ResultType<(Vec<AuditLog>, i64)> {
        let mut conn = self.pool.get().await?;
        let logs = sqlx::query_as::<_, AuditLog>(
            "select id, actor_id, actor_name, action, resource_type, resource_id, summary, created_at \
             from admin_audit_logs \
             where (? is null or actor_name = ?) \
               and (? is null or action = ?) \
               and (? is null or resource_type = ?) \
             order by id desc limit ? offset ?",
        )
        .bind(actor)
        .bind(actor)
        .bind(action)
        .bind(action)
        .bind(resource_type)
        .bind(resource_type)
        .bind(limit)
        .bind(offset)
        .fetch_all(conn.deref_mut())
        .await?;
        let total = sqlx::query_scalar(
            "select count(*) from admin_audit_logs \
             where (? is null or actor_name = ?) \
               and (? is null or action = ?) \
               and (? is null or resource_type = ?)",
        )
        .bind(actor)
        .bind(actor)
        .bind(action)
        .bind(action)
        .bind(resource_type)
        .bind(resource_type)
        .fetch_one(conn.deref_mut())
        .await?;
        Ok((logs, total))
    }

    pub async fn get_or_create_api_secret(&self) -> ResultType<String> {
        let mut conn = self.pool.get().await?;
        sqlx::query("insert or ignore into app_config(key, value) values('api_secret', ?)")
            .bind(uuid::Uuid::new_v4().to_string())
            .execute(conn.deref_mut())
            .await?;
        Ok(
            sqlx::query_scalar("select value from app_config where key = 'api_secret'")
                .fetch_one(conn.deref_mut())
                .await?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{Connection, Database, SqliteConnectOptions, SqliteConnection};
    use hbb_common::tokio;

    #[test]
    fn migrates_legacy_address_books_and_allows_scoped_names() {
        address_book_owner_migration();
    }

    #[tokio::main(flavor = "current_thread")]
    async fn address_book_owner_migration() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let options = SqliteConnectOptions::new()
            .filename(file.path())
            .create_if_missing(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        sqlx::query(
            "create table address_books (
                id integer primary key autoincrement,
                name varchar(100) not null collate nocase unique,
                description varchar(300) not null default '',
                created_at datetime not null default(current_timestamp)
            );
            create table address_book_entries (
                id integer primary key autoincrement,
                book_id integer not null,
                device_id varchar(100) not null,
                alias varchar(100) not null default '',
                note varchar(300) not null default '',
                tags text not null default '[]',
                unique (book_id, device_id)
            );
            insert into address_books(name, description) values('Existing', 'legacy');
            insert into address_book_entries(book_id, device_id, alias) \
             values(1, 'legacy-device', 'Legacy device');",
        )
        .execute(&mut conn)
        .await
        .unwrap();
        conn.close().await.unwrap();

        let db = Database::new(file.path().to_str().unwrap()).await.unwrap();
        let (shared, shared_total) = db.list_address_books(100, 0).await.unwrap();
        assert_eq!(shared_total, 1);
        assert_eq!(shared[0].name, "Existing");
        assert!(!shared[0].is_personal);
        assert_eq!(
            db.list_address_book_entries(1).await.unwrap().unwrap()[0].device_id,
            "legacy-device"
        );

        db.create_personal_address_book(7, "Existing", "private")
            .await
            .unwrap();
        db.create_personal_address_book(8, "Existing", "another user")
            .await
            .unwrap();
        assert!(db
            .create_personal_address_book(7, "existing", "duplicate")
            .await
            .is_err());
        let (personal, personal_total) = db.list_personal_address_books(7, 100, 0).await.unwrap();
        assert_eq!(personal_total, 1);
        assert!(personal[0].is_personal);
    }

    #[test]
    fn test_insert() {
        insert();
    }

    #[tokio::main(flavor = "multi_thread")]
    async fn insert() {
        let db = super::Database::new("test.sqlite3").await.unwrap();
        let mut jobs = vec![];
        for i in 0..10000 {
            let cloned = db.clone();
            let id = i.to_string();
            let a = tokio::spawn(async move {
                let empty_vec = Vec::new();
                cloned
                    .insert_peer(&id, &empty_vec, &empty_vec, "")
                    .await
                    .unwrap();
            });
            jobs.push(a);
        }
        for i in 0..10000 {
            let cloned = db.clone();
            let id = i.to_string();
            let a = tokio::spawn(async move {
                cloned.get_peer(&id).await.unwrap();
            });
            jobs.push(a);
        }
        hbb_common::futures::future::join_all(jobs).await;
    }
}
