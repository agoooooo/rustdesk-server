use async_trait::async_trait;
use hbb_common::{log, ResultType};
use serde::Serialize;
use sqlx::{
    sqlite::SqliteConnectOptions, ConnectOptions, Connection, Error as SqlxError, SqliteConnection,
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
                on user_group_members (user_id);",
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
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

    pub async fn claim_peer(&self, id: &str, uuid: &[u8], owner: &str) -> ResultType<bool> {
        let owner = owner.as_bytes();
        let result = sqlx::query(
            "update peer set user = ? \
             where id = ? and uuid = ? and (user is null or user = ?)",
        )
        .bind(owner)
        .bind(id)
        .bind(uuid)
        .bind(owner)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(result.rows_affected() == 1)
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
        sqlx::query!(
            "insert into peer(guid, id, uuid, pk, info) values(?, ?, ?, ?, ?)",
            guid,
            id,
            uuid,
            pk,
            info
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(guid)
    }

    pub async fn update_pk(
        &self,
        guid: &Vec<u8>,
        id: &str,
        pk: &[u8],
        info: &str,
    ) -> ResultType<()> {
        sqlx::query!(
            "update peer set id=?, pk=?, info=? where guid=?",
            id,
            pk,
            info,
            guid
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
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
        sqlx::query(
            "update users set display_name = ?, email = ?, is_admin = ?, status = ? where id = ?",
        )
        .bind(display_name)
        .bind(email)
        .bind(is_admin)
        .bind(status)
        .bind(id)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
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
        }
        sqlx::query("delete from user_group_members where user_id = ?")
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
    use hbb_common::tokio;
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
