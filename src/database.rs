use async_trait::async_trait;
use hbb_common::{log, ResultType};
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

#[derive(Default)]
pub struct Peer {
    pub guid: Vec<u8>,
    pub id: String,
    pub uuid: Vec<u8>,
    pub pk: Vec<u8>,
    pub user: Option<Vec<u8>>,
    pub info: String,
    pub status: Option<i64>,
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
            );",
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    pub async fn get_peer(&self, id: &str) -> ResultType<Option<Peer>> {
        Ok(sqlx::query_as!(
            Peer,
            "select guid, id, uuid, pk, user, status, info from peer where id = ?",
            id
        )
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?)
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

    pub async fn list_users(&self, status: Option<i64>, limit: i64, offset: i64) -> ResultType<(Vec<User>, i64)> {
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

    pub async fn update_user(&self, id: i64, display_name: &str, email: &str, is_admin: bool, status: i64) -> ResultType<()> {
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
        sqlx::query("delete from users where id = ?")
            .bind(id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    pub async fn count_admins(&self) -> ResultType<i64> {
        Ok(sqlx::query_scalar("select count(*) from users where is_admin = 1 and status = 1")
            .fetch_one(self.pool.get().await?.deref_mut())
            .await?)
    }

    pub async fn get_or_create_api_secret(&self) -> ResultType<String> {
        let mut conn = self.pool.get().await?;
        sqlx::query("insert or ignore into app_config(key, value) values('api_secret', ?)")
            .bind(uuid::Uuid::new_v4().to_string())
            .execute(conn.deref_mut())
            .await?;
        Ok(sqlx::query_scalar("select value from app_config where key = 'api_secret'")
            .fetch_one(conn.deref_mut())
            .await?)
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
