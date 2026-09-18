//! SQLite connection pool initialization and migration runner.

use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use std::str::FromStr;

/// Initialize a SQLite connection pool with WAL mode enabled.
///
/// # Arguments
///
/// * `database_url` — SQLite connection string (e.g. `"sqlite:dbmaster.db?mode=rwc"`).
///
/// # Errors
///
/// Returns an error if the database cannot be opened or WAL mode cannot be set.
pub async fn init_pool(database_url: &str) -> anyhow::Result<SqlitePool> {
    let opts = SqliteConnectOptions::from_str(database_url)?
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .foreign_keys(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(16)
        .connect_with(opts)
        .await?;

    tracing::info!("SQLite pool initialized (WAL mode, FK enforced)");

    Ok(pool)
}

/// Run pending SQLx migrations from the `migrations/` directory.
///
/// Migrations are embedded at compile time via `sqlx::migrate!()`.
/// Already-applied migrations are skipped (idempotent).
///
/// # Errors
///
/// Returns an error if a migration fails to apply.
pub async fn run_migrations(pool: &SqlitePool) -> anyhow::Result<()> {
    sqlx::migrate!("../../migrations").run(pool).await?;
    tracing::info!("Database migrations applied");
    Ok(())
}

/// Embedded 模式专用：迁移失败 → 备份旧库并重建（2026-08-25）。
///
/// 背景：`sqlx::migrate!` 在**编译期**内嵌迁移文件字节计算 checksum，
/// 历史构建曾受行尾（CRLF/LF）影响导致同一迁移 checksum 漂移——存量
/// embedded 库对新二进制报 `VersionMismatch` 启动即崩（客户端网关功能
/// 全灭）。embedded 库是本地可再生数据（vault 连接注册由客户端下次连接
/// 自动重建），因此允许一次性备份 + 重建；**远程部署模式不使用本入口**，
/// 仍走 [`init_pool`] + [`run_migrations`] 的硬失败路径（真实数据）。
///
/// 重建只尝试一次：重建后再失败原样返回错误（防死循环，如迁移文件本身
/// 有语法错误时）。
///
/// 返回 `(pool, rebuilt)`：rebuilt=true 表示发生了备份重建（调用方可据此
/// 用自身 target 记日志——默认 EnvFilter 只开 dbmaster_server=info，
/// core 内的 WARN 在 embedded 场景不可见）。
///
/// # Errors
///
/// Returns an error if migration still fails after a rebuild, or if the
/// backup/rebuild IO fails.
pub async fn init_pool_with_embedded_rebuild(
    database_url: &str,
    db_path: &std::path::Path,
) -> anyhow::Result<(SqlitePool, bool)> {
    let pool = init_pool(database_url).await?;
    match run_migrations(&pool).await {
        Ok(()) => Ok((pool, false)),
        Err(first_err) => {
            tracing::warn!(
                "embedded migrations failed ({first_err}); backing up and rebuilding local db"
            );
            pool.close().await;
            backup_db_files(db_path).await?;
            let pool = init_pool(database_url).await?;
            run_migrations(&pool).await?;
            tracing::warn!("embedded db rebuilt from scratch after migration failure");
            Ok((pool, true))
        }
    }
}

/// 把 db 文件（含 `-wal`/`-shm` 伴生文件）改名备份为 `.bak-<epoch>`。
/// 不存在的伴生文件跳过（非 WAL 模式或首次启动时可能无 wal/shm）。
///
/// Windows 上 `pool.close()` 返回后 SQLite 文件句柄释放有毫秒~百毫秒级
/// 延迟（rename 撞 os error 32「另一个程序正在使用此文件」，实测复现），
/// 因此对可重试错误做 100ms × 30 的退避重试。
async fn backup_db_files(db_path: &std::path::Path) -> anyhow::Result<()> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    for path in [
        db_path.to_path_buf(),
        std::path::PathBuf::from(format!("{}-wal", db_path.display())),
        std::path::PathBuf::from(format!("{}-shm", db_path.display())),
    ] {
        let bak = std::path::PathBuf::from(format!("{}.bak-{stamp}", path.display()));
        let mut attempts = 0;
        loop {
            match std::fs::rename(&path, &bak) {
                Ok(()) => {
                    tracing::warn!(path = %path.display(), "embedded db file backed up");
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                Err(e) => {
                    attempts += 1;
                    if attempts >= 30 {
                        return Err(e.into());
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }
    Ok(())
}
