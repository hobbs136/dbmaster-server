//! embedded 迁移 checksum 漂移 → 备份重建（2026-08-25）。
//!
//! 背景实锤：`sqlx::migrate!` 在编译期内嵌迁移文件字节计算 checksum，
//! 历史构建的行尾差异（CRLF/LF）导致同一迁移 checksum 漂移——存量
//! embedded 库对新二进制报 VersionMismatch，server 启动即崩，客户端
//! 网关功能（T29 后含 MySQL 族）全灭。
//!
//! `db::init_pool_with_embedded_rebuild` 只在 embedded 模式使用：迁移失败
//! 时备份旧库（`.bak-*`）后重建一次；健康库零开销直通。

use dbmaster_core::db;

#[tokio::test]
async fn checksum_mismatch_triggers_backup_and_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("dbmaster-embedded.db");
    let url = format!("sqlite:{}?mode=rwc", db_path.display());

    // 首轮：正常建库 + 全量迁移，记下已应用迁移数。
    let pool = db::init_pool(&url).await.unwrap();
    db::run_migrations(&pool).await.unwrap();
    let (applied_before,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .unwrap();
    // 篡改 version 6 的 checksum，模拟「行尾漂移的旧库」。
    sqlx::query("UPDATE _sqlx_migrations SET checksum = randomblob(48) WHERE version = 6")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    // 二轮：直接走 rebuild 入口（不走 run_migrations——那会硬失败）。
    let (pool, rebuilt) = db::init_pool_with_embedded_rebuild(&url, &db_path)
        .await
        .expect("checksum mismatch 应触发备份重建而非失败");
    assert!(rebuilt, "checksum mismatch 应标记 rebuilt=true");
    let (applied_after,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        applied_after, applied_before,
        "重建后迁移应完整重放（数量一致）"
    );
    pool.close().await;

    // 旧库文件应以 .bak-<epoch> 备份保留（可人工找回）。
    let backups = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".bak-"))
        .count();
    assert!(backups >= 1, "旧库应有 .bak-* 备份文件");
}

#[tokio::test]
async fn healthy_db_boots_without_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("dbmaster-embedded.db");
    let url = format!("sqlite:{}?mode=rwc", db_path.display());

    let pool = db::init_pool(&url).await.unwrap();
    db::run_migrations(&pool).await.unwrap();
    pool.close().await;

    // 健康库：直通，无备份产生。
    let (pool, rebuilt) = db::init_pool_with_embedded_rebuild(&url, &db_path)
        .await
        .unwrap();
    assert!(!rebuilt, "健康库不应标记 rebuilt");
    pool.close().await;
    let backups = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".bak-"))
        .count();
    assert_eq!(backups, 0, "健康库不应触发备份重建");
}
