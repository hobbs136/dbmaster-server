-- ADR-0003 第一阶段：database_connections 加 file_path 列。
-- SQLite 源库的文件路径存在这里（host/port/username 对 SQLite 无意义，
-- 但保留以兼容现有 schema；SQLite 行的 host='sqlite'、port=0、username='sqlite'）。
-- 其他 db_type（mysql/postgres）的 file_path 为 NULL。

ALTER TABLE database_connections ADD COLUMN file_path TEXT;
