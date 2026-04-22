-- backup-admin-setup.sql: バックアップ tamj_admin アカウント作成
-- 実行方法: Cloudflare D1 Console（adapt-db）に貼り付けて実行
--
-- 目的: tamj-admin アカウント（プライマリ）が使えなくなった場合に備え、
--       バックアップ管理者を事前に用意しておく。
--       通常運用では使用せず、ログイン情報を別途金庫/Bitwardenに保管。
--
-- 実行前に下記の値を変更してください:
--  - login_id: 推奨 'tamj-admin-backup'
--  - password_hash: 下記パスワードを SHA-256 hex にしたもの
--    パスワード例: "backup-" + ランダム32文字（Bitwarden で生成推奨）
--  - email: バックアップ管理者の実メールアドレス
--
-- SHA-256 hex 生成方法（ブラウザ Dev Tools で実行）:
--   crypto.subtle.digest('SHA-256', new TextEncoder().encode("YOUR_PASSWORD"))
--     .then(h => console.log([...new Uint8Array(h)].map(b=>b.toString(16).padStart(2,'0')).join('')))
--
-- ★ このSQLコメントの値はサンプルです。必ず変更してから実行してください ★

-- 1. master_company_id を確認（通常 TAmJ.Corp の company_id）
-- 事前に: SELECT company_id, name FROM master_companies WHERE name LIKE '%TAmJ%' OR name LIKE '%タムジ%';
-- 取得した company_id を :YOUR_COMPANY_ID の箇所に書き換えてください

-- 2. staff_id の次番号を確認
-- 事前に: SELECT staff_id FROM master_staff WHERE staff_id LIKE 'ADP-STF-%' ORDER BY staff_id DESC LIMIT 1;
-- たとえば 'ADP-STF-000003' なら、次は 'ADP-STF-000004'

-- 3. バックアップ管理者 INSERT（staff_id / company_id / login_id / password_hash / email を実値に変更）
INSERT INTO master_staff (
  staff_id,
  master_company_id,
  login_id,
  name,
  email,
  password_hash,
  role,
  status,
  created_at,
  updated_at
) VALUES (
  'ADP-STF-000004',
  'YOUR_COMPANY_ID',
  'tamj-admin-backup',
  'タムジ社バックアップ管理者',
  'backup-admin@tamjump.com',
  '__REPLACE_WITH_SHA256_HEX_OF_PASSWORD__',
  'tamj_admin',
  'active',
  datetime('now'),
  datetime('now')
);

-- 4. 確認SELECT
SELECT staff_id, login_id, name, email, role, status, created_at
  FROM master_staff
 WHERE role = 'tamj_admin'
 ORDER BY created_at;

-- 注意:
-- - role='tamj_admin' は Adavoo 管理画面（admin-dashboard.html）へのフルアクセス権を意味します
-- - 作成後、Bitwardenなどのパスワード管理ツールに以下を保存:
--   · ログインID: tamj-admin-backup
--   · パスワード: (上記SHA-256の元パスワード)
--   · 目的: プライマリ管理者ロックアウト時の復旧用
-- - 通常は status='active' のままで問題なし（ログインして使わなければ影響ゼロ）
-- - Phase 4-1 のパスワードリセット機能も使用可能（email 宛にリセットリンク送信）
