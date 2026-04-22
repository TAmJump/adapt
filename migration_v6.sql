-- migration_v6.sql: Phase 4-3a 按分率履歴管理
-- 実行方法: Cloudflare D1 Console に貼り付けて実行（コメント行は事前削除推奨）

-- 1. 履歴テーブル作成
CREATE TABLE IF NOT EXISTS partner_revenue_share_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  partner_id TEXT NOT NULL,
  scope TEXT NOT NULL DEFAULT 'tamj_to_super',
  parent_partner_id TEXT,
  pct REAL NOT NULL,
  effective_from TEXT NOT NULL,
  effective_to TEXT,
  set_by_staff_id TEXT,
  set_by_partner_id TEXT,
  note TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (partner_id) REFERENCES partners(partner_id),
  FOREIGN KEY (parent_partner_id) REFERENCES partners(partner_id),
  FOREIGN KEY (set_by_staff_id) REFERENCES master_staff(staff_id),
  FOREIGN KEY (set_by_partner_id) REFERENCES partners(partner_id)
);

CREATE INDEX IF NOT EXISTS idx_rsh_partner ON partner_revenue_share_history(partner_id);
CREATE INDEX IF NOT EXISTS idx_rsh_scope ON partner_revenue_share_history(scope);
CREATE INDEX IF NOT EXISTS idx_rsh_effective ON partner_revenue_share_history(effective_from, effective_to);
CREATE INDEX IF NOT EXISTS idx_rsh_parent ON partner_revenue_share_history(parent_partner_id);

-- 2. 既存の partners.revenue_share_pct を履歴化（初期レコード INSERT）
-- 契約開始日を発効日として遡及登録
INSERT INTO partner_revenue_share_history
  (partner_id, scope, parent_partner_id, pct, effective_from, effective_to, set_by_staff_id, note)
SELECT
  partner_id,
  'tamj_to_super' AS scope,
  NULL AS parent_partner_id,
  revenue_share_pct AS pct,
  COALESCE(DATE(contract_start_at), DATE('now')) AS effective_from,
  NULL AS effective_to,
  (SELECT staff_id FROM master_staff WHERE login_id='tamj-admin' LIMIT 1) AS set_by_staff_id,
  'migration_v6 初期移行（既存の partners.revenue_share_pct を履歴化）' AS note
FROM partners
WHERE type='super' AND revenue_share_pct IS NOT NULL;

-- 3. revenue_ledger に share_history_id カラム追加（按分根拠の証跡）
ALTER TABLE revenue_ledger ADD COLUMN share_history_id INTEGER REFERENCES partner_revenue_share_history(id);
CREATE INDEX IF NOT EXISTS idx_ledger_share_history ON revenue_ledger(share_history_id);

-- 4. 確認用SELECT（コメントアウト・実行時は手動で実行）
-- SELECT partner_id, scope, pct, effective_from, effective_to, note FROM partner_revenue_share_history ORDER BY partner_id, effective_from DESC;
-- SELECT COUNT(*) FROM partner_revenue_share_history;
-- SELECT COUNT(*) FROM revenue_ledger WHERE share_history_id IS NOT NULL;
