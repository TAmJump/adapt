-- migration_v9.sql: Phase 4-4 通知機能
-- 実行方法: Cloudflare D1 Console（adapt-db）に貼り付けて実行

-- partner_notifications テーブル
-- タムジ→総代理店、総代理店→代理店（将来）の両方向に対応
CREATE TABLE IF NOT EXISTS partner_notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  partner_id TEXT NOT NULL,
  sender_type TEXT NOT NULL,
  sender_staff_id TEXT,
  sender_partner_id TEXT,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  action_url TEXT,
  priority TEXT NOT NULL DEFAULT 'normal',
  read_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (partner_id) REFERENCES partners(partner_id),
  FOREIGN KEY (sender_staff_id) REFERENCES master_staff(staff_id),
  FOREIGN KEY (sender_partner_id) REFERENCES partners(partner_id)
);

CREATE INDEX IF NOT EXISTS idx_pn_partner ON partner_notifications(partner_id);
CREATE INDEX IF NOT EXISTS idx_pn_unread ON partner_notifications(partner_id, read_at);
CREATE INDEX IF NOT EXISTS idx_pn_created ON partner_notifications(created_at);

-- カラム説明:
-- sender_type: 'admin' (タムジ社) / 'super' (総代理店) / 'system' (自動通知)
-- priority: 'low' / 'normal' / 'high'
-- action_url: 通知クリック時の遷移先（optional）
-- read_at: 既読時刻（NULL = 未読）
