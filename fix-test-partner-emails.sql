-- fix-test-partner-emails.sql: テスト代理店アカウントのメアド SES バウンス対策
-- 実行: Cloudflare D1 Console（adapt-db）に貼り付けて実行
-- 関連: Adavoo 設計書 v2.10 §21.3b.1
--
-- 背景:
--   sup-test@example.com / agt-test@example.com は RFC2606 予約ドメインのため
--   SES 送信時に HARD BOUNCE が発生し、AWS 側のバウンス率指標を悪化させる。
--   本番送信枠（10,000通/日）取得後はバウンス率 5% 超でサンドボックス逆戻り。
--
-- 対策:
--   info@tamjump.com は SES 検証済みアドレス。
--   「info+sup-test@tamjump.com」のようなサブアドレス形式なら
--   RFC5233 準拠で SES 送信が成功し、info@ に配送される（バウンスなし）。
--
-- 影響範囲:
--   - partners.email（Phase 4-3d 契約継続承認SES通知の宛先）
--   - partners.email（Phase 4-4 通知機能の action_url 通知先）
--   - パスワードリセットリンク送信先

-- 0. 事前確認: 現状のメアド値
SELECT partner_id, login_id, type, email, company_name
  FROM partners
 WHERE login_id IN ('sup-test', 'agt-test')
 ORDER BY type DESC, login_id;

-- 1. sup-test（Master Reseller）のメアド変更
UPDATE partners
   SET email      = 'info+sup-test@tamjump.com',
       updated_at = datetime('now')
 WHERE login_id  = 'sup-test'
   AND email     = 'sup-test@example.com';

-- 2. agt-test（Reseller）のメアド変更
UPDATE partners
   SET email      = 'info+agt-test@tamjump.com',
       updated_at = datetime('now')
 WHERE login_id  = 'agt-test'
   AND email     = 'agt-test@example.com';

-- 3. 確認: 変更後の値
SELECT partner_id, login_id, type, email, updated_at
  FROM partners
 WHERE login_id IN ('sup-test', 'agt-test')
 ORDER BY type DESC, login_id;

-- 期待結果:
--   sup-test → info+sup-test@tamjump.com
--   agt-test → info+agt-test@tamjump.com
--
-- 動作確認（任意）:
--   1. admin-dashboard 「通知送信」タブから broadcast_scope='all' で送信
--   2. info@tamjump.com の受信トレイに 2通届くことを確認（TO ヘッダで区別可）
--   3. partners.email が null の旧代理店にも影響しないことを確認
--
-- ロールバック（必要な場合のみ）:
--   UPDATE partners SET email = 'sup-test@example.com' WHERE login_id = 'sup-test';
--   UPDATE partners SET email = 'agt-test@example.com' WHERE login_id = 'agt-test';
