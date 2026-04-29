# Cron Triggers セットアップ手順（Phase 3e）

やるゼ！ Worker (`adapt-api`) の定期バッチ処理を Cloudflare Cron Triggers で設定する手順です。

## 設定する4つのCron

| Cron式（UTC） | JST時刻 | タスク | 処理内容 |
|---|---|---|---|
| `0 0 * * *` | 毎日 09:00 | `contract_notify_2month` | 契約終了60日以内のpartnersへ通知メール送信（SES） |
| `5 15 * * *` | 翌日 00:05 | `contract_auto_expire` | contract_end_at 経過の partners を `expired` 化＋セッション削除 |
| `5 15 1 * *` | 毎月1日 00:05 | `ledger_monthly_close` | **前月分**のsubscriptionsを集計してrevenue_ledgerにINSERT |
| `0 18 * * *` | 翌日 03:00 | `cleanup_expired_tokens` | sso_tickets / email_verifications / sessions / partner_sessions の期限切れ削除 |

> **月次集計について**：設計書§12.7では「月末23:59 JST」となっていますが、Cloudflare Cron は `L`（月末指定）非対応のため、**翌月1日00:05 JST に前月分を集計** する形に変更しています。実質的な処理タイミングは同等です。

## 設定手順

### ① Cloudflare Dashboard で設定する場合（推奨）

1. Cloudflare Dashboard → **Workers & Pages** → `adapt-api`
2. **Settings** タブ → **Triggers** セクション
3. **Cron Triggers** で **Add Cron Trigger** をクリック
4. 上の表の cron式を1つずつ登録（**UTC基準**で入力すること）
5. 4つ全て登録したら Save

### ② wrangler.toml 経由で設定する場合

プロジェクトに `wrangler.toml` を配置している場合は、以下を追加してデプロイ：

```toml
[triggers]
crons = [
  "0 0 * * *",       # 09:00 JST - contract_notify_2month
  "5 15 * * *",      # 翌日 00:05 JST - contract_auto_expire
  "5 15 1 * *",      # 毎月1日 00:05 JST - ledger_monthly_close（前月分集計）
  "0 18 * * *"       # 翌日 03:00 JST - cleanup_expired_tokens
]
```

## 動作確認

### 手動実行テスト

Cloudflare Dashboard の **Cron Triggers** 一覧で **Trigger** ボタン（手動実行）をクリックすると、対応する cron を即座に1回走らせられます。

### 実行ログの確認

全てのCron実行結果は `audit_logs` テーブルの `type = 'cron_run'` として記録されます：

```sql
SELECT timestamp, details FROM audit_logs
 WHERE type = 'cron_run'
 ORDER BY timestamp DESC LIMIT 20;
```

`details` は JSON 形式で以下の情報を含みます：
```json
{
  "cron": "0 0 * * *",
  "task": "contract_notify_2month",
  "started": "2026-04-21T00:00:00.000Z",
  "result": { "sent": 2, "failed": 0, "candidates": 2 },
  "error": null
}
```

## 月次台帳の手動再生成（保険用）

Cron実行が失敗した場合や、既存データを再集計したい場合、`tamj_admin` ロールで以下のAPIを呼び出せます：

```
POST /api/admin/ledger/2026-04/regenerate
Authorization: Bearer <tamj_admin_token>
```

同月の `status='pending'` エントリを全削除してから再生成します（`paid` 済みエントリは保護されます）。

## 通知メールの文面カスタマイズ

`assets/worker.js` の `runContractNotify2Month` 関数内のテキストを直接編集してください。将来的には SES テンプレート化することも検討されています（Phase 4）。

## トラブルシューティング

- **メールが届かない** → SES の sending reputation 確認、FROM_EMAIL が verified か確認
- **Cron が動かない** → Cloudflare Dashboard → Workers → adapt-api → **Logs** で `scheduled event` を確認
- **重複集計が起きた** → `generateMonthlyLedger` は冪等で、同月のpendingを削除してから再INSERTするため、再実行で上書きされます
