# Square 決済連携 セットアップ手順（Phase 3f）

Adavoo の `/api/subscriptions/*` および `purchase.html` で使用する Square 連携の設定手順です。

## 必要な環境変数

Cloudflare Dashboard → Workers → `adapt-api` → **Settings → Variables** で設定：

| 変数名 | Type | 用途 |
|---|---|---|
| `SQUARE_ACCESS_TOKEN` | **Secret** | Square REST API 呼び出し用Bearerトークン |
| `SQUARE_LOCATION_ID` | Plaintext | 決済を受け付ける拠点ID |
| `SQUARE_APPLICATION_ID` | Plaintext | フロント Web Payments SDK 初期化用 |
| `SQUARE_WEBHOOK_SIGNATURE_KEY` | **Secret** | Webhook署名検証用 |
| `SQUARE_ENV` | Plaintext | `sandbox` または `production` |
| `SQUARE_WEBHOOK_NOTIFICATION_URL` | Plaintext（任意） | Webhook登録時URLと同じ（未設定時は `{Origin}/api/subscriptions/webhook` を使用） |

## Square Developer Dashboard での作業

### 1. アプリケーション作成

1. https://developer.squareup.com/apps にログイン
2. **＋** ボタンから新規アプリ作成（例: `Adavoo Platform`）
3. アプリを開く

### 2. Sandbox環境のトークン取得

Sandbox でのテスト実装段階は以下を `SQUARE_ACCESS_TOKEN` / `SQUARE_APPLICATION_ID` に設定：

- **Credentials** タブ → **Sandbox** セクション
  - **Sandbox Access Token**（EAAA... で始まる）→ `SQUARE_ACCESS_TOKEN`
  - **Sandbox Application ID**（sandbox-sq0idb-... で始まる）→ `SQUARE_APPLICATION_ID`
- **Locations** タブ → Sandbox location の **Location ID** → `SQUARE_LOCATION_ID`

`SQUARE_ENV=sandbox` を指定。

### 3. Webhook設定

1. アプリ画面 → **Webhooks** タブ → **Add Subscription**
2. Notification URL に `https://adapt-api.animalb001.workers.dev/api/subscriptions/webhook` を登録
3. **Events** で以下にチェック：
   - `subscription.created`
   - `subscription.updated`
   - `invoice.payment_made`
   - `invoice.scheduled_charge_failed`
4. 保存後、**Signature Key** をコピーして `SQUARE_WEBHOOK_SIGNATURE_KEY` に設定

### 4. Catalog と Subscription Plan の登録

Square は「Catalog Item（商品）」＋「Subscription Plan」を事前登録しておく必要があります。

現状の Adavoo は `AVAILABLE_PLANS` を `worker.js` にハードコードしています（`onetouch_pro`, `medadapt_pro`）。対応する Subscription Plan を Square に作成：

- **Dashboard** → **Items & orders** → **Service library** で商品を作成
- **Subscriptions** で「プラン」を作成し、商品と紐付け
- プランIDを取得（`SBSCPL_xxx` 形式）

※ 現時点のAdavoo実装ではSquareのSubscription Plan IDの直接管理は未実装です。Phase 3f本格実装時に `AVAILABLE_PLANS` にSquareのプランIDを追加して連携する形になります。

### 5. 適格請求書等保存方式（インボイス制度）対応

- Square Dashboard → **Account & Settings → Business information**
- **適格請求書発行事業者登録番号** (T+13桁) を入力
- これにより Square が自動送信するレシートに登録番号が記載される

## 動作確認

### Sandbox用テストカード番号

- `4111 1111 1111 1111` （成功）
- 有効期限: 未来日、CVV: 任意3桁、ZIP: `94103`

### 確認手順

1. `purchase.html` をブラウザで開く
2. プラン選択 → ID数入力 → 決済情報入力へ
3. テストカード番号を入力 → 「購入を確定する」
4. Adavoo側 `subscriptions` テーブルに INSERT されることを確認
5. Square Dashboard → Transactions に記録されることを確認
6. Webhook が飛んで `subscriptions.status='active'` に更新されることを確認

## 実装ステータス

### ✅ Phase 3fで完了した部分

- 設定値公開API（`GET /api/subscriptions/config`）
- プラン一覧API（`GET /api/subscriptions/plans`）
- Webhook受信＋署名検証（`POST /api/subscriptions/webhook`）
  - `subscription.created/updated` → `subscriptions.status` 反映
  - `invoice.payment_made` → `subscriptions.status='active'` 更新
- `purchase.html`：プラン選択UI＋Square Web Payments SDK統合＋カードトークン化

### ⚠️ Phase 3f 本格実装で残っている作業

現状の `POST /api/subscriptions/create` は「**Adavoo内モック実装**」です。カードトークンを受け取るが、Square Subscriptions API は呼び出していません。本格運用時は以下を追加実装：

1. `worker.js` の `/api/subscriptions/create` で:
   - Square **Create Customer** API (`POST /v2/customers`)
   - Square **Create Card** API (`POST /v2/cards`)（カードオンファイル化）
   - Square **Create Subscription** API (`POST /v2/subscriptions`)
   - 返ってきた subscription.id を `subscriptions.square_subscription_id` に保存
2. `AVAILABLE_PLANS` に各プランの Square `plan_variation_id` を追加
3. エラーハンドリング（カード拒否・重複登録など）

## 本番移行

- Sandbox動作確認後、Production Credentials を Dashboard で取得
- 上記6つの環境変数を全てProduction用に差し替え
- `SQUARE_ENV=production` に変更
- Webhookエンドポイントも Production 用に別途登録

## トラブルシューティング

- **Webhook 401 invalid_signature**
  - `SQUARE_WEBHOOK_SIGNATURE_KEY` が正しくコピーされているか確認
  - Notification URLが完全一致しているか（末尾 / の有無、httpsかhttpか）
- **フロントでSquare SDK初期化失敗**
  - Consoleで `window.Square` が undefined なら CDN読み込み失敗
  - `SQUARE_APPLICATION_ID` とSDK側のenvがマッチしていない可能性（sandbox Appli IDを本番SDKで読もうとするなど）
- **カード拒否**
  - Sandbox以外では本物のカードが必要。テスト用カードは Sandbox でのみ有効
