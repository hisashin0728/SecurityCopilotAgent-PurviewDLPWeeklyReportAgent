# Purview DLP Weekly Report — Security Copilot カスタムエージェント

Microsoft Purview の DLP（データ損失防止）アクティビティを、Microsoft Defender の
Advanced Hunting テーブル **`CloudAppEvents`** から KQL で**週次**集計し、視認性の高い
**HTML/CSS レポート**を **Azure Logic App 経由でメール配信**する Security Copilot カスタムエージェントです。

「秘密度ラベルが付与されたファイル」に対するユーザー操作・DLP 操作（ブロック／検知）を、
Purview の監査ログ（`CloudAppEvents`）を基に集計し、**適用された秘密度ラベル**、
**検出された機密情報の種類（SIT）**、**どのクラウドサービス・経路（SharePoint / OneDrive /
Teams / Exchange / USB / 印刷など）**で操作が行われたか、**どのユーザーに偏っているか**を判別します。

---

## 情報の取得方法（要件）

- Defender に対して **KQL** を用いて週次の統計を取得する。
- **`CloudAppEvents`** を用い、Purview アラートに紐づく条件
  （`RawEventData.Operation` = **`DLPRuleMatch` / `DLPRuleUndo`** 等）を適用して、
  **適用ラベル**と**利用クラウドサービス**を判別する。
- レポートは他エージェント同様、**HTML/CSS の視認性の高いレポート**を **Logic App 経由**で生成する。

参考: [Investigate data loss prevention alerts with Microsoft Sentinel / Defender XDR](https://learn.microsoft.com/ja-jp/defender-xdr/dlp-investigate-alerts-sentinel)

---

## 使用テーブルとカラム

### `CloudAppEvents`（Defender Advanced Hunting）

> The **CloudAppEvents** table contains all audit logs across all locations like SharePoint,
> OneDrive, Exchange and Devices. — [Investigate DLP alerts with Microsoft Defender XDR](https://learn.microsoft.com/defender-xdr/dlp-investigate-alerts-defender)

`CloudAppEvents` は Microsoft 365 の統合監査ログ（Purview DLP 監査データを含む）を保持します。
DLP や秘密度ラベルの詳細は、`RawEventData`（元の監査イベント JSON）内のフィールドに格納されます。

本エージェントが使用する主なカラム／フィールド:

| カラム / フィールド | 用途 |
| --- | --- |
| `Timestamp` | 対象期間フィルタ（週次） |
| `RawEventData.Operation` | **DLP アラートの識別**（`DLPRuleMatch` / `DLPRuleUndo`） |
| `RawEventData.SensitivityLabelEventData.SensitivityLabelId` / `RawEventData.LabelId` / `RawEventData.SensitivityLabelId` / `RawEventData.SharePointMetaData.SensitivityLabelIds` | **適用された秘密度ラベル（GUID）**。複数フィールドを優先順で抽出し、`LabelMap` で名称に変換 |
| `RawEventData.PolicyDetails[].Rules[].ConditionsMatched.SensitiveInformation[].SensitiveInformationTypeName` | **検出された機密情報の種類（SIT）**（例: Credit Card Number） |
| `RawEventData.PolicyDetails[].Rules[].Actions` | **ブロック / 検知の判定**（`BlockAccess`=ブロック、`GenerateAlert`=検知） |
| `RawEventData.Workload` / `Application` | **ワークロード／利用クラウドサービス**（持ち出し経路分析） |
| `AccountDisplayName` / `RawEventData.UserId` / `AccountId` | **ユーザー（実操作者）別集計**。システム/アプリプリンシパル（`APP@SHAREPOINT` 等）の場合はアラート通知先で補完 |
| `RawEventData.PolicyDetails[].Rules[].ActionParameters`（`GenerateAlert:<UPN>`） | **DLP ポリシーのアラート通知先/管理者**（例: `admin@contoso.com`。トリガーした実ユーザーではない） |
| `RawEventData.EvaluationSource` | DLP 評価の契機（例: `DlpPolicyEventBasedAssistantSharePoint` = SharePoint コンテンツスキャン） |
| `RawEventData.PolicyDetails[].PolicyName` / `.Rules[].RuleName` / `.Rules[].Severity` | DLP ポリシー名・ルール名・重大度 |

### ブロック / 検知の判定

DLP ルール一致レコードのアクションに基づいて判定します。`RawEventData` の内容から、
アクセス制御が実行された場合を「ブロック」、監査のみの場合を「検知」とします。

```kusto
| extend RawStr = tostring(RawEventData)
| extend Verdict = iff(RawStr has "BlockAccess"
                       or RawStr has "\"Mode\":\"Block\""
                       or RawStr has "\"EnforcementMode\":\"Block\"", "ブロック", "検知")
```

> **注意（ヒューリスティック判定）:** ブロック／検知の厳密な表現は、ワークロード（Exchange /
> SharePoint / Endpoint）や DLP ポリシー構成によって `RawEventData` 内の格納形式が異なります。
> 実レコード投入後に `RawEventData` の `PolicyDetails[].Rules[].Actions` や
> `EndpointMetaData.EnforcementMode` を確認し、上記判定条件を調整してください。

---

## KQL スキル一覧

すべて **Target: Defender**（Advanced Hunting）で `CloudAppEvents` を対象とし、
週次（過去 7 日）と前週（過去 7〜14 日）の比較のため過去 14 日間を集計します。

| スキル | 目的 | レポート項目 |
| --- | --- | --- |
| `GetDlpDetectionSummary` | 週（今週/前週）× 判定（ブロック/検知）× ワークロード × 適用ラベル別の DLP アラート数 | 1. 対象期間 / 2. エグゼクティブサマリー / 3-1. ラベル毎 |
| `GetDlpBySensitiveInfoType` | 機密情報の種類（SIT）別の検知数（今週/前週 × 判定） | 3-2. 機密情報の種類毎 |
| `GetDlpByEgressChannel` | 持ち出し経路（SharePoint/OneDrive/Teams/Exchange/USB/印刷）別の検知数・判定・ラベル | 3-3. 持ち出し経路分析 |
| `GetDlpByUserAndLabel` | ユーザー × 適用ラベル別の DLP アラート数（ブロック/検知）、検知数降順 Top 10 | 3-4. ユーザー分析 |

### DLP イベントの識別とラベル抽出

DLP 検知イベントは `RawEventData.Operation` で識別します。秘密度ラベルの GUID はレコードによって
格納場所が異なるため、[ナレッジ記事](https://thewindowsupdate.com/2023/05/23/advanced-hunting-for-microsoft-purview-data-loss-prevention-dlp-incidents/)
の手法に従い、**複数フィールドを優先順で抽出**します（従来は `SharePointMetaData` のみを参照しており、
他フィールドのラベルを取りこぼしていました）。

```kusto
| extend LabelGUID1 = tostring(parse_json(tostring(RawEventData.SensitivityLabelEventData)).SensitivityLabelId)
| extend LabelGUID2 = iff(isempty(tostring(RawEventData.LabelId)), LabelGUID1, tostring(RawEventData.LabelId))
| extend LabelGUID3 = iff(isempty(tostring(RawEventData.SensitivityLabelId)), LabelGUID2, tostring(RawEventData.SensitivityLabelId))
| extend SPArrIds  = tostring(RawEventData.SharePointMetaData.SensitivityLabelIds)
| extend SPArrNames = tostring(RawEventData.SharePointMetaData.SensitivityLabelNames)
| extend LabelGUID = coalesce(iff(isempty(LabelGUID3), "", LabelGUID3),
                              iff(SPArrIds != "[]" and isnotempty(SPArrIds), tostring(parse_json(SPArrIds)[0]), ""))
| lookup kind=leftouter LabelMap on $left.LabelGUID == $right.LabelGuid
| extend Label = coalesce(iff(SPArrNames != "[]" and isnotempty(SPArrNames), tostring(parse_json(SPArrNames)[0]), ""),
                          LabelName, iff(isnotempty(LabelGUID), LabelGUID, ""), "ラベルなし/不明")
```

#### GUID → ラベル名の変換テーブル（LabelMap）

`RawEventData` のラベルは **GUID** で格納されます。各 KQL スキルは `LabelMap` という `datatable` で
既定ラベルの GUID を名称に変換します。**テナント固有のカスタムラベル**は、以下の PowerShell で
取得した GUID/名称を `LabelMap` に追記してください（Security & Compliance PowerShell）:

```powershell
Connect-IPPSSession
Get-Label | Select-Object ImmutableId, DisplayName
```

```kusto
let LabelMap = datatable(LabelGuid:string, LabelName:string)
[
  "defa4170-0d19-0005-0000-bc88714345d2","Personal",
  "defa4170-0d19-0005-0002-bc88714345d2","General",
  "defa4170-0d19-0005-0004-bc88714345d2","All Employees (unrestricted)",
  "defa4170-0d19-0005-0005-bc88714345d2","Confidential",
  "defa4170-0d19-0005-0009-bc88714345d2","Highly Confidential"
  // ... カスタムラベルの GUID/名称を追記
];
```

### 機密情報の種類（SIT）の抽出

SIT は `RawEventData.PolicyDetails[]` を `mv-expand` で展開して抽出します。

```kusto
| mv-expand PD = RawEventData.PolicyDetails
| mv-expand Rule = PD.Rules
| mv-expand SI = Rule.ConditionsMatched.SensitiveInformation
| extend SensitiveInfoType = tostring(SI.SensitiveInformationTypeName)   // 例: Credit Card Number
```

### 持ち出し経路の分類

`RawEventData.Workload` と `RawEventData` 内のエンドポイント指標から経路を分類します。

```kusto
| extend EgressChannel = case(
    Workload has "SharePoint", "SharePoint",
    Workload has "OneDrive", "OneDrive",
    Workload has "Teams", "Teams",
    Workload has "Exchange", "Exchange (メール)",
    Workload has "Endpoint" and (RawStr has "RemovableMedia" or RawStr has "USB"), "USB/リムーバブルメディア",
    Workload has "Endpoint" and RawStr has "Print", "印刷",
    Workload has "Endpoint", "エンドポイント (その他)",
    Workload)
```

---

## ⚠️ 前提条件とデータ構造

`CloudAppEvents` に Purview DLP 監査レコードが投入されるには、**Microsoft 365 を Defender for
Cloud Apps に接続**し、**DLP ポリシー（Exchange / SharePoint / OneDrive / Teams / Endpoint）が
稼働**している必要があります。DLP ポリシー違反が発生すると `RawEventData.Operation = DLPRuleMatch`
のレコードが `CloudAppEvents` に現れます。

### 実レコードの構造

DLP イベントの重要情報は `RawEventData` 内の**ワークロード別メタデータ**に格納されます。
`RawEventData.SensitivityLabelId` は DLP レコードでは空のことが多いため、本エージェントは以下を参照します。

| 情報 | 実際の格納先 |
| --- | --- |
| 秘密度ラベル | `RawEventData.SharePointMetaData.SensitivityLabelNames` / `.SensitivityLabelIds`（配列。Exchange/Endpoint は各メタデータ） |
| ブロック/検知 | `RawEventData.PolicyDetails[].Rules[].Actions`（`GenerateAlert`=検知、`BlockAccess`=ブロック） |
| ファイル名 | `RawEventData.SharePointMetaData.FileName` |
| ワークロード / クラウドサービス | `RawEventData.Workload` / `Application` |
| DLP ポリシー・ルール名・重大度 | `RawEventData.PolicyDetails[].PolicyName` / `.Rules[].RuleName` / `.Rules[].Severity` |
| 検出された機密情報の種類 | `RawEventData.PolicyDetails[].Rules[].ConditionsMatched.SensitiveInformation[].SensitiveInformationTypeName` |
| DLP 評価の契機 | `RawEventData.EvaluationSource`（例: `DlpPolicyEventBasedAssistantSharePoint` = SharePoint コンテンツスキャン） |

### ユーザー分析のユーザー値について（重要）

DLP イベントの実操作者は `RawEventData.UserId`（または `AccountDisplayName`）に格納されます。
ただし **SharePoint のイベントベースコンテンツスキャン**（`EvaluationSource =
DlpPolicyEventBasedAssistantSharePoint`）による検知は、対話的なユーザー操作ではなく、
実操作者が `APP@SHAREPOINT` などのシステム/アプリプリンシパルになります。
このような場合、DLP ポリシーの `GenerateAlert:<UPN>` アクションで指定された **アラート通知先
（ポリシー管理者）** が唯一のユーザー UPN であり、これは**トリガーしたユーザーではありません**。

`GetDlpByUserAndLabel` はこの実態に合わせて、以下の優先順でユーザーを判定します:

1. **実操作者**（`RawEventData.UserId` / `AccountDisplayName`）— エンドポイント/メール DLP など
   対話的な操作では実ユーザー UPN がここに入ります。
2. 実操作者がシステム/アプリプリンシパル（`APP@` で始まる）の場合 → **アラート通知先**
   （`GenerateAlert:<UPN>` から抽出した UPN を「（ポリシー管理者/通知先）」付きで表示）。
3. いずれもなければ → 「（システム）」として表示。

```kusto
| extend ActorRaw = coalesce(AccountDisplayName, tostring(RawEventData.UserId), AccountId, "不明")
| extend AlertRecipient = extract(@"GenerateAlert:([^""\]]+)", 1, tostring(RawEventData))
| extend User = case(
    isnotempty(ActorRaw) and not(ActorRaw startswith "APP@") and ActorRaw != "不明", ActorRaw,
    isnotempty(AlertRecipient), strcat(AlertRecipient, " (ポリシー管理者/通知先)"),
    isnotempty(ActorRaw), strcat(ActorRaw, " (システム)"),
    "不明")
```

> DLP レコードが 1 件も見つからない場合、本エージェントは HTML レポート冒頭に注意バナーを表示し、
> 各セクションに「データなし」を明記します（架空データは生成しません）。

---

## レポート項目（出力構成）

PurviewReport.md で定義された順序で HTML レポートを生成します。

1. **対象期間** — 今週の対象期間・前週比較期間・生成日時・今週/前週の総アラート数
2. **エグゼクティブサマリー** — 先週と今週を比較し、DLP アラートの傾向を記載（前週比・ブロック/検知比率・総合リスク判定バナー）
3. **DLP アラート 集計**（各集計に 2〜3 行の傾向コメントを付与）
   - 3-1. **Microsoft Purview ラベル毎の集計**
   - 3-2. **Microsoft Purview 機密情報の種類（SIT）毎の集計**
   - 3-3. **持ち出し経路分析**（SharePoint / OneDrive / Teams / Exchange / USB / 印刷 など）
   - 3-4. **ユーザー分析**（ユーザー × ラベル、Top 10）

---

## エージェント構成

- **種別**: スケジュール実行エージェント（`Interfaces: [Agent]`、`WeeklySchedule` トリガー = 604800 秒）
- **モデル**: `gpt-4o`
- **子スキル**: 4 つの KQL スキル（CloudAppEvents）＋ 1 つの LogicApp スキル
- **RequiredSkillsets**: `PurviewDlpWeeklyReport`（本マニフェスト自身のインラインスキル）
- **出力**: 自己完結型 HTML レポート（インライン CSS、外部リソース・JavaScript 不使用）を
  `SendDlpReportEmail`（Logic App）でメール配信

> レポート生成・HTML 整形・要約・推奨はエージェント本体（GPT）が Instructions に従って実施するため、
> 別途 GPT 子スキルは作成していません。

---

## Logic App（メール送信）

同梱の [PurviewDlpWeeklyReport_LogicApp_ARM.json](PurviewDlpWeeklyReport_LogicApp_ARM.json) を
デプロイすると、HTTP トリガー（`manual`）で受け取った `ReportHtml` を Office 365 コネクタで
メール送信する Logic App が作成されます。

- トリガー: `manual`（HTTP Request）— ボディに `ReportHtml` を受け取る
- アクション: **Parse JSON**（`ReportHtml` を抽出）→ **Send an email (V2)**（`Body` に HTML を設定）
- デプロイ後、Office 365 API 接続の認可（配信元メールボックス）を完了させてください。
- Logic App の **サブスクリプション ID / リソースグループ / ワークフロー名** を、
  プラグイン設定（`LogicAppSubscriptionId` / `LogicAppResourceGroup` / `LogicAppWorkflowName`）に設定します。

---

## デプロイ手順

1. [PurviewDlpWeeklyReport_LogicApp_ARM.json](PurviewDlpWeeklyReport_LogicApp_ARM.json) を
   対象リソースグループ（例: `ispf-resourcegroup`）へデプロイし、Office 365 接続を認可、
   送信先・件名を設定する。
2. Security Copilot の **プラグイン管理**で
   [PurviewDlpWeeklyReport.yaml](PurviewDlpWeeklyReport.yaml) をカスタムプラグインとしてアップロードする。
3. プラグイン設定に Logic App の **サブスクリプション ID / リソースグループ / ワークフロー名**を入力する。
4. **アクティブエージェント**でエージェントをセットアップ（認証）する。
5. 週次スケジュールで自動実行、または手動でレポートを生成・送信する。

---

## 制約と注意点

- ブロック／検知の判定は `RawEventData` に対するヒューリスティックです。実レコードで
  `PolicyDetails[].Rules[].Actions` / `EndpointMetaData.EnforcementMode` を確認し調整してください。
- 秘密度ラベルはテナント固有の GUID（`SensitivityLabelId`）で識別されます。
  ラベル名との対応は Purview のラベル定義を参照してください。
- `CloudAppEvents` の DLP 監査レコードは、M365 と Defender for Cloud Apps の接続、および
  DLP ポリシーの稼働が前提です（前提条件セクション参照）。
- テナントの Advanced Hunting には処理リソースのレート制限があります。スケジュール実行の
  集計は 14 日窓・上位 N 件に制限しています。

## 参考ドキュメント

- [Investigate DLP alerts with Microsoft Sentinel](https://learn.microsoft.com/ja-jp/defender-xdr/dlp-investigate-alerts-sentinel)
- [Investigate DLP alerts with Microsoft Defender XDR](https://learn.microsoft.com/defender-xdr/dlp-investigate-alerts-defender)
- [CloudAppEvents — advanced hunting schema](https://learn.microsoft.com/defender-xdr/advanced-hunting-cloudappevents-table)
- [Connect Microsoft 365 to Microsoft Defender for Cloud Apps](https://learn.microsoft.com/defender-cloud-apps/protect-office-365)
- [Labeling activities available in Activity explorer](https://learn.microsoft.com/purview/data-classification-activity-explorer-available-events)
