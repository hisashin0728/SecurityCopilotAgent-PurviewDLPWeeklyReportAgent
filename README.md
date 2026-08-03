# Purview DLP Weekly Report — Security Copilot カスタムエージェント

Microsoft Purview の DLP（データ損失防止）アクティビティを、Microsoft Defender の
Advanced Hunting テーブル **`CloudAppEvents`** から KQL で**週次**集計し、視認性の高い
**HTML/CSS レポート**を **Azure Logic App 経由でメール配信**する Security Copilot カスタムエージェントです。

「秘密度ラベルが付与されたファイル」に対するユーザー操作・DLP 操作（ブロック／検知）を、
Purview の監査ログ（`CloudAppEvents`）を基に集計し、**適用された秘密度ラベル**、
**検出された機密情報の種類（SIT）**、**どのクラウドサービス・経路（SharePoint / OneDrive /
Teams / Exchange / USB / 印刷など）**で操作が行われたか、**どのユーザーに偏っているか**を判別します。

---

## なぜ CloudAppEvents によるログ分析レポートなのか

DLP の状況把握には「アラートを見る」方法と「監査ログ（イベント）を分析する」方法があります。
本エージェントが後者（`CloudAppEvents` のログ分析）を採用している理由を説明します。

### 1. Purview の DLP アラートだけでは情報が足りない

Purview / Defender の **DLP アラート**（Purview アラートポータル、Defender の `AlertInfo` /
`AlertEvidence` 等）は「ポリシーに違反した」という**事象の通知**が主目的で、集約・重複排除された
サマリー情報です。週次の傾向分析に必要な以下の粒度が**取り出しにくい／欠落**します。

- **適用された秘密度ラベル**が何か（Confidential / Highly Confidential 等）
- **検出された機密情報の種類（SIT）**別の件数（クレジットカード番号、マイナンバー等）
- **持ち出し経路**（SharePoint / OneDrive / Teams / Exchange / USB / 印刷）ごとの内訳
- **ユーザー別**の実操作の偏り（誰に集中しているか）
- **ブロック／検知**の内訳をイベント単位で
- 前週比などの**時系列の集計・トレンド**

アラートは「気づき」には向きますが、**定量的な週次レポート**の材料としては粒度が粗く、
ラベル・SIT・経路・ユーザーを軸にした多面的な集計には不向きです。

### 2. Purview DLP イベントを記録する主なテーブルの比較

| データソース | 取得手段 | 収録内容 | 自動集計（KQL） | 可用性 |
| --- | --- | --- | --- | --- |
| **`CloudAppEvents`**（本エージェント採用） | Defender Advanced Hunting | M365 統合監査ログ全体（SharePoint/OneDrive/Exchange/Teams/Endpoint）。`RawEventData` に DLP 詳細（ラベル・SIT・アクション・ワークロード・操作者）を内包 | ○ | Defender for Cloud Apps 接続済みなら広く利用可 |
| `DataSecurityEvents`（Preview） | Defender Advanced Hunting | Purview IRM/DSPM 由来。ラベル・アクション等が**構造化カラム**で提供（`RawEventData` パース不要） | ○（きれい） | **Preview＋IRM→Defender オプトインが必要**。未有効だと `cannot resolve table` |
| `DataSecurityBehaviors`（Preview） | Defender Advanced Hunting | ユーザーのデータ操作「行動」単位 | ○ | 同上（Preview／オプトイン必要） |
| `AlertInfo` / `AlertEvidence` | Defender Advanced Hunting | DLP **アラート**の粒度（ポリシー名・重大度・件数） | △（アラート単位のみ） | 広く利用可だが粒度が粗い |
| Purview アラート／Activity Explorer | Purview ポータル UI | ラベル・DLP アクティビティの閲覧 | ✕（UI 中心・自動化困難） | 利用可だが API/自動化に不向き |
| 統合監査ログ（UAL）/ Graph API | API | 生の監査イベント | △（別基盤で実装が必要） | 実装コスト高 |

要点:
- **アラート系**（`AlertInfo` 等）は粒度が粗く、ラベル/SIT/経路/ユーザーの多軸集計に不足。
- **`DataSecurityEvents`（Preview）**は構造化されていて理想的だが、**IRM→Defender の
  オプトインが未有効だと利用できない**（`cannot resolve table`）ため前提が重い。
- **`CloudAppEvents`** は M365 監査ログ全体を 1 テーブルで KQL 集計でき、可用性が高い。

### 3. メリット・デメリット（CloudAppEvents 採用の理由）

**メリット**
- **1 テーブルで全ワークロード横断**（SharePoint/OneDrive/Exchange/Teams/Endpoint）。経路別分析に最適。
- **Defender Advanced Hunting で KQL 集計が可能** → Security Copilot エージェントで**自動化・週次レポート化**できる。
- `RawEventData` に **ラベル・SIT・アクション・ワークロード・操作者**まで含み、多軸の集計に必要な詳細が揃う。
- **Preview 機能のオプトイン不要**（Defender for Cloud Apps 接続済みなら利用可）で、導入前提が比較的軽い。
- アラートと違い**イベント単位**なので、ブロック／検知や前週比などの定量集計が可能。

**デメリット（と対処）**
- **Defender for Cloud Apps への M365 接続が前提**。未接続だとテーブルが空（→ 前提条件を要確認）。
- 詳細が **`RawEventData` のネスト JSON** に入り、**ワークロードごとに格納形式が異なる**ため
  パースが複雑（ブロック/検知はヒューリスティック判定が必要）。
- 秘密度ラベルは **GUID 格納** → `LabelMap` で名称変換が必要（カスタムラベルは追記）。
- **SharePoint のイベントベーススキャン**は操作者が `APP@SHAREPOINT` 等のシステム
  プリンシパルになり、実ユーザー特定が難しい（→ アラート通知先で補完）。
- Advanced Hunting の**保持期間は約30日**（週次レポート用途には十分だが長期保管には別途必要）。

### まとめ

構造化された `DataSecurityEvents`（Preview）が使える環境なら将来的にそちらが有利ですが、
**オプトイン前提が重く未有効なテナントが多い**ため、本エージェントは**可用性が高く、
全ワークロードを 1 テーブルで KQL 集計できる `CloudAppEvents`** を採用しています。
アラートでは得られない**ラベル／SIT／経路／ユーザーの多軸集計**を、自動化された週次 HTML
レポートとして提供できる点が最大の価値です。

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
| `RawEventData.SharePointMetaData.FileName` / `.FilePathUrl` / `RawEventData.EndpointMetaData.TargetFilePath` | **対象ファイル名・パス**（ファイル分析。拡張子から種別を判定、`parse_path` でフォルダを抽出） |
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

すべて **Target: Defender**（Advanced Hunting）です。DLP アクティビティ集計の4スキルは
`CloudAppEvents`、ファイル分析の2スキルは `AlertInfo` / `AlertEvidence` を対象とし、
週次（過去 7 日）と前週（過去 7〜14 日）の比較のため過去 14 日間を集計します。

| スキル | 目的 | レポート項目 |
| --- | --- | --- |
| `GetDlpDetectionSummary` | 週（今週/前週）× 判定（ブロック/検知）× ワークロード × 適用ラベル別の DLP アラート数 | 1. 対象期間 / 2. エグゼクティブサマリー / 3-1. ラベル毎 |
| `GetDlpBySensitiveInfoType` | 機密情報の種類（SIT）別の検知数（今週/前週 × 判定） | 3-2. 機密情報の種類毎 |
| `GetDlpByEgressChannel` | 持ち出し経路（SharePoint/OneDrive/Teams/Exchange/USB/印刷）別の検知数・判定・ラベル | 3-3. 持ち出し経路分析 |
| `GetDlpByUserAndLabel` | ユーザー × 適用ラベル別の DLP アラート数（ブロック/検知）、検知数降順 Top 10 | 3-4. ユーザー分析 |
| `GetDlpFileStatistics` | DLP アラートのファイル証拠を、種別（Excel/Word/PDF 等）× アプリケーション/検出元 × 週別に集計（**Defender AlertInfo / AlertEvidence**） | 3-5. ファイル分析 |
| `GetDlpAlertFileEvidence` | DLP アラートのファイル証拠：**今週のみ**、ファイル名×DLPルール×ディレクトリ別の件数 Top 20（**Defender AlertInfo / AlertEvidence**） | 3-5. ファイル分析 |

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

### ファイル分析（種別・パス）

DLP アラートの対象ファイルは、Defender の **`AlertInfo`** と **`AlertEvidence`** を `AlertId` で結合して
抽出します（`GetDlpFileStatistics`）。`AlertInfo.ServiceSource == "Microsoft Data Loss Prevention"` で
DLP アラートを限定し、`AlertEvidence.EntityType == "File"` の `FileName` / `FolderPath` を使用します。
アラート発生時刻を基準に今週/前週へ分け、拡張子から種別（Excel / Word / PDF / PowerPoint /
テキスト等）を判定します。`Workload` 出力列には `AlertEvidence.Application`、空の場合は
`DetectionSource` を格納します。

```kusto
let dlpAlerts = AlertInfo
    | where Timestamp > ago(14d)
    | where ServiceSource == "Microsoft Data Loss Prevention"
    | summarize AlertTimestamp = max(Timestamp) by AlertId
    | extend Week = iff(AlertTimestamp > ago(7d), "今週", "前週")
    | project AlertId, Week;
AlertEvidence
| where Timestamp > ago(14d)
| where EntityType =~ "File" and isnotempty(FileName)
| project AlertId, FileName = url_decode(FileName), Folder = url_decode(FolderPath),
    Workload = coalesce(Application, DetectionSource, "不明")
| join kind=inner (dlpAlerts) on AlertId
| extend FileExt = tolower(extract(@"\.([A-Za-z0-9]{1,6})$", 1, FileName))
| extend FileType = case(FileExt in ("xlsx","xls","csv"), "Excel/表計算",
                         FileExt in ("docx","doc"), "Word", FileExt == "pdf", "PDF",
                         FileExt in ("pptx","ppt"), "PowerPoint", FileExt in ("txt","rtf"), "テキスト",
       isnotempty(FileExt), strcat("その他 (.", FileExt, ")"), "種別不明")
```

> DLP ルールでアラート生成が無効な場合、`CloudAppEvents` にルール一致が存在しても
> `AlertInfo` / `AlertEvidence` には出力されないため、ファイル分析は「データなし」になります。

#### DLP アラートのファイル証拠（Defender AlertInfo / AlertEvidence）

アラートレベルのファイル証拠（エンドポイント/クラウド両方の DLP アラート）は、Defender の
**`AlertInfo`**（`ServiceSource == "Microsoft Data Loss Prevention"`）と **`AlertEvidence`** を結合して
取得します（`GetDlpAlertFileEvidence`、**Target: Defender** で Sentinel 不要）。トークン量を考慮し、
**今週（過去 7 日）のみ、件数降順 Top 20** に限定します。DLP アラートルール名は
`AlertInfo.Title`（例:「DLP policy (ルール名) matched for ...」）から `extract` で抽出し、
**ファイル名 × DLP ルール × ディレクトリ** で集計します。ファイル名・パスは `url_decode` で可読化します。

```kusto
let dlpAlerts = AlertInfo
    | where Timestamp > ago(7d)
    | where ServiceSource == "Microsoft Data Loss Prevention"
    | extend DlpRule = extract(@"DLP policy \(([^)]+)\)", 1, Title)
    | project AlertId, DlpRule;
AlertEvidence
| where Timestamp > ago(7d)
| where EntityType == "File" and isnotempty(FileName)
| join kind=inner (dlpAlerts) on AlertId
| extend FileName = url_decode(FileName), Directory = url_decode(FolderPath)
| summarize Count = count() by FileType, FileName, DlpRule, Directory
| sort by Count desc
| take 20
```

> 出力列: `FileType | FileName | DlpRule | Directory | Count`。
> 出力例（実データで検証済み）: `テキスト | dlp-test-20260730-084007.txt | DLP Test - Credit Card Detection | https://.../DLPSimulation | 1`、
> ZAVA: `Word | Project Obsidian.docx | <ルール名> | .../personal/u3044_int_zava-corp_com/Documents | N`。

> このスキルは **Target: Defender**（Advanced Hunting）のみで動作し、Sentinel ワークスペース設定は不要です。
> エンドポイント DLP（ローカルパス）・クラウド DLP（SharePoint/OneDrive パス）の両方のファイル証拠を含みます。

---

## ⚠️ 前提条件とデータ構造

`CloudAppEvents` に Purview DLP 監査レコードが投入されるには、**Microsoft 365 を Defender for
Cloud Apps に接続**し、**DLP ポリシー（Exchange / SharePoint / OneDrive / Teams / Endpoint）が
稼働**している必要があります。DLP ポリシー違反が発生すると `RawEventData.Operation = DLPRuleMatch`
のレコードが `CloudAppEvents` に現れます。

### 【必須】AlertInfo / AlertEvidence に DLP アラートを出力する設定

本エージェントのファイル分析（3-5）は **Defender の `AlertInfo` / `AlertEvidence`** に
**`ServiceSource = "Microsoft Data Loss Prevention"`** のアラートが出力されていることが前提です。
DLP アラートが Defender XDR（＝ Advanced Hunting の `AlertInfo` / `AlertEvidence`）に流れるには、
以下の設定が必要です。

| # | 設定項目 | 内容 |
| --- | --- | --- |
| 1 | **ライセンス** | Microsoft Purview DLP + Microsoft Defender XDR（Advanced Hunting）。フルのアラート機能は **Microsoft 365 E5 / E5 Compliance** を推奨（E3 はアラート集計の挙動が異なる） |
| 2 | **DLP ポリシーの作成・有効化** | Microsoft Purview ポータル（[purview.microsoft.com](https://purview.microsoft.com)）で対象ワークロード（Exchange / SharePoint / OneDrive / Teams / **デバイス＝エンドポイント DLP**）の DLP ポリシーを作成し、**有効（オン）** にする |
| 3 | **ルールでアラートを有効化（最重要）** | 各 DLP ポリシーの **ルール編集 → 「インシデントレポート（Incident reports）」** で **「ルールが一致したときにアラートを生成する」** をオンにする。アラート重大度（低/中/高）も設定する。**この設定が無いとアラートは生成されず、`AlertInfo` に出力されません** |
| 4 | **Defender XDR への統合（既定でオン）** | DLP アラートは Microsoft Defender ポータルの統合インシデントキューに **自動連携** されます（IRM のような個別オプトインは不要）。Defender ポータル > **インシデントとアラート** で **サービス/検出ソース = Microsoft Data Loss Prevention** のフィルタで確認できます |
| 5 | **エンドポイント DLP（デバイス）** | ローカルファイルのファイル名・パスを取得するには、対象デバイスを **Microsoft Purview（エンドポイント DLP）にオンボード**し、デバイス向け DLP ポリシー（USB / 印刷 / クラウドアップロード等）でアラートを有効化する |
| 6 | **反映確認** | 設定後、DLP ポリシー違反を発生させ、Advanced Hunting で次を実行してレコードを確認する:<br>`AlertInfo \| where ServiceSource == "Microsoft Data Loss Prevention" \| take 10` |

> **確認クエリ（ファイル証拠の有無）:**
> ```kusto
> let dlpAlerts = AlertInfo
>     | where Timestamp > ago(14d)
>     | where ServiceSource == "Microsoft Data Loss Prevention"
>     | distinct AlertId;
> AlertEvidence
> | where Timestamp > ago(14d)
> | where AlertId in (dlpAlerts) and EntityType == "File"
> | project Timestamp, AlertId, FileName, FolderPath
> ```
> `AlertInfo`（`ServiceSource == "Microsoft Data Loss Prevention"`, `Category == "Exfiltration"`）に
> レコードが無い場合、上記 **手順 3（ルールのアラート生成）** が未設定の可能性が高いです。
> `GetDlpAlertFileEvidence` スキルはデータが無い場合「データなし」を明記します（架空データは生成しません）。

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
   - 3-5. **ファイル分析**（ファイル種別 Excel/Word/PDF 等 ― 種別ごとの流出ファイル名・ディレクトリ一覧）

---

## エージェント構成

- **種別**: スケジュール実行エージェント（`Interfaces: [Agent]`、`WeeklySchedule` トリガー = 604800 秒）
- **モデル**: `gpt-4o`
- **子スキル**: 6 つの KQL スキル（CloudAppEvents 5 + AlertInfo/AlertEvidence 1、すべて Target: Defender）＋ 1 つの LogicApp スキル
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
