# OWASP Mobile Application Security Testing Guide ja - tests-beta

## Android

### MASVS-STORAGE: ストレージ

- [MASTG-TEST-0200](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0200.md) 外部ストレージに書き込まれたファイル (Files Written to External Storage)
- [MASTG-TEST-0201](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0201.md) 外部ストレージにアクセスするための API の実行時使用 (Runtime Use of APIs to Access External Storage)
- [MASTG-TEST-0202](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0202.md) 外部ストレージにアクセスするための API とパーミッションへの参照 (References to APIs and Permissions for Accessing External Storage)
- [MASTG-TEST-0203](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0203.md) ログ記録 API の実行時使用 (Runtime Use of Logging APIs)
- [MASTG-TEST-0207](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0207.md) アプリのサンドボックスでの暗号化していないデータの実行時保存 (Runtime Storage of Unencrypted Data in the App Sandbox)
- [MASTG-TEST-0216](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0216.md) バックアップから除外されない機密データ (Sensitive Data Not Excluded From Backup)
- [MASTG-TEST-0231](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0231.md) ログ記録 API への参照 (References to Logging APIs)
- [MASTG-TEST-0262](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0262.md) 機密データを除外しないバックアップ構成への参照 (References to Backup Configurations Not Excluding Sensitive Data)
- [MASTG-TEST-0287](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0287.md) SharedPreferences API を介してアプリサンドボックスに暗号化されずに保存される機密データ (Sensitive Data Stored Unencrypted via the SharedPreferences API to the App Sandbox)
- [MASTG-TEST-0304](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0304.md) SQLite 経由で暗号化されずに保存される機密データ (Sensitive Data Stored Unencrypted via SQLite)
- [MASTG-TEST-0305](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0305.md) DataStore 経由で暗号化されずに保存される機密データ (Sensitive Data Stored Unencrypted via DataStore)
- [MASTG-TEST-0306](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0306.md) Android Room DB 経由で暗号化されずに保存される機密データ (Sensitive Data Stored Unencrypted via Android Room DB)

### MASVS-CRYPTO: 暗号

- [MASTG-TEST-0204](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0204.md) 安全でないランダム API の使用 (Insecure Random API Usage)
- [MASTG-TEST-0205](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0205.md) ランダムでないソースの使用 (Non-random Sources Usage)
- [MASTG-TEST-0208](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0208.md) 不十分な鍵サイズ (Insufficient Key Sizes)
- [MASTG-TEST-0212](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0212.md) コード内にハードコードされた暗号鍵の使用 (Use of Hardcoded Cryptographic Keys in Code)
- [MASTG-TEST-0221](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0221.md) 不備のある対称暗号アルゴリズム (Broken Symmetric Encryption Algorithms)
- [MASTG-TEST-0232](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0232.md) 不備のある対称暗号モード (Broken Symmetric Encryption Modes)
- [MASTG-TEST-0307](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0307.md) 複数の目的で使用される非対称鍵ペアへの参照 (References to Asymmetric Key Pairs Used For Multiple Purposes)
- [MASTG-TEST-0308](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0308.md) 複数の目的で使用される非対称鍵ペアの実行時使用 (Runtime Use of Asymmetric Key Pairs Used For Multiple Purposes)
- [MASTG-TEST-0309](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0309.md) 対称暗号化での再使用される初期化ベクトルへの参照 (References to Reused Initialization Vectors in Symmetric Encryption)
- [MASTG-TEST-0310](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0310.md) 対称暗号化での再使用される初期化ベクトルの実行時使用 (Runtime Use of Reused Initialization Vectors in Symmetric Encryption)
- [MASTG-TEST-0312](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0312.md) 暗号 API での明示的なセキュリティプロバイダへの参照 (References to Explicit Security Provider in Cryptographic APIs)

### MASVS-NETWORK: ネットワーク通信

- [MASTG-TEST-0217](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0217.md) コード内で明示的に許可された安全でない TLS プロトコル (Insecure TLS Protocols Explicitly Allowed in Code)
- [MASTG-TEST-0218](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0218.md) ネットワークトラフィックにおける安全でない TLS プロトコル (Insecure TLS Protocols in Network Traffic)
- [MASTG-TEST-0233](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0233.md) ハードコードされた HTTP URL  (Hardcoded HTTP URLs)
- [MASTG-TEST-0234](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0234.md) SSLSocket でのサーバーホスト名検証の実装の欠如 (Missing Implementation of Server Hostname Verification with SSLSockets)
- [MASTG-TEST-0235](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0235.md) クリアテキストトラフィックを許可する Android アプリ構成 (Android App Configurations Allowing Cleartext Traffic)
- [MASTG-TEST-0236](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0236.md) ネットワーク上で観測されるクリアテキストトラフィック (Cleartext Traffic Observed on the Network)
- [MASTG-TEST-0237](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0237.md) クリアテキストトラフィックを許可するクロスプラットフォーム構成 (Cross-Platform Framework Configurations Allowing Cleartext Traffic)
- [MASTG-TEST-0238](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0238.md) クリアテキストトラフィックを転送するネットワーク API の実行時使用 (Runtime Use of Network APIs Transmitting Cleartext Traffic)
- [MASTG-TEST-0239](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0239.md) カスタム HTTP 接続をセットアップする低レベル API (Socket など) の使用 (Using low-level APIs (e.g. Socket) to set up a custom HTTP connection)
- [MASTG-TEST-0242](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0242.md) Network Security Configuration での証明書ピン留めの欠如 (Missing Certificate Pinning in Network Security Configuration)
- [MASTG-TEST-0243](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0243.md) Network Security Configuration での証明書ピン留めの期限切れ (Expired Certificate Pins in the Network Security Configuration)
- [MASTG-TEST-0244](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0244.md) ネットワークトラフィックでの証明書ピン留めの欠如 (Missing Certificate Pinning in Network Traffic)
- [MASTG-TEST-0282](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0282.md) 安全でないカスタムトラスト評価 (Unsafe Custom Trust Evaluation)
- [MASTG-TEST-0283](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0283.md) サーバーホスト名検証の正しくない実装 (Incorrect Implementation of Server Hostname Verification)
- [MASTG-TEST-0284](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0284.md) WebView での正しくない SSL エラー処理 (Incorrect SSL Error Handling in WebViews)
- [MASTG-TEST-0285](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0285.md) ユーザー提供の CA を信頼する古い Android バージョン (Outdated Android Version Allowing Trust in User-Provided CAs)
- [MASTG-TEST-0286](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0286.md) ユーザー提供の CA を信頼する Network Security Configuration (Network Security Configuration Allowing Trust in User-Provided CAs)
- [MASTG-TEST-0295](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0295.md) 更新されていない GMS セキュリティプロバイダ (GMS Security Provider Not Updated)

### MASVS-PLATFORM: プラットフォーム連携

- [MASTG-TEST-0250](tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0250.md) WebView におけるコンテンツプロバイダアクセスへの参照 (References to Content Provider Access in WebViews)
- [MASTG-TEST-0251](tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0251.md) WebView におけるコンテンツプロバイダアクセス API の実行時使用 (Runtime Use of Content Provider Access APIs in WebViews)
- [MASTG-TEST-0252](tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0252.md) WebView におけるローカルファイルアクセスへの参照 (References to Local File Access in WebViews)
- [MASTG-TEST-0253](tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0253.md) WebView におけるローカルファイルアクセス API の実行時使用 (Runtime Use of Local File Access APIs in WebViews)
- [MASTG-TEST-0258](tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0258.md) UI 要素のキーボードキャッシュ属性への参照 (References to Keyboard Caching Attributes in UI Elements)
- [MASTG-TEST-0289](tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0289.md) アプリのバックグラウンド時のスクリーンショットでの機密コンテンツ露出の実行時検証 (Runtime Verification of Sensitive Content Exposure in Screenshots During App Backgrounding)
- [MASTG-TEST-0291](tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0291.md) スクリーンキャプチャ防止 API への参照 (References to Screen Capturing Prevention APIs)
- [MASTG-TEST-0292](tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0292.md) バックグラウンド時にスクリーンショットを防止するために使用されていない `setRecentsScreenshotEnabled` (`setRecentsScreenshotEnabled` Not Used to Prevent Screenshots When Backgrounded)
- [MASTG-TEST-0293](tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0293.md) SurfaceView でのスクリーンショットを防止するために使用されていない `setSecure` (`setSecure` Not Used to Prevent Screenshots in SurfaceViews)
- [MASTG-TEST-0294](tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0294.md) Compose ダイアログのスクリーンショットを防止するために使用されていない `SecureOn` (`SecureOn` Not Used to Prevent Screenshots in Compose Dialogs)

### MASVS-CODE: コード品質

- [MASTG-TEST-0222](tests-beta/android/MASVS-CODE/MASTG-TEST-0222.md) 位置独立コード (PIC) が有効でない (Position Independent Code (PIC) Not Enabled)
- [MASTG-TEST-0223](tests-beta/android/MASVS-CODE/MASTG-TEST-0223.md) スタックカナリアが有効でない (Stack Canaries Not Enabled)
- [MASTG-TEST-0245](tests-beta/android/MASVS-CODE/MASTG-TEST-0245.md) プラットフォームバージョン API への参照 (References to Platform Version APIs)
- [MASTG-TEST-0272](tests-beta/android/MASVS-CODE/MASTG-TEST-0272.md) Android プロジェクトでの既知の脆弱性を持つ依存関係を特定する (Identify Dependencies with Known Vulnerabilities in the Android Project)
- [MASTG-TEST-0274](tests-beta/android/MASVS-CODE/MASTG-TEST-0274.md) アプリの SBOM での既知の脆弱性を持つ依存関係 (Dependencies with Known Vulnerabilities in the App's SBOM)

### MASVS-RESILIENCE: リバースエンジニアリングと改竄に対する耐性

- [MASTG-TEST-0224](tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0224.md) 安全でない署名バージョンの使用 (Usage of Insecure Signature Version)
- [MASTG-TEST-0225](tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0225.md) 安全でない署名鍵サイズの使用 (Usage of Insecure Signature Key Size)
- [MASTG-TEST-0226](tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0226.md) AndroidManifest で有効になっているデバッグフラグ (Debuggable Flag Enabled in the AndroidManifest)
- [MASTG-TEST-0227](tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0227.md) WebView のデバッグが有効 (Debugging Enabled for WebViews)
- [MASTG-TEST-0247](tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0247.md) 安全な画面ロックを検出するための API への参照 (References to APIs for Detecting Secure Screen Lock)
- [MASTG-TEST-0249](tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0249.md) 安全な画面ロック検出 API の実行時使用 (Runtime Use of Secure Screen Lock Detection APIs)
- [MASTG-TEST-0263](tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0263.md) StrictMode 違反のログ記録 (Logging of StrictMode Violations)
- [MASTG-TEST-0264](tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0264.md) StrictMode API の実行時使用 (Runtime Use of StrictMode APIs)
- [MASTG-TEST-0265](tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0265.md) StrictMode API への参照 (References to StrictMode APIs)
- [MASTG-TEST-0288](tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0288.md) ネイティブバイナリのデバッグシンボル (Debugging Symbols in Native Binaries)

### MASVS-PRIVACY: プライバシー

- [MASTG-TEST-0206](tests-beta/android/MASVS-PRIVACY/MASTG-TEST-0206.md) ネットワークトラフィックキャプチャにおける宣言されていない PII (Undeclared PII in Network Traffic Capture)
- [MASTG-TEST-0254](tests-beta/android/MASVS-PRIVACY/MASTG-TEST-0254.md) 危険なアプリパーミッション (Dangerous App Permissions)
- [MASTG-TEST-0255](tests-beta/android/MASVS-PRIVACY/MASTG-TEST-0255.md) 最低限でないパーミッションリクエスト (Permission Requests Not Minimized)
- [MASTG-TEST-0256](tests-beta/android/MASVS-PRIVACY/MASTG-TEST-0256.md) パーミッションの理由付けの欠如 (Missing Permission Rationale)
- [MASTG-TEST-0257](tests-beta/android/MASVS-PRIVACY/MASTG-TEST-0257.md) リセットしていない未使用のパーミッション (Not Resetting Unused Permissions)

## iOS

### MASVS-STORAGE: ストレージ

- [MASTG-TEST-0215](tests-beta/ios/MASVS-STORAGE/MASTG-TEST-0215.md) バックアップ除外としてマークされていない機密データ (Sensitive Data Not Marked For Backup Exclusion)
- [MASTG-TEST-0296](tests-beta/ios/MASVS-STORAGE/MASTG-TEST-0296.md) 安全でないログ記録による機密データ露出 (Sensitive Data Exposure Through Insecure Logging)
- [MASTG-TEST-0297](tests-beta/ios/MASVS-STORAGE/MASTG-TEST-0297.md) ログへの機密データの挿入 (Insertion of Sensitive Data into Logs)
- [MASTG-TEST-0298](tests-beta/ios/MASVS-STORAGE/MASTG-TEST-0298.md) バックアップ対象のファイルの実行時監視 (Runtime Monitoring of Files Eligible for Backup)
- [MASTG-TEST-0299](tests-beta/ios/MASVS-STORAGE/MASTG-TEST-0299.md) プライベートストレージでのファイルのデータ保護クラス (Data Protection Classes for Files in Private Storage)
- [MASTG-TEST-0300](tests-beta/ios/MASVS-STORAGE/MASTG-TEST-0300.md) プライベートストレージに暗号化されていないデータを保存するための API への参照 (References to APIs for Storing Unencrypted Data in Private Storage)
- [MASTG-TEST-0301](tests-beta/ios/MASVS-STORAGE/MASTG-TEST-0301.md) プライベートストレージに暗号化されていないデータを保存するための API の実行時使用 (Runtime Use of APIs for Storing Unencrypted Data in Private Storage)
- [MASTG-TEST-0302](tests-beta/ios/MASVS-STORAGE/MASTG-TEST-0302.md) プライベートストレージファイル内の暗号化されていない機密データ (Sensitive Data Unencrypted in Private Storage Files)
- [MASTG-TEST-0303](tests-beta/ios/MASVS-STORAGE/MASTG-TEST-0303.md) 共有ストレージに暗号化されていないデータを保存するための API への参照 (References to APIs for Storing Unencrypted Data in Shared Storage)

### MASVS-CRYPTO: 暗号

- [MASTG-TEST-0209](tests-beta/ios/MASVS-CRYPTO/MASTG-TEST-0209.md) 不十分な鍵サイズ (Insufficient Key Sizes)
- [MASTG-TEST-0210](tests-beta/ios/MASVS-CRYPTO/MASTG-TEST-0210.md) 不備のある対称暗号アルゴリズム (Broken Symmetric Encryption Algorithms)
- [MASTG-TEST-0211](tests-beta/ios/MASVS-CRYPTO/MASTG-TEST-0211.md) 不備のあるハッシュアルゴリズム (Broken Hashing Algorithms)
- [MASTG-TEST-0213](tests-beta/ios/MASVS-CRYPTO/MASTG-TEST-0213.md) コード内にハードコードされた暗号鍵の使用 (Use of Hardcoded Cryptographic Keys in Code)
- [MASTG-TEST-0214](tests-beta/ios/MASVS-CRYPTO/MASTG-TEST-0214.md) ファイル内にハードコードされた暗号鍵 (Hardcoded Cryptographic Keys in Files)
- [MASTG-TEST-0311](tests-beta/ios/MASVS-CRYPTO/MASTG-TEST-0311.md) 安全でないランダム API の使用 (Insecure Random API Usage)

### MASVS-AUTH: 認証と認可

- [MASTG-TEST-0266](tests-beta/ios/MASVS-AUTH/MASTG-TEST-0266.md) イベントバウンド型生体認証用の API への参照 (References to APIs for Event-Bound Biometric Authentication)
- [MASTG-TEST-0267](tests-beta/ios/MASVS-AUTH/MASTG-TEST-0267.md) イベントバウンド型生体認証の実行時使用 (Runtime Use Of Event-Bound Biometric Authentication)
- [MASTG-TEST-0268](tests-beta/ios/MASVS-AUTH/MASTG-TEST-0268.md) 非生体認証へのフォールバックを許可する API への参照 (References to APIs Allowing Fallback to Non-Biometric Authentication)
- [MASTG-TEST-0269](tests-beta/ios/MASVS-AUTH/MASTG-TEST-0269.md) 非生体認証へのフォールバックを許可する API の実行時使用 (Runtime Use Of APIs Allowing Fallback to Non-Biometric Authentication)
- [MASTG-TEST-0270](tests-beta/ios/MASVS-AUTH/MASTG-TEST-0270.md) 生体認証登録の変更を検出する API への参照 (References to APIs Detecting Biometric Enrollment Changes)
- [MASTG-TEST-0271](tests-beta/ios/MASVS-AUTH/MASTG-TEST-0271.md) 生体認証登録の変更を検出する API の実行時使用 (Runtime Use Of APIs Detecting Biometric Enrollment Changes)

### MASVS-PLATFORM: プラットフォーム連携

- [MASTG-TEST-0276](tests-beta/ios/MASVS-PLATFORM/MASTG-TEST-0276.md) iOS の汎用ペーストボードの使用 (Use of the iOS General Pasteboard)
- [MASTG-TEST-0277](tests-beta/ios/MASVS-PLATFORM/MASTG-TEST-0277.md) 実行時の iOS の汎用ペーストボード内の機密データ (Sensitive Data in the iOS General Pasteboard at Runtime)
- [MASTG-TEST-0278](tests-beta/ios/MASVS-PLATFORM/MASTG-TEST-0278.md) 使用後にクリアされないペーストボードコンテンツ (Pasteboard Contents Not Cleared After Use)
- [MASTG-TEST-0279](tests-beta/ios/MASVS-PLATFORM/MASTG-TEST-0279.md) 期限切れにならないペーストボードコンテンツ (Pasteboard Contents Not Expiring)
- [MASTG-TEST-0280](tests-beta/ios/MASVS-PLATFORM/MASTG-TEST-0280.md) ローカルデバイスに制限されていないペーストボードコンテンツ (Pasteboard Contents Not Restricted to Local Device)
- [MASTG-TEST-0290](tests-beta/ios/MASVS-PLATFORM/MASTG-TEST-0290.md) アプリのバックグラウンド時のスクリーンショットでの機密コンテンツ露出の実行時検証 (Runtime Verification of Sensitive Content Exposure in Screenshots During App Backgrounding)

### MASVS-CODE: コード品質

- [MASTG-TEST-0228](tests-beta/ios/MASVS-CODE/MASTG-TEST-0228.md) 位置独立コード (PIC) が有効でない (Position Independent Code (PIC) not Enabled)
- [MASTG-TEST-0229](tests-beta/ios/MASVS-CODE/MASTG-TEST-0229.md) スタックカナリアが有効でない (Stack Canaries Not enabled)
- [MASTG-TEST-0230](tests-beta/ios/MASVS-CODE/MASTG-TEST-0230.md) 自動参照カウント (ARC) が有効でない (Automatic Reference Counting (ARC) not enabled)
- [MASTG-TEST-0273](tests-beta/ios/MASVS-CODE/MASTG-TEST-0273.md) 依存関係マネージャのアーティファクトをスキャンして既知の脆弱性を持つ依存関係を特定する (Identify Dependencies with Known Vulnerabilities by Scanning Dependency Managers Artifacts)
- [MASTG-TEST-0275](tests-beta/ios/MASVS-CODE/MASTG-TEST-0275.md) アプリの SBOM での既知の脆弱性を持つ依存関係 (Dependencies with Known Vulnerabilities in the App's SBOM)

### MASVS-RESILIENCE: リバースエンジニアリングと改竄に対する耐性

- [MASTG-TEST-0219](tests-beta/ios/MASVS-RESILIENCE/MASTG-TEST-0219.md) デバッグシンボルのテスト (Testing for Debugging Symbols)
- [MASTG-TEST-0220](tests-beta/ios/MASVS-RESILIENCE/MASTG-TEST-0220.md) 古いコード署名フォーマットの使用 (Usage of Outdated Code Signature Format)
- [MASTG-TEST-0240](tests-beta/ios/MASVS-RESILIENCE/MASTG-TEST-0240.md) コード内の脱獄検出 (Jailbreak Detection in Code)
- [MASTG-TEST-0241](tests-beta/ios/MASVS-RESILIENCE/MASTG-TEST-0241.md) 脱獄検出技法の実行時使用 (Runtime Use of Jailbreak Detection Techniques)
- [MASTG-TEST-0246](tests-beta/ios/MASVS-RESILIENCE/MASTG-TEST-0246.md) 安全な画面ロック検出 API の実行時使用 (Runtime Use of Secure Screen Lock Detection APIs)
- [MASTG-TEST-0248](tests-beta/ios/MASVS-RESILIENCE/MASTG-TEST-0248.md) 安全な画面ロックを検出するための API への参照 (References to APIs for Detecting Secure Screen Lock)
- [MASTG-TEST-0261](tests-beta/ios/MASVS-RESILIENCE/MASTG-TEST-0261.md) entitlements.plist で有効になっているデバッグ可能なエンタイトルメント (Debuggable Entitlement Enabled in the entitlements.plist)

### MASVS-PRIVACY: プライバシー

- [MASTG-TEST-0281](tests-beta/ios/MASVS-PRIVACY/MASTG-TEST-0281.md) 未宣言の既知のトラッキングドメイン (Undeclared Known Tracking Domains)
