# OWASP Mobile Application Security Testing Guide ja - tests-beta

## Android

### MASVS-STORAGE: ストレージ

- [MASTG-TEST-0200](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0200.md) 外部ストレージに書き込まれたファイル (Files Written to External Storage)
- [MASTG-TEST-0201](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0201.md) 外部ストレージにアクセスするための API の実行時使用 (Runtime Use of APIs to Access External Storage)
- [MASTG-TEST-0202](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0202.md) 外部ストレージにアクセスするための API とパーミッションへの参照 (References to APIs and Permissions for Accessing External Storage)
- [MASTG-TEST-0203](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0203.md) ログ記録 API の実行時使用 (Runtime Use of Logging APIs)
- [MASTG-TEST-0207](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0207.md) 実行時にアプリのサンドボックスに保存されるデータ (Data Stored in the App Sandbox at Runtime)
- [MASTG-TEST-0216](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0216.md) バックアップから除外されない機密データ (Sensitive Data Not Excluded From Backup)
- [MASTG-TEST-0231](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0231.md) ログ記録 API への参照 (References to Logging APIs)

### MASVS-CRYPTO: 暗号

- [MASTG-TEST-0204](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0204.md) 安全でないランダム API の使用 (Insecure Random API Usage)
- [MASTG-TEST-0205](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0205.md) ランダムでないソースの使用 (Non-random Sources Usage)
- [MASTG-TEST-0208](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0208.md) 不適切な鍵サイズ (Inappropriate Key Sizes)
- [MASTG-TEST-0212](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0212.md) コード内にハードコードされた暗号鍵の使用 (Use of Hardcoded Cryptographic Keys in Code)
- [MASTG-TEST-0221](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0221.md) 脆弱な対称暗号アルゴリズム (Weak Symmetric Encryption Algorithms)
- [MASTG-TEST-0232](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0232.md) 脆弱な対称暗号モード (Weak Symmetric Encryption Modes)

### MASVS-NETWORK: ネットワーク通信

- [MASTG-TEST-0217](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0217.md) コード内で明示的に許可された安全でない TLS プロトコル (Insecure TLS Protocols Explicitly Allowed in Code)
- [MASTG-TEST-0218](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0218.md) ネットワークトラフィックにおける安全でない TLS プロトコル (Insecure TLS Protocols in Network Traffic)
- [MASTG-TEST-0233](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0233.md) ハードコードされた HTTP URL  (Hardcoded HTTP URLs)
- [MASTG-TEST-0234](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0234.md) ホスト名を適切に検証しない SSLSocket (SSLSockets not Properly Verifying Hostnames)
- [MASTG-TEST-0235](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0235.md) クリアテキストトラフィックを許可する Android アプリ構成 (Android App Configurations Allowing Cleartext Traffic)
- [MASTG-TEST-0236](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0236.md) ネットワーク上で観測されるクリアテキストトラフィック (Cleartext Traffic Observed on the Network)
- [MASTG-TEST-0237](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0237.md) クリアテキストトラフィックを許可するクロスプラットフォーム構成 (Cross-Platform Framework Configurations Allowing Cleartext Traffic)
- [MASTG-TEST-0238](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0238.md) クリアテキストトラフィックを転送するネットワーク API の実行時使用 (Runtime Use of Network APIs Transmitting Cleartext Traffic)
- [MASTG-TEST-0239](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0239.md) カスタム HTTP 接続をセットアップする低レベル API (Socket など) の使用 (Using low-level APIs (e.g. Socket) to set up a custom HTTP connection)
- [MASTG-TEST-0242](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0242.md) Network Security Configuration での証明書ピン留めの欠如 (Missing Certificate Pinning in Network Security Configuration)
- [MASTG-TEST-0243](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0243.md) Network Security Configuration での証明書ピン留めの期限切れ (Expired Certificate Pins in the Network Security Configuration)
- [MASTG-TEST-0244](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0244.md) ネットワークトラフィックでの証明書ピン留めの欠如 (Missing Certificate Pinning in Network Traffic)

### MASVS-PLATFORM: プラットフォーム連携

- [MASTG-TEST-0250](tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0250.md) WebView におけるコンテンツプロバイダアクセスへの参照 (References to Content Provider Access in WebViews)
- [MASTG-TEST-0251](tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0251.md) WebView におけるコンテンツプロバイダアクセス API の実行時使用 (Runtime Use of Content Provider Access APIs in WebViews)
- [MASTG-TEST-0252](tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0252.md) WebView におけるローカルファイルアクセスへの参照 (References to Local File Access in WebViews)
- [MASTG-TEST-0253](tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0253.md) WebView におけるローカルファイルアクセス API の実行時使用 (Runtime Use of Local File Access APIs in WebViews)

### MASVS-CODE: コード品質

- [MASTG-TEST-0222](tests-beta/android/MASVS-CODE/MASTG-TEST-0222.md) 位置独立コード (PIC) が有効でない (Position Independent Code (PIC) Not Enabled)
- [MASTG-TEST-0223](tests-beta/android/MASVS-CODE/MASTG-TEST-0223.md) スタックカナリアが有効でない (Stack Canaries Not Enabled)
- [MASTG-TEST-0245](tests-beta/android/MASVS-CODE/MASTG-TEST-0245.md) プラットフォームバージョン API への参照 (References to Platform Version APIs)

### MASVS-RESILIENCE: リバースエンジニアリングと改竄に対する耐性

- [MASTG-TEST-0224](tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0224.md) 安全でない署名バージョンの使用 (Usage of Insecure Signature Version)
- [MASTG-TEST-0225](tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0225.md) 安全でない署名鍵サイズの使用 (Usage of Insecure Signature Key Size)
- [MASTG-TEST-0226](tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0226.md) AndroidManifest で有効になっているデバッグフラグ (Debuggable Flag Enabled in the AndroidManifest)
- [MASTG-TEST-0227](tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0227.md) WebView のデバッグが有効 (Debugging Enabled for WebViews)
- [MASTG-TEST-0247](tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0247.md) 安全な画面ロックを検出するための API への参照 (References to APIs for Detecting Secure Screen Lock)
- [MASTG-TEST-0249](tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0249.md) 安全な画面ロック検出 API の実行時使用 (Runtime Use of Secure Screen Lock Detection APIs)

### MASVS-PRIVACY: プライバシー

- [MASTG-TEST-0206](tests-beta/android/MASVS-PRIVACY/MASTG-TEST-0206.md) ネットワークトラフィックキャプチャにおける機密データ (Sensitive Data in Network Traffic Capture)
- [MASTG-TEST-0254](tests-beta/android/MASVS-PRIVACY/MASTG-TEST-0254.md) 危険なアプリパーミッション (Dangerous App Permissions)
- [MASTG-TEST-0255](tests-beta/android/MASVS-PRIVACY/MASTG-TEST-0255.md) 最低限でないパーミッションリクエスト (Permission Requests Not Minimized)
- [MASTG-TEST-0256](tests-beta/android/MASVS-PRIVACY/MASTG-TEST-0256.md) パーミッションの理由付けの欠如 (Missing Permission Rationale)

## iOS

### MASVS-STORAGE: ストレージ

- [MASTG-TEST-0215](tests-beta/ios/MASVS-STORAGE/MASTG-TEST-0215.md) バックアップから除外されない機密データ (Sensitive Data Not Excluded From Backup)

### MASVS-CRYPTO: 暗号

- [MASTG-TEST-0209](tests-beta/ios/MASVS-CRYPTO/MASTG-TEST-0209.md) 不適切な鍵サイズ (Inappropriate Key Sizes)
- [MASTG-TEST-0210](tests-beta/ios/MASVS-CRYPTO/MASTG-TEST-0210.md) 脆弱な暗号アルゴリズム (Weak Encryption Algorithms)
- [MASTG-TEST-0211](tests-beta/ios/MASVS-CRYPTO/MASTG-TEST-0211.md) 脆弱なハッシュアルゴリズム (Weak Hashing Algorithms)
- [MASTG-TEST-0213](tests-beta/ios/MASVS-CRYPTO/MASTG-TEST-0213.md) コード内にハードコードされた暗号鍵の使用 (Use of Hardcoded Cryptographic Keys in Code)
- [MASTG-TEST-0214](tests-beta/ios/MASVS-CRYPTO/MASTG-TEST-0214.md) ファイル内にハードコードされた暗号鍵 (Hardcoded Cryptographic Keys in Files)

### MASVS-CODE: コード品質

- [MASTG-TEST-0228](tests-beta/ios/MASVS-CODE/MASTG-TEST-0228.md) 位置独立コード (PIC) が有効でない (Position Independent Code (PIC) not Enabled)
- [MASTG-TEST-0229](tests-beta/ios/MASVS-CODE/MASTG-TEST-0229.md) スタックカナリアが有効でない (Stack Canaries Not enabled)
- [MASTG-TEST-0230](tests-beta/ios/MASVS-CODE/MASTG-TEST-0230.md) 自動参照カウント (ARC) が有効でない (Automatic Reference Counting (ARC) not enabled)

### MASVS-RESILIENCE: リバースエンジニアリングと改竄に対する耐性

- [MASTG-TEST-0219](tests-beta/ios/MASVS-RESILIENCE/MASTG-TEST-0219.md) デバッグシンボルのテスト (Testing for Debugging Symbols)
- [MASTG-TEST-0220](tests-beta/ios/MASVS-RESILIENCE/MASTG-TEST-0220.md) 古いコード署名フォーマットの使用 (Usage of Outdated Code Signature Format)
- [MASTG-TEST-0240](tests-beta/ios/MASVS-RESILIENCE/MASTG-TEST-0240.md) コード内の脱獄検出 (Jailbreak Detection in Code)
- [MASTG-TEST-0241](tests-beta/ios/MASVS-RESILIENCE/MASTG-TEST-0241.md) 脱獄検出技法の実行時使用 (Runtime Use of Jailbreak Detection Techniques)
- [MASTG-TEST-0246](tests-beta/ios/MASVS-RESILIENCE/MASTG-TEST-0246.md) 安全な画面ロック検出 API の実行時使用 (Runtime Use of Secure Screen Lock Detection APIs)
- [MASTG-TEST-0248](tests-beta/ios/MASVS-RESILIENCE/MASTG-TEST-0248.md) 安全な画面ロックを検出するための API への参照 (References to APIs for Detecting Secure Screen Lock)
