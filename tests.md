# OWASP Mobile Application Security Testing Guide ja - tests

## Android

### MASVS-STORAGE: ストレージ

<!--
- [MASTG-TEST-0001](tests/android/MASVS-STORAGE/MASTG-TEST-0001.md) 機密データに対してのローカルストレージのテスト (Testing Local Storage for Sensitive Data)
- [MASTG-TEST-0003](tests/android/MASVS-STORAGE/MASTG-TEST-0003.md) 機密データに対してのログのテスト (Testing Logs for Sensitive Data)
- [MASTG-TEST-0004](tests/android/MASVS-STORAGE/MASTG-TEST-0004.md) 機密データが組み込みサービスを介してサードパーティと共有されるかどうかの判定 (Determining Whether Sensitive Data Is Shared with Third Parties via Embedded Services)
- [MASTG-TEST-0005](tests/android/MASVS-STORAGE/MASTG-TEST-0005.md) 機密データが通知を介してサードパーティと共有されるかどうかの判定 (Determining Whether Sensitive Data Is Shared with Third Parties via Notifications)
- [MASTG-TEST-0006](tests/android/MASVS-STORAGE/MASTG-TEST-0006.md) テキスト入力フィールドでキーボードキャッシュが無効かどうかの判定 (Determining Whether the Keyboard Cache Is Disabled for Text Input Fields)
- [MASTG-TEST-0009](tests/android/MASVS-STORAGE/MASTG-TEST-0009.md) 機密データに対してのバックアップのテスト (Testing Backups for Sensitive Data)
- [MASTG-TEST-0011](tests/android/MASVS-STORAGE/MASTG-TEST-0011.md) 機密データに対してのメモリのテスト (Testing Memory for Sensitive Data)
- [MASTG-TEST-0012](tests/android/MASVS-STORAGE/MASTG-TEST-0012.md) デバイスアクセスセキュリティポリシーのテスト (Testing the Device-Access-Security Policy)
-->

### MASVS-CRYPTO: 暗号

- [MASTG-TEST-0013](tests/android/MASVS-CRYPTO/MASTG-TEST-0013.md) 対称暗号のテスト (Testing Symmetric Cryptography)
- [MASTG-TEST-0014](tests/android/MASVS-CRYPTO/MASTG-TEST-0014.md) 暗号標準アルゴリズムの設定のテスト (Testing the Configuration of Cryptographic Standard Algorithms)
- [MASTG-TEST-0015](tests/android/MASVS-CRYPTO/MASTG-TEST-0015.md) 鍵の目的のテスト (Testing the Purposes of Keys)
- [MASTG-TEST-0016](tests/android/MASVS-CRYPTO/MASTG-TEST-0016.md) 乱数生成のテスト (Testing Random Number Generation)

### MASVS-AUTH: 認証と認可

- [MASTG-TEST-0017](tests/android/MASVS-AUTH/MASTG-TEST-0017.md) 認証情報確認のテスト (Testing Confirm Credentials)
- [MASTG-TEST-0018](tests/android/MASVS-AUTH/MASTG-TEST-0018.md) 生体認証のテスト (Testing Biometric Authentication)

### MASVS-NETWORK: ネットワーク通信

- [MASTG-TEST-0019](tests/android/MASVS-NETWORK/MASTG-TEST-0019.md) ネットワーク上のデータ暗号化のテスト (Testing Data Encryption on the Network)
- [MASTG-TEST-0020](tests/android/MASVS-NETWORK/MASTG-TEST-0020.md) TLS 設定のテスト (Testing the TLS Settings)
- [MASTG-TEST-0021](tests/android/MASVS-NETWORK/MASTG-TEST-0021.md) エンドポイント同一性検証のテスト (Testing Endpoint Identify Verification)
- [MASTG-TEST-0022](tests/android/MASVS-NETWORK/MASTG-TEST-0022.md) カスタム証明書ストアおよび証明書ピン留めのテスト (Testing Custom Certificate Stores and Certificate Pinning)
- [MASTG-TEST-0023](tests/android/MASVS-NETWORK/MASTG-TEST-0023.md) セキュリティプロバイダのテスト (Testing the Security Provider)

### MASVS-PLATFORM: プラットフォーム連携

<!--
- [MASTG-TEST-0007](tests/android/MASVS-PLATFORM/MASTG-TEST-0007.md) IPC メカニズムを介して機密性の高いデータが漏洩したかどうかの判定 (Determining Whether Sensitive Stored Data Has Been Exposed via IPC Mechanisms)
- [MASTG-TEST-0008](tests/android/MASVS-PLATFORM/MASTG-TEST-0008.md) ユーザーインタフェースを介した機密データの漏洩のチェック (Checking for Sensitive Data Disclosure Through the User Interface)
- [MASTG-TEST-0010](tests/android/MASVS-PLATFORM/MASTG-TEST-0010.md) 自動生成されたスクリーンショット内の機密情報を見つける (Finding Sensitive Information in Auto-Generated Screenshots)
- [MASTG-TEST-0024](tests/android/MASVS-PLATFORM/MASTG-TEST-0024.md) アプリパーミッションのテスト (Testing for App Permissions)
- [MASTG-TEST-0028](tests/android/MASVS-PLATFORM/MASTG-TEST-0028.md) ディープリンクのテスト (Testing Deep Links)
- [MASTG-TEST-0029](tests/android/MASVS-PLATFORM/MASTG-TEST-0029.md) IPC を介した機密機能露出のテスト (Testing for Sensitive Functionality Exposure Through IPC)
- [MASTG-TEST-0030](tests/android/MASVS-PLATFORM/MASTG-TEST-0030.md) PendingIntent の脆弱な実装のテスト (Testing for Vulnerable Implementation of PendingIntent)
- [MASTG-TEST-0031](tests/android/MASVS-PLATFORM/MASTG-TEST-0031.md) WebView での JavaScript 実行のテスト (Testing JavaScript Execution in WebViews)
- [MASTG-TEST-0032](tests/android/MASVS-PLATFORM/MASTG-TEST-0032.md) WebView プロトコルハンドラのテスト (Testing WebView Protocol Handlers)
- [MASTG-TEST-0033](tests/android/MASVS-PLATFORM/MASTG-TEST-0033.md) WebView を介して公開される Java オブジェクトのテスト (Testing for Java Objects Exposed Through WebViews)
- [MASTG-TEST-0035](tests/android/MASVS-PLATFORM/MASTG-TEST-0035.md) オーバーレイ攻撃のテスト (Testing for Overlay Attacks)
- [MASTG-TEST-0037](tests/android/MASVS-PLATFORM/MASTG-TEST-0037.md) WebView クリーンアップのテスト (Testing WebViews Cleanup)
-->

### MASVS-CODE: コード品質

- [MASTG-TEST-0002](tests/android/MASVS-CODE/MASTG-TEST-0002.md) ローカルストレージの入力バリデーションのテスト (Testing Local Storage for Input Validation)
- [MASTG-TEST-0025](tests/android/MASVS-CODE/MASTG-TEST-0025.md) インジェクション欠陥のテスト (Testing for Injection Flaws)
- [MASTG-TEST-0026](tests/android/MASVS-CODE/MASTG-TEST-0026.md) 暗黙的インテントのテスト (Testing Implicit Intents)
- [MASTG-TEST-0027](tests/android/MASVS-CODE/MASTG-TEST-0027.md) WebView での URL ローディングのテスト (Testing for URL Loading in WebViews)
- [MASTG-TEST-0034](tests/android/MASVS-CODE/MASTG-TEST-0034.md) オブジェクト永続化のテスト (Testing Object Persistence)
- [MASTG-TEST-0036](tests/android/MASVS-CODE/MASTG-TEST-0036.md) 強制更新のテスト (Testing Enforced Updating)
- [MASTG-TEST-0042](tests/android/MASVS-CODE/MASTG-TEST-0042.md) サードパーティーライブラリの脆弱性の確認 (Checking for Weaknesses in Third Party Libraries)
- [MASTG-TEST-0043](tests/android/MASVS-CODE/MASTG-TEST-0043.md) メモリ破損バグ (Memory Corruption Bugs)
- [MASTG-TEST-0044](tests/android/MASVS-CODE/MASTG-TEST-0044.md) フリーのセキュリティ機能が有効であることの確認 (Make Sure That Free Security Features Are Activated)

### MASVS-RESILIENCE: リバースエンジニアリングと改竄に対する耐性

- [MASTG-TEST-0038](tests/android/MASVS-RESILIENCE/MASTG-TEST-0038.md) アプリが正しく署名されていることの確認 (Making Sure that the App is Properly Signed)
- [MASTG-TEST-0039](tests/android/MASVS-RESILIENCE/MASTG-TEST-0039.md) アプリがデバッグ可能であるかのテスト (Testing whether the App is Debuggable)
- [MASTG-TEST-0040](tests/android/MASVS-RESILIENCE/MASTG-TEST-0040.md) デバッグシンボルに関するテスト (Testing for Debugging Symbols)
- [MASTG-TEST-0041](tests/android/MASVS-RESILIENCE/MASTG-TEST-0041.md) デバッグコードと詳細エラーログに関するテスト (Testing for Debugging Code and Verbose Error Logging)
- [MASTG-TEST-0045](tests/android/MASVS-RESILIENCE/MASTG-TEST-0045.md) ルート検出のテスト (Testing Root Detection)
- [MASTG-TEST-0046](tests/android/MASVS-RESILIENCE/MASTG-TEST-0046.md) アンチデバッグ検出のテスト (Testing Anti-Debugging Detection)
- [MASTG-TEST-0047](tests/android/MASVS-RESILIENCE/MASTG-TEST-0047.md) ファイル完全性チェックのテスト (Testing File Integrity Checks)
- [MASTG-TEST-0048](tests/android/MASVS-RESILIENCE/MASTG-TEST-0048.md) リバースエンジニアリングツール検出のテスト (Testing Reverse Engineering Tools Detection)
- [MASTG-TEST-0049](tests/android/MASVS-RESILIENCE/MASTG-TEST-0049.md) エミュレータ検出のテスト (Testing Emulator Detection)
- [MASTG-TEST-0050](tests/android/MASVS-RESILIENCE/MASTG-TEST-0050.md) ランタイム完全性チェックのテスト (Testing Runtime Integrity Checks)
- [MASTG-TEST-0051](tests/android/MASVS-RESILIENCE/MASTG-TEST-0051.md) 難読化のテスト (Testing Obfuscation)

## iOS

### MASVS-STORAGE: ストレージ

<!--
- [MASTG-TEST-0052](tests/ios/MASVS-STORAGE/MASTG-TEST-0052.md) ローカルデータストレージのテスト (Testing Local Data Storage)
- [MASTG-TEST-0053](tests/ios/MASVS-STORAGE/MASTG-TEST-0053.md) 機密データのログチェック (Checking Logs for Sensitive Data)
- [MASTG-TEST-0054](tests/ios/MASVS-STORAGE/MASTG-TEST-0054.md) 機密データがサードパーティと共有されるかどうかの判定 (Determining Whether Sensitive Data Is Shared with Third Parties)
- [MASTG-TEST-0055](tests/ios/MASVS-STORAGE/MASTG-TEST-0055.md) キーボードキャッシュ内の機密データの調査 (Finding Sensitive Data in the Keyboard Cache)
- [MASTG-TEST-0058](tests/ios/MASVS-STORAGE/MASTG-TEST-0058.md) 機密データに対してのバックアップのテスト (Testing Backups for Sensitive Data)
- [MASTG-TEST-0060](tests/ios/MASVS-STORAGE/MASTG-TEST-0060.md) 機密データに対してのメモリのテスト (Testing Memory for Sensitive Data)
-->

### MASVS-CRYPTO: 暗号

- [MASTG-TEST-0061](tests/ios/MASVS-CRYPTO/MASTG-TEST-0061.md) 暗号標準アルゴリズムの構成の検証 (Verifying the Configuration of Cryptographic Standard Algorithms)
- [MASTG-TEST-0062](tests/ios/MASVS-CRYPTO/MASTG-TEST-0062.md) 鍵管理のテスト (Testing Key Management)
- [MASTG-TEST-0063](tests/ios/MASVS-CRYPTO/MASTG-TEST-0063.md) 乱数生成のテスト (Testing Random Number Generation)

### MASVS-AUTH: 認証と認可

- [MASTG-TEST-0064](tests/ios/MASVS-AUTH/MASTG-TEST-0064.md) 生体認証のテスト (Testing Biometric Authentication)

### MASVS-NETWORK: ネットワーク通信

- [MASTG-TEST-0065](tests/ios/MASVS-NETWORK/MASTG-TEST-0065.md) ネットワーク上のデータ暗号化のテスト (Testing Data Encryption on the Network)
- [MASTG-TEST-0066](tests/ios/MASVS-NETWORK/MASTG-TEST-0066.md) TLS 設定のテスト (Testing the TLS Settings)
- [MASTG-TEST-0067](tests/ios/MASVS-NETWORK/MASTG-TEST-0067.md) エンドポイント同一性検証のテスト (Testing Endpoint Identity Verification)
- [MASTG-TEST-0068](tests/ios/MASVS-NETWORK/MASTG-TEST-0068.md) カスタム証明書ストアおよび証明書ピン留めのテスト (Testing Custom Certificate Stores and Certificate Pinning)

### MASVS-PLATFORM: プラットフォーム連携

<!--
- [MASTG-TEST-0056](tests/ios/MASVS-PLATFORM/MASTG-TEST-0056.md) 機密データが IPC メカニズムを介して開示されているかどうかの判断 (Determining Whether Sensitive Data Is Exposed via IPC Mechanisms)
- [MASTG-TEST-0057](tests/ios/MASVS-PLATFORM/MASTG-TEST-0057.md) 機密データがユーザーインタフェースを通じて開示されているかどうかのチェック (Checking for Sensitive Data Disclosed Through the User Interface)
- [MASTG-TEST-0059](tests/ios/MASVS-PLATFORM/MASTG-TEST-0059.md) 自動生成されたスクリーンショットの機密情報についてのテスト (Testing Auto-Generated Screenshots for Sensitive Information)
- [MASTG-TEST-0069](tests/ios/MASVS-PLATFORM/MASTG-TEST-0069.md) アプリパーミッションのテスト (Testing App Permissions)
- [MASTG-TEST-0070](tests/ios/MASVS-PLATFORM/MASTG-TEST-0070.md) ユニバーサルリンクのテスト (Testing Universal Links)
- [MASTG-TEST-0071](tests/ios/MASVS-PLATFORM/MASTG-TEST-0071.md) UIActivity 共有のテスト (Testing UIActivity Sharing)
- [MASTG-TEST-0072](tests/ios/MASVS-PLATFORM/MASTG-TEST-0072.md) App Extension のテスト (Testing App Extensions)
-->
- [MASTG-TEST-0073](tests/ios/MASVS-PLATFORM/MASTG-TEST-0073.md) UIPasteboard のテスト (Testing UIPasteboard)
<!--
- [MASTG-TEST-0074](tests/ios/MASVS-PLATFORM/MASTG-TEST-0074.md) IPC を介した機密機能露出のテスト (Testing for Sensitive Functionality Exposure Through IPC)
- [MASTG-TEST-0075](tests/ios/MASVS-PLATFORM/MASTG-TEST-0075.md) カスタム URL スキームのテスト (Testing Custom URL Schemes)
- [MASTG-TEST-0076](tests/ios/MASVS-PLATFORM/MASTG-TEST-0076.md) iOS WebView のテスト (Testing iOS WebViews)
- [MASTG-TEST-0077](tests/ios/MASVS-PLATFORM/MASTG-TEST-0077.md) WebView プロトコルハンドラのテスト (Testing WebView Protocol Handlers)
- [MASTG-TEST-0078](tests/ios/MASVS-PLATFORM/MASTG-TEST-0078.md) WebView を介してネイティブメソッドが公開されているかどうかの判断 (Determining Whether Native Methods Are Exposed Through WebViews)
-->

### MASVS-CODE: コード品質

- [MASTG-TEST-0079](tests/ios/MASVS-CODE/MASTG-TEST-0079.md) オブジェクト永続化のテスト (Testing Object Persistence)
- [MASTG-TEST-0080](tests/ios/MASVS-CODE/MASTG-TEST-0080.md) 強制更新のテスト (Testing Enforced Updating)
- [MASTG-TEST-0085](tests/ios/MASVS-CODE/MASTG-TEST-0085.md) サードパーティライブラリの脆弱性のチェック (Checking for Weaknesses in Third Party Libraries)
- [MASTG-TEST-0086](tests/ios/MASVS-CODE/MASTG-TEST-0086.md) メモリ破損バグ (Memory Corruption Bugs)
- [MASTG-TEST-0087](tests/ios/MASVS-CODE/MASTG-TEST-0087.md) フリーなセキュリティ機能が有効であることの確認 (Make Sure That Free Security Features Are Activated)

### MASVS-RESILIENCE: リバースエンジニアリングと改竄に対する耐性

- [MASTG-TEST-0081](tests/ios/MASVS-RESILIENCE/MASTG-TEST-0081.md) アプリが正しく署名されていることの確認 (Making Sure that the App Is Properly Signed)
- [MASTG-TEST-0082](tests/ios/MASVS-RESILIENCE/MASTG-TEST-0082.md) アプリがデバッグ可能かどうかのテスト (Testing whether the App is Debuggable)
- [MASTG-TEST-0083](tests/ios/MASVS-RESILIENCE/MASTG-TEST-0083.md) デバッグシンボルのテスト (Testing for Debugging Symbols)
- [MASTG-TEST-0084](tests/ios/MASVS-RESILIENCE/MASTG-TEST-0084.md) デバッグコードと詳細エラーログのテスト (Testing for Debugging Code and Verbose Error Logging)
- [MASTG-TEST-0088](tests/ios/MASVS-RESILIENCE/MASTG-TEST-0088.md) 脱獄検出のテスト (Testing Jailbreak Detection)
- [MASTG-TEST-0089](tests/ios/MASVS-RESILIENCE/MASTG-TEST-0089.md) アンチデバッグ検出のテスト (Testing Anti-Debugging Detection)
- [MASTG-TEST-0090](tests/ios/MASVS-RESILIENCE/MASTG-TEST-0090.md) ファイル完全性チェックのテスト (Testing File Integrity Checks)
- [MASTG-TEST-0091](tests/ios/MASVS-RESILIENCE/MASTG-TEST-0091.md) リバースエンジニアリングツール検出のテスト (Testing Reverse Engineering Tools Detection)
- [MASTG-TEST-0092](tests/ios/MASVS-RESILIENCE/MASTG-TEST-0092.md) エミュレータ検出のテスト (Testing Emulator Detection)
- [MASTG-TEST-0093](tests/ios/MASVS-RESILIENCE/MASTG-TEST-0093.md) 難読化のテスト (Testing Obfuscation)
