# OWASP Mobile Application Security Testing Guide ja - tests-beta

## Android

### MASVS-STORAGE: ストレージ

- [MASTG-TEST-0200](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0200.md) 外部ストレージに書き込まれたファイル (Files Written to External Storage)
- [MASTG-TEST-0201](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0201.md) 外部ストレージにアクセスするための API の実行時使用 (Runtime Use of APIs to Access External Storage)
- [MASTG-TEST-0202](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0202.md) 外部ストレージにアクセスするための API とパーミッションへの参照 (References to APIs and Permissions for Accessing External Storage)
- [MASTG-TEST-0203](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0203.md) ログ記録 API を介した機密データの漏洩 (Leakage of Sensitive Data via Logging APIs)
- [MASTG-TEST-0207](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0207.md) 実行時にアプリのサンドボックスに保存されるデータ (Data Stored in the App Sandbox at Runtime)
- [MASTG-TEST-0216](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0216.md) バックアップから除外されない機密データ (Sensitive Data Not Excluded From Backup)

### MASVS-CRYPTO: 暗号

- [MASTG-TEST-0204](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0204.md) 安全でないランダム API の使用 (Insecure Random API Usage)
- [MASTG-TEST-0205](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0205.md) ランダムでないソースの使用 (Non-random Sources Usage)
- [MASTG-TEST-0208](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0208.md) 不適切な鍵サイズ (Inappropriate Key Sizes)
- [MASTG-TEST-0212](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0212.md) コード内にハードコードされた暗号鍵の使用 (Use of Hardcoded Cryptographic Keys in Code)
- [MASTG-TEST-0221](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0221.md) 脆弱な暗号アルゴリズム (Weak Encryption Algorithms)

### MASVS-NETWORK: ネットワーク通信

- [MASTG-TEST-0217](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0217.md) コード内で明示的に許可された安全でない TLS プロトコル (Insecure TLS Protocols Explicitly Allowed in Code)
- [MASTG-TEST-0218](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0218.md) ネットワークトラフィックにおける安全でない TLS プロトコル (Insecure TLS Protocols in Network Traffic)

### MASVS-CODE: コード品質

- [MASTG-TEST-0222](tests-beta/android/MASVS-CODE/MASTG-TEST-0222.md) 位置独立コード (PIC) が有効でない (Position Independent Code (PIC) Not Enabled)
- [MASTG-TEST-0223](tests-beta/android/MASVS-CODE/MASTG-TEST-0223.md) スタックカナリアが有効でない (Stack Canaries Not Enabled)

### MASVS-RESILIENCE: リバースエンジニアリングと改竄に対する耐性

- [MASTG-TEST-0224](tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0224.md) 安全でない署名バージョンの使用 (Usage of Insecure Signature Version)
- [MASTG-TEST-0225](tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0225.md) 安全でない署名鍵サイズの使用 (Usage of Insecure Signature Key Size)

### MASVS-PRIVACY: プライバシー

- [MASTG-TEST-0206](tests-beta/android/MASVS-PRIVACY/MASTG-TEST-0206.md) ネットワークトラフィックキャプチャにおける機密データ (Sensitive Data in Network Traffic Capture)

## iOS

### MASVS-STORAGE: ストレージ

- [MASTG-TEST-0215](tests-beta/ios/MASVS-STORAGE/MASTG-TEST-0215.md) バックアップから除外されない機密データ (Sensitive Data Not Excluded From Backup)

### MASVS-CRYPTO: 暗号

- [MASTG-TEST-0209](tests-beta/ios/MASVS-CRYPTO/MASTG-TEST-0209.md) 不適切な鍵サイズ (Inappropriate Key Sizes)
- [MASTG-TEST-0210](tests-beta/ios/MASVS-CRYPTO/MASTG-TEST-0210.md) 脆弱な暗号アルゴリズム (Weak Encryption Algorithms)
- [MASTG-TEST-0211](tests-beta/ios/MASVS-CRYPTO/MASTG-TEST-0211.md) 脆弱なハッシュアルゴリズム (Weak Hashing Algorithms)
- [MASTG-TEST-0213](tests-beta/ios/MASVS-CRYPTO/MASTG-TEST-0213.md) コード内にハードコードされた暗号鍵の使用 (Use of Hardcoded Cryptographic Keys in Code)
- [MASTG-TEST-0214](tests-beta/ios/MASVS-CRYPTO/MASTG-TEST-0214.md) ファイル内にハードコードされた暗号鍵 (Hardcoded Cryptographic Keys in Files)

### MASVS-RESILIENCE: リバースエンジニアリングと改竄に対する耐性

- [MASTG-TEST-0219](tests-beta/ios/MASVS-RESILIENCE/MASTG-TEST-0219.md) デバッグシンボルのテスト (Testing for Debugging Symbols)
- [MASTG-TEST-0220](tests-beta/ios/MASVS-RESILIENCE/MASTG-TEST-0220.md) 古いコード署名フォーマットの使用 (Usage of Outdated Code Signature Format)
