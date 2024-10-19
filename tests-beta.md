# OWASP Mobile Application Security Testing Guide ja - tests-beta

## Android

### MASVS-STORAGE: ストレージ

- [MASTG-TEST-0200 外部ストレージに書き込まれたファイル (Files Written to External Storage)](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0200.md)
- [MASTG-TEST-0201 外部ストレージにアクセスするための API の実行時使用 (Runtime Use of APIs to Access External Storage)](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0201.md)
- [MASTG-TEST-0202 外部ストレージにアクセスするための API とパーミッションへの参照 (References to APIs and Permissions for Accessing External Storage)](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0202.md)
- [MASTG-TEST-0203 ログ記録 API を介した機密データの漏洩 (Leakage of Sensitive Data via Logging APIs)](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0203.md)
- [MASTG-TEST-0207 実行時にアプリのサンドボックスに保存されるデータ (Data Stored in the App Sandbox at Runtime)](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0207.md)
- [MASTG-TEST-0216 バックアップから除外されない機密データ (Sensitive Data Not Excluded From Backup)](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0216.md)

### MASVS-CRYPTO: 暗号

- [MASTG-TEST-0204 安全でないランダム API の使用 (Insecure Random API Usage)](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0204.md)
- [MASTG-TEST-0205 ランダムでないソースの使用 (Non-random Sources Usage)](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0205.md)
- [MASTG-TEST-0208 不適切な鍵サイズ (Inappropriate Key Sizes)](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0208.md)
- [MASTG-TEST-0212 コード内にハードコードされた暗号鍵の使用 (Use of Hardcoded Cryptographic Keys in Code)](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0212.md)

### MASVS-PRIVACY: プライバシー

- [MASTG-TEST-0206 ネットワークトラフィックキャプチャにおける機密データ (Sensitive Data in Network Traffic Capture)](tests-beta/android/MASVS-PRIVACY/MASTG-TEST-0206.md)

## iOS

### MASVS-CRYPTO: 暗号

- [MASTG-TEST-0209 不適切な鍵サイズ (Inappropriate Key Sizes)](tests-beta/ios/MASVS-CRYPTO/MASTG-TEST-0209.md)
- [MASTG-TEST-0210 脆弱な暗号アルゴリズム (Weak Encryption Algorithms)](tests-beta/ios/MASVS-CRYPTO/MASTG-TEST-0210.md)
- [MASTG-TEST-0211 脆弱なハッシュアルゴリズム (Weak Hashing Algorithms)](tests-beta/ios/MASVS-CRYPTO/MASTG-TEST-0211.md)
- [MASTG-TEST-0213 コード内にハードコードされた暗号鍵の使用 (Use of Hardcoded Cryptographic Keys in Code)](tests-beta/ios/MASVS-CRYPTO/MASTG-TEST-0213.md)
- [MASTG-TEST-0214 ファイル内にハードコードされた暗号鍵 (Hardcoded Cryptographic Keys in Files)](tests-beta/ios/MASVS-CRYPTO/MASTG-TEST-0214.md)
