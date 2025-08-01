# OWASP Mobile Application Security Testing Guide ja - knowledge

## Android

### MASVS-STORAGE: ストレージ

<!--
- [MASTG-KNOW-0036](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0036.md) Shared Preferences
- [MASTG-KNOW-0037](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0037.md) SQLite Database
- [MASTG-KNOW-0038](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0038.md) SQLCipher Database
- [MASTG-KNOW-0039](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0039.md) Firebase Real-time Databases
- [MASTG-KNOW-0040](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0040.md) Realm Databases
- [MASTG-KNOW-0041](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0041.md) Internal Storage
- [MASTG-KNOW-0042](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0042.md) External Storage
- [MASTG-KNOW-0043](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0043.md) Android KeyStore
- [MASTG-KNOW-0044](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0044.md) Key Attestation
- [MASTG-KNOW-0045](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0045.md) Secure Key Import into Keystore
- [MASTG-KNOW-0046](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0046.md) BouncyCastle KeyStore
- [MASTG-KNOW-0047](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0047.md) Cryptographic Key Storage
- [MASTG-KNOW-0048](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0048.md) KeyChain
- [MASTG-KNOW-0049](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0049.md) Logs
- [MASTG-KNOW-0050](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0050.md) Backups
- [MASTG-KNOW-0051](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0051.md) Process Memory
- [MASTG-KNOW-0052](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0052.md) User Interface Components
- [MASTG-KNOW-0053](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0053.md) Screenshots
- [MASTG-KNOW-0054](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0054.md) App Notifications
- [MASTG-KNOW-0055](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0055.md) Keyboard Cache
-->

### MASVS-CRYPTO: 暗号

- [MASTG-KNOW-0011](knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0011.md) セキュリティプロバイダ (Security Provider)
- [MASTG-KNOW-0012](knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012.md) 鍵生成 (Key Generation)
- [MASTG-KNOW-0013](knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0013.md) 乱数生成 (Random number generation)

### MASVS-AUTH: 認証と認可

- [MASTG-KNOW-0001](knowledge/android/MASVS-AUTH/MASTG-KNOW-0001.md) 生体認証 (Biometric Authentication)
- [MASTG-KNOW-0002](knowledge/android/MASVS-AUTH/MASTG-KNOW-0002.md) FingerprintManager

### MASVS-NETWORK: ネットワーク通信

- [MASTG-KNOW-0014](knowledge/android/MASVS-NETWORK/MASTG-KNOW-0014.md) Android Network Security Configuration
- [MASTG-KNOW-0015](knowledge/android/MASVS-NETWORK/MASTG-KNOW-0015.md) 証明書ピン留め (Certificate Pinning)
- [MASTG-KNOW-0016](knowledge/android/MASVS-NETWORK/MASTG-KNOW-0016.md) TBD

### MASVS-PLATFORM: プラットフォーム連携

<!--
- [MASTG-KNOW-0017](knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0017.md) App Permissions
- [MASTG-KNOW-0018](knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0018.md) WebViews
- [MASTG-KNOW-0019](knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0019.md) Deep Links
- [MASTG-KNOW-0020](knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0020.md) Inter-Process Communication (IPC) Mechanisms
- [MASTG-KNOW-0021](knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0021.md) Object Serialization
- [MASTG-KNOW-0022](knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0022.md) Overlay Attacks
- [MASTG-KNOW-0023](knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0023.md) Enforced Updating
- [MASTG-KNOW-0024](knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0024.md) Pending Intents
- [MASTG-KNOW-0025](knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0025.md) Implicit Intents
-->

### MASVS-CODE: コード品質

- [MASTG-KNOW-0003](knowledge/android/MASVS-CODE/MASTG-KNOW-0003.md) アプリ署名 (App Signing)
- [MASTG-KNOW-0004](knowledge/android/MASVS-CODE/MASTG-KNOW-0004.md) サードパーティーライブラリ (Third-Party Libraries)
- [MASTG-KNOW-0005](knowledge/android/MASVS-CODE/MASTG-KNOW-0005.md) メモリ破損バグ (Memory Corruption Bugs)
- [MASTG-KNOW-0006](knowledge/android/MASVS-CODE/MASTG-KNOW-0006.md) バイナリ保護メカニズム (Binary Protection Mechanisms)
- [MASTG-KNOW-0007](knowledge/android/MASVS-CODE/MASTG-KNOW-0007.md) デバッグ可能アプリ (Debuggable Apps)
- [MASTG-KNOW-0008](knowledge/android/MASVS-CODE/MASTG-KNOW-0008.md) デバッグシンボル (Debugging Symbols)
- [MASTG-KNOW-0009](knowledge/android/MASVS-CODE/MASTG-KNOW-0009.md) StrictMode
- [MASTG-KNOW-0010](knowledge/android/MASVS-CODE/MASTG-KNOW-0010.md) 例外処理 (Exception Handling)

### MASVS-RESILIENCE: リバースエンジニアリングと改竄に対する耐性

- [MASTG-KNOW-0027](knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0027.md) ルート検出 (Root Detection)
- [MASTG-KNOW-0028](knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0028.md) アンチデバッグ (Anti-Debugging)
- [MASTG-KNOW-0029](knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0029.md) ファイル完全性チェック (File Integrity Checks)
- [MASTG-KNOW-0030](knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0030.md) リバースエンジニアリングツールの検出 (Detection of Reverse Engineering Tools)
- [MASTG-KNOW-0031](knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0031.md) エミュレータの検出 (Emulator Detection)
- [MASTG-KNOW-0032](knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0032.md) ランタイム完全性検証 (Runtime Integrity Verification)
- [MASTG-KNOW-0033](knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0033.md) 難読化 (Obfuscation)
- [MASTG-KNOW-0034](knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0034.md) デバイスバインディング (Device Binding)
- [MASTG-KNOW-0035](knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0035.md) Google Play Integrity API

### MASVS-PRIVACY: プライバシー

<!--
- [MASTG-KNOW-0026](knowledge/android/MASVS-PRIVACY/MASTG-KNOW-0026.md) Third-party Services Embedded in the App
-->

## iOS

### MASVS-STORAGE: ストレージ

<!--
- [MASTG-KNOW-0091](knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0091.md) File System APIs
- [MASTG-KNOW-0092](knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0092.md) Binary Data Storage
- [MASTG-KNOW-0093](knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0093.md) UserDefaults
- [MASTG-KNOW-0094](knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0094.md) CoreData
- [MASTG-KNOW-0095](knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0095.md) Firebase Real-time Databases
- [MASTG-KNOW-0096](knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0096.md) Realm Databases
- [MASTG-KNOW-0097](knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0097.md) Other Third-Party Databases
- [MASTG-KNOW-0098](knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0098.md) User Interface Components
- [MASTG-KNOW-0099](knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0099.md) Screenshots
- [MASTG-KNOW-0100](knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0100.md) Keyboard Cache
- [MASTG-KNOW-0101](knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0101.md) Logs
- [MASTG-KNOW-0102](knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0102.md) Backups
- [MASTG-KNOW-0103](knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0103.md) Process Memory
- [MASTG-KNOW-0104](knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0104.md) Inter-Process Communication (IPC) Mechanisms
-->

### MASVS-CRYPTO: 暗号

<!--
- [MASTG-KNOW-0066](knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0066.md) CryptoKit
- [MASTG-KNOW-0067](knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0067.md) CommonCrypto, SecKey and Wrapper libraries
- [MASTG-KNOW-0068](knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0068.md) Cryptographic Third-Party libraries
- [MASTG-KNOW-0069](knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0069.md) Key Management
- [MASTG-KNOW-0070](knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0070.md) Random Number Generator
-->

### MASVS-AUTH: 認証と認可

<!--
- [MASTG-KNOW-0056](knowledge/ios/MASVS-AUTH/MASTG-KNOW-0056.md) Local Authentication Framework
- [MASTG-KNOW-0057](knowledge/ios/MASVS-AUTH/MASTG-KNOW-0057.md) Keychain Services
-->

### MASVS-NETWORK: ネットワーク通信

<!--
- [MASTG-KNOW-0071](knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0071.md) iOS App Transport Security
- [MASTG-KNOW-0072](knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0072.md) Server Trust Evaluation
- [MASTG-KNOW-0073](knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0073.md) iOS Network APIs
-->

### MASVS-PLATFORM: プラットフォーム連携

<!--
- [MASTG-KNOW-0074](knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0074.md) Enforced Updating
- [MASTG-KNOW-0075](knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0075.md) Object Serialization
- [MASTG-KNOW-0076](knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0076.md) WebViews
- [MASTG-KNOW-0077](knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0077.md) App Permissions
- [MASTG-KNOW-0078](knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0078.md) Inter-Process Communication (IPC)
- [MASTG-KNOW-0079](knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0079.md) Custom URL Schemes
- [MASTG-KNOW-0080](knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0080.md) Universal Links
- [MASTG-KNOW-0081](knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0081.md) UIActivity Sharing
- [MASTG-KNOW-0082](knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0082.md) App extensions
- [MASTG-KNOW-0083](knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0083.md) Pasteboard
-->

### MASVS-CODE: コード品質

<!--
- [MASTG-KNOW-0058](knowledge/ios/MASVS-CODE/MASTG-KNOW-0058.md) App Signing
- [MASTG-KNOW-0059](knowledge/ios/MASVS-CODE/MASTG-KNOW-0059.md) Third-Party Libraries
- [MASTG-KNOW-0060](knowledge/ios/MASVS-CODE/MASTG-KNOW-0060.md) Memory Corruption Bugs
- [MASTG-KNOW-0061](knowledge/ios/MASVS-CODE/MASTG-KNOW-0061.md) Binary Protection Mechanisms
- [MASTG-KNOW-0062](knowledge/ios/MASVS-CODE/MASTG-KNOW-0062.md) Debuggable Apps
- [MASTG-KNOW-0063](knowledge/ios/MASVS-CODE/MASTG-KNOW-0063.md) Debugging Symbols
- [MASTG-KNOW-0064](knowledge/ios/MASVS-CODE/MASTG-KNOW-0064.md) Debugging Code and Error Logging
- [MASTG-KNOW-0065](knowledge/ios/MASVS-CODE/MASTG-KNOW-0065.md) Exception Handling
-->

### MASVS-RESILIENCE: リバースエンジニアリングと改竄に対する耐性

<!--
- [MASTG-KNOW-0084](knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0084.md) Jailbreak Detection
- [MASTG-KNOW-0085](knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0085.md) Anti-Debugging Detection
- [MASTG-KNOW-0086](knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0086.md) File Integrity Checks
- [MASTG-KNOW-0087](knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0087.md) Reverse Engineering Tools Detection
- [MASTG-KNOW-0088](knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0088.md) Emulator Detection
- [MASTG-KNOW-0089](knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0089.md) Obfuscation
- [MASTG-KNOW-0090](knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0090.md) Device Binding
-->
