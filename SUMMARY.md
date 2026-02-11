# OWASP Mobile Application Security Testing Guide ja

- [OWASP Mobile Application Security Testing Guide ja](README.md)

## OWASP モバイルアプリケーションセキュリティテストガイド 日本語版

- [序文](Document/0x01-Foreword.md)
- [扉](Document/0x02a-Frontispiece.md)
- [OWASP MASVS と MASTG の採用](Document/0x02b-MASVS-MASTG-Adoption.md)
- [謝辞](Document/0x02c-Acknowledgements.md)
- [OWASP モバイルアプリケーションセキュリティプロジェクトの序文](Document/0x03-Overview.md)
- [MAS テストプロファイル](Document/0x03b-Testing-Profiles.md)
- [さらに学ぶための資料](Document/0x09-Suggested-Reading.md)

### 総合テストガイド

- [モバイルアプリケーションの分類](Document/0x04a-Mobile-App-Taxonomy.md)
- [モバイルアプリケーションのセキュリティテスト](Document/0x04b-Mobile-App-Security-Testing.md)
- [モバイルアプリの認証アーキテクチャ](Document/0x04e-Testing-Authentication-and-Session-Management.md)
- [ネットワーク通信のテスト](Document/0x04f-Testing-Network-Communication.md)
- [モバイルアプリの暗号化](Document/0x04g-Testing-Cryptography.md)
- [コード品質のテスト](Document/0x04h-Testing-Code-Quality.md)
- [改竄とリバースエンジニアリング](Document/0x04c-Tampering-and-Reverse-Engineering.md)
- [ユーザープライバシー保護のテスト](Document/0x04i-Testing-User-Privacy-Protection.md)

### Android テストガイド

- [Android プラットフォーム概要](Document/0x05a-Platform-Overview.md)
- [Android セキュリティテスト入門](Document/0x05b-Android-Security-Testing.md)
- [Android のデータストレージ](Document/0x05d-Testing-Data-Storage.md)
- [Android の暗号化 API](Document/0x05e-Testing-Cryptography.md)
- [Android のローカル認証](Document/0x05f-Testing-Local-Authentication.md)
- [Android のネットワーク通信](Document/0x05g-Testing-Network-Communication.md)
- [Android のプラットフォーム API](Document/0x05h-Testing-Platform-Interaction.md)
- [Android アプリのコード品質とビルド設定](Document/0x05i-Testing-Code-Quality-and-Build-Settings.md)
- [Android のアンチリバース防御](Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md)

### iOS テストガイド

- [iOS プラットフォーム概要](Document/0x06a-Platform-Overview.md)
- [iOS セキュリティテスト入門](Document/0x06b-iOS-Security-Testing.md)
- [iOS のデータストレージ](Document/0x06d-Testing-Data-Storage.md)
- [iOS の暗号化 API](Document/0x06e-Testing-Cryptography.md)
- [iOS のローカル認証](Document/0x06f-Testing-Local-Authentication.md)
- [iOS のネットワーク通信](Document/0x06g-Testing-Network-Communication.md)
- [iOS のプラットフォーム API](Document/0x06h-Testing-Platform-Interaction.md)
- [iOS アプリのコード品質とビルド設定](Document/0x06i-Testing-Code-Quality-and-Build-Settings.md)
- [iOS のアンチリバース防御](Document/0x06j-Testing-Resiliency-Against-Reverse-Engineering.md)

### ベストプラクティス

- [ベストプラクティス一覧](best-practices.md)
  - [MASTG-BEST-0001 安全な乱数生成 API を使用する (Use Secure Random Number Generator APIs)](best-practices/MASTG-BEST-0001.md)
  - [MASTG-BEST-0002 ログ記録コードを削除する (Remove Logging Code)](best-practices/MASTG-BEST-0002.md)
  - [MASTG-BEST-0003 プライバシー規制とベストプラクティスを遵守する (Comply with Privacy Regulations and Best Practices)](best-practices/MASTG-BEST-0003.md)
  - [MASTG-BEST-0004 バックアップから機密データを除外する (Exclude Sensitive Data from Backups)](best-practices/MASTG-BEST-0004.md)
  - [MASTG-BEST-0005 安全な暗号モードを使用する (Use Secure Encryption Modes)](best-practices/MASTG-BEST-0005.md)
  - [MASTG-BEST-0006 最新の APK 署名スキームを使用する (Use Up-to-Date APK Signing Schemes)](best-practices/MASTG-BEST-0006.md)
  - [MASTG-BEST-0007 AndroidManifest のデバッグフラグを無効にする (Debuggable Flag Disabled in the AndroidManifest)](best-practices/MASTG-BEST-0007.md)
  - [MASTG-BEST-0008 WebView のデバッグを無効にする (Debugging Disabled for WebViews)](best-practices/MASTG-BEST-0008.md)
  - [MASTG-BEST-0009 安全な暗号アルゴリズムを使用する (Use Secure Encryption Algorithms)](best-practices/MASTG-BEST-0009.md)
  - [MASTG-BEST-0010 最新の minSdkVersion を使用する (Use Up-to-Date minSdkVersion)](best-practices/MASTG-BEST-0010.md)
  - [MASTG-BEST-0011 WebView でファイルコンテンツを安全にロードする (Securely Load File Content in a WebView)](best-practices/MASTG-BEST-0011.md)
  - [MASTG-BEST-0012 WebView で JavaScript を無効にする (Disable JavaScript in WebViews)](best-practices/MASTG-BEST-0012.md)
  - [MASTG-BEST-0013 WebView でコンテンツプロバイダアクセスを無効にする (Disable Content Provider Access in WebViews)](best-practices/MASTG-BEST-0013.md)
  - [MASTG-BEST-0014 スクリーンショットと画面録画を防止する (Preventing Screenshots and Screen Recording)](best-practices/MASTG-BEST-0014.md)
  - [MASTG-BEST-0015 バックグラウンド時にスクリーンショットを防ぐために `setRecentsScreenshotEnabled` を使用する (Use `setRecentsScreenshotEnabled` to Prevent Screenshots When Backgrounded)](best-practices/MASTG-BEST-0015.md)
  - [MASTG-BEST-0016 スクリーンショットやスクリーン録画を防ぐために `SECURE_FLAG` を使用する (Use `SECURE_FLAG` to Prevent Screenshots and Screen Recording)](best-practices/MASTG-BEST-0016.md)
  - [MASTG-BEST-0017 SurfaceView でのスクリーンショットを防ぐために `setSecure` を使用する (Use `setSecure` to Prevent Screenshots in SurfaceViews)](best-practices/MASTG-BEST-0017.md)
  - [MASTG-BEST-0018 Compose コンポーネントでのスクリーンショットを防ぐために `SecureFlagPolicy.SecureOn` を使用する (Use `SecureFlagPolicy.SecureOn` to Prevent Screenshots in Compose Components)](best-practices/MASTG-BEST-0018.md)
  - [MASTG-BEST-0019 機密性の高いフィールドに対して非キャッシュ入力タイプを使用する (Use Non-Caching Input Types for Sensitive Fields)](best-practices/MASTG-BEST-0019.md)
  - [MASTG-BEST-0020 GMS セキュリティプロバイダを更新する (Update the GMS Security Provider)](best-practices/MASTG-BEST-0020.md)
  - [MASTG-BEST-0021 適切なエラーおよび例外処理を確保する (Ensure Proper Error and Exception Handling)](best-practices/MASTG-BEST-0021.md)
  - [MASTG-BEST-0022 プロダクションビルドで詳細ログ記録とデバッグログ記録を無効にする (Disable Verbose and Debug Logging in Production Builds)](best-practices/MASTG-BEST-0022.md)
  - [MASTG-BEST-0023 バックアップから機密情報を除外する (Exclude Sensitive Information from Backups)](best-practices/MASTG-BEST-0023.md)
  - [MASTG-BEST-0024 アプリサンドボックスディレクトリに暗号化したデータを保存する (Store Data Encrypted in App Sandbox Directory)](best-practices/MASTG-BEST-0024.md)
  - [MASTG-BEST-0025 安全な乱数生成器 API を使用する (Use Secure Random Number Generator APIs)](best-practices/MASTG-BEST-0025.md)
  - [MASTG-BEST-0026 機密テキスト入力のキーボードキャッシュを防止する (Preventing Keyboard Caching for Sensitive Text Inputs)](best-practices/MASTG-BEST-0026.md)
  - [MASTG-BEST-0027 通知での機密データの露出を防止する (Preventing Sensitive Data Exposure in Notifications)](best-practices/MASTG-BEST-0027.md)
  - [MASTG-BEST-0028 WebView キャッシュをクリーンアップする (WebViews Cache Cleanup)](best-practices/MASTG-BEST-0028.md)
  - [MASTG-BEST-0029 耐性と RASP シグナルを実装する (Implementing Resilience and RASP Signals)](best-practices/MASTG-BEST-0029.md)
  - [MASTG-BEST-0030 ルート検出を実装する (Implementing Root Detection)](best-practices/MASTG-BEST-0030.md)

### ナレッジ

- [ナレッジ一覧](knowledge.md)
  - Android
    - MASVS-STORAGE: ストレージ
      - [MASTG-KNOW-0037 SQLite データベース (SQLite Database)](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0037.md)
      - [MASTG-KNOW-0038 SQLCipher データベース (SQLCipher Database)](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0038.md)
      - [MASTG-KNOW-0039 Firebase リアルタイムデータベース (Firebase Real-time Databases)](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0039.md)
      - [MASTG-KNOW-0041 内部ストレージ (Internal Storage)](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0041.md)
      - [MASTG-KNOW-0045 キーストアへの安全な鍵のインポート (Secure Key Import into Keystore)](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0045.md)
      - [MASTG-KNOW-0046 BouncyCastle キーストア (BouncyCastle KeyStore)](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0046.md)
      - [MASTG-KNOW-0048 キーチェーン (KeyChain)](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0048.md)
      - [MASTG-KNOW-0049 ログ (Logs)](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0049.md)
      - [MASTG-KNOW-0050 バックアップ (Backups)](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0050.md)
      - [MASTG-KNOW-0052 ユーザーインタフェースコンポーネント (User Interface Components)](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0052.md)
      - [MASTG-KNOW-0053 スクリーンショット (Screenshots)](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0053.md)
      - [MASTG-KNOW-0054 アプリ通知 (App Notifications)](knowledge/android/MASVS-STORAGE/MASTG-KNOW-0054.md)

    - MASVS-CRYPTO: 暗号
      - [MASTG-KNOW-0011 セキュリティプロバイダ (Security Provider)](knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0011.md)
      - [MASTG-KNOW-0012 鍵生成 (Key Generation)](knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012.md)
      - [MASTG-KNOW-0013 乱数生成 (Random Number Generation)](knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0013.md)

    - MASVS-AUTH: 認証と認可
      - [MASTG-KNOW-0001 生体認証 (Biometric Authentication)](knowledge/android/MASVS-AUTH/MASTG-KNOW-0001.md)
      - [MASTG-KNOW-0002 FingerprintManager](knowledge/android/MASVS-AUTH/MASTG-KNOW-0002.md)

    - MASVS-NETWORK: ネットワーク通信
      - [MASTG-KNOW-0014 Android Network Security Configuration](knowledge/android/MASVS-NETWORK/MASTG-KNOW-0014.md)
      - [MASTG-KNOW-0015 証明書ピン留め (Certificate Pinning)](knowledge/android/MASVS-NETWORK/MASTG-KNOW-0015.md)
      - [MASTG-KNOW-0016 TBD](knowledge/android/MASVS-NETWORK/MASTG-KNOW-0016.md)

    - MASVS-PLATFORM: プラットフォーム連携
      - [MASTG-KNOW-0019 ディープリンク (Deep Links)](knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0019.md)
      - [MASTG-KNOW-0020 プロセス間通信 (IPC) メカニズム (Inter-Process Communication (IPC) Mechanisms)](knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0020.md)
      - [MASTG-KNOW-0022 オーバーレイ攻撃 (Overlay Attacks)](knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0022.md)
      - [MASTG-KNOW-0023 強制アップデート (Enforced Updating)](knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0023.md)
      - [MASTG-KNOW-0025 暗黙的インテント (Implicit Intents)](knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0025.md)
      - [MASTG-KNOW-0105 ユーザーによるスクリーンショットとスクリーン録画 (User-Initiated Screenshots and Screen Recording)](knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0105.md)
      - [MASTG-KNOW-0106 アプリによるスクリーンショットとスクリーン録画 (App-Initiated Screenshots and Screen Recording)](knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0106.md)
      - [MASTG-KNOW-0107 スクリーンショットとスクリーン録画の検出 (Screenshots and Screen Recording Detection)](knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0107.md)

    - MASVS-CODE: コード品質
      - [MASTG-KNOW-0004 サードパーティーライブラリ (Third-Party Libraries)](knowledge/android/MASVS-CODE/MASTG-KNOW-0004.md)
      - [MASTG-KNOW-0005 メモリ破損バグ (Memory Corruption Bugs)](knowledge/android/MASVS-CODE/MASTG-KNOW-0005.md)
      - [MASTG-KNOW-0006 バイナリ保護メカニズム (Binary Protection Mechanisms)](knowledge/android/MASVS-CODE/MASTG-KNOW-0006.md)
      - [MASTG-KNOW-0008 デバッグ情報とデバッグシンボル (Debugging Information and Debug Symbols)](knowledge/android/MASVS-CODE/MASTG-KNOW-0008.md)
      - [MASTG-KNOW-0009 StrictMode](knowledge/android/MASVS-CODE/MASTG-KNOW-0009.md)
      - [MASTG-KNOW-0010 例外処理 (Exception Handling)](knowledge/android/MASVS-CODE/MASTG-KNOW-0010.md)

    - MASVS-RESILIENCE: リバースエンジニアリングと改竄に対する耐性
      - [MASTG-KNOW-0003 アプリ署名 (App Signing)](knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0003.md)
      - [MASTG-KNOW-0007 デバッグ可能アプリ (Debuggable Apps)](knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0007.md)
      - [MASTG-KNOW-0027 ルート検出 (Root Detection)](knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0027.md)
      - [MASTG-KNOW-0028 アンチデバッグ (Anti-Debugging)](knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0028.md)
      - [MASTG-KNOW-0029 ファイル完全性チェック (File Integrity Checks)](knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0029.md)
      - [MASTG-KNOW-0030 リバースエンジニアリングツールの検出 (Detection of Reverse Engineering Tools)](knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0030.md)
      - [MASTG-KNOW-0031 エミュレータの検出 (Emulator Detection)](knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0031.md)
      - [MASTG-KNOW-0032 ランタイム完全性検証 (Runtime Integrity Verification)](knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0032.md)
      - [MASTG-KNOW-0033 難読化 (Obfuscation)](knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0033.md)
      - [MASTG-KNOW-0034 デバイスバインディング (Device Binding)](knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0034.md)
      - [MASTG-KNOW-0035 Google Play Integrity API](knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0035.md)

    - MASVS-PRIVACY: プライバシー
      - [MASTG-KNOW-0026 アプリに組み込まれたサードパーティサービス (Third-party Services Embedded in the App)](knowledge/android/MASVS-PRIVACY/MASTG-KNOW-0026.md)

  - iOS
    - MASVS-STORAGE: ストレージ
      - [MASTG-KNOW-0091 ファイルシステム API (File System APIs)](knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0091.md)
      - [MASTG-KNOW-0092 バイナリデータストレージ (Binary Data Storage)](knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0092.md)
      - [MASTG-KNOW-0093 UserDefaults](knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0093.md)
      - [MASTG-KNOW-0094 CoreData](knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0094.md)
      - [MASTG-KNOW-0095 Firebase リアルタイムデータベース (Firebase Real-time Databases)](knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0095.md)
      - [MASTG-KNOW-0096 Realm データベース (Realm Databases)](knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0096.md)
      - [MASTG-KNOW-0097 その他のサードパーティデータベース (Other Third-Party Databases)](knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0097.md)
      - [MASTG-KNOW-0098 ユーザーインタフェースコンポーネント (User Interface Components)](knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0098.md)
      - [MASTG-KNOW-0099 スクリーンショット (Screenshots)](knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0099.md)
      - [MASTG-KNOW-0100 キーボードキャッシュ (Keyboard Cache)](knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0100.md)
      - [MASTG-KNOW-0101 ログ (Logs)](knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0101.md)
      - [MASTG-KNOW-0102 バックアップ (Backups)](knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0102.md)
      - [MASTG-KNOW-0104 プロセス間通信 (IPC) メカニズム (Inter-Process Communication (IPC) Mechanisms)](knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0104.md)

    - MASVS-CRYPTO: 暗号
      - [MASTG-KNOW-0066 CryptoKit](knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0066.md)
      - [MASTG-KNOW-0067 CommonCrypto, SecKey および Wrapper ライブラリ (CommonCrypto, SecKey and Wrapper libraries)](knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0067.md)
      - [MASTG-KNOW-0068 暗号サードパーティーライブラリ (Cryptographic Third-Party libraries)](knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0068.md)
      - [MASTG-KNOW-0069 鍵管理 (Key Management)](knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0069.md)
      - [MASTG-KNOW-0070 乱数生成 (Random Number Generator)](knowledge/ios/MASVS-CRYPTO/MASTG-KNOW-0070.md)

    - MASVS-AUTH: 認証と認可
      - [MASTG-KNOW-0056 ローカル認証フレームワーク (Local Authentication Framework)](knowledge/ios/MASVS-AUTH/MASTG-KNOW-0056.md)
      - [MASTG-KNOW-0057 キーチェーンサービス (Keychain Services)](knowledge/ios/MASVS-AUTH/MASTG-KNOW-0057.md)

    - MASVS-NETWORK: ネットワーク通信
      - [MASTG-KNOW-0071 iOS App Transport Security](knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0071.md)
      - [MASTG-KNOW-0072 サーバー信頼性評価 (Server Trust Evaluation)](knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0072.md)
      - [MASTG-KNOW-0073 iOS ネットワーク API (iOS Network APIs)](knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0073.md)

    - MASVS-PLATFORM: プラットフォーム連携
      - [MASTG-KNOW-0074 強制アップデート (Enforced Updating)](knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0074.md)
      - [MASTG-KNOW-0078 プロセス間通信 (IPC) (Inter-Process Communication (IPC))](knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0078.md)
      - [MASTG-KNOW-0080 ユニバーサルリンク (Universal Links)](knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0080.md)
      - [MASTG-KNOW-0081 UIActivity 共有 (UIActivity Sharing)](knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0081.md)

    - MASVS-CODE: コード品質
      - [MASTG-KNOW-0058 アプリ署名 (App Signing)](knowledge/ios/MASVS-CODE/MASTG-KNOW-0058.md)
      - [MASTG-KNOW-0059 サードパーティライブラリ (Third-Party Libraries)](knowledge/ios/MASVS-CODE/MASTG-KNOW-0059.md)
      - [MASTG-KNOW-0060 メモリ破損バグ (Memory Corruption Bugs)](knowledge/ios/MASVS-CODE/MASTG-KNOW-0060.md)
      - [MASTG-KNOW-0061 バイナリ保護メカニズム (Binary Protection Mechanisms)](knowledge/ios/MASVS-CODE/MASTG-KNOW-0061.md)
      - [MASTG-KNOW-0062 デバッグ可能アプリ (Debuggable Apps)](knowledge/ios/MASVS-CODE/MASTG-KNOW-0062.md)
      - [MASTG-KNOW-0063 デバッグ情報とデバッグシンボル (Debugging Information and Debug Symbols)](knowledge/ios/MASVS-CODE/MASTG-KNOW-0063.md)
      - [MASTG-KNOW-0064 デバッグコードとエラーログ (Debugging Code and Error Logging)](knowledge/ios/MASVS-CODE/MASTG-KNOW-0064.md)
      - [MASTG-KNOW-0065 例外処理 (Exception Handling)](knowledge/ios/MASVS-CODE/MASTG-KNOW-0065.md)

    - MASVS-RESILIENCE: リバースエンジニアリングと改竄に対する耐性
      - [MASTG-KNOW-0084](knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0084.md) 脱獄検出 (Jailbreak Detection)
      - [MASTG-KNOW-0085](knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0085.md) アンチデバッグ検出 (Anti-Debugging Detection)
      - [MASTG-KNOW-0086](knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0086.md) ファイル完全性チェック (File Integrity Checks)
      - [MASTG-KNOW-0087](knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0087.md) リバースエンジニアリングツール検出 (Reverse Engineering Tools Detection)
      - [MASTG-KNOW-0088](knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0088.md) エミュレータ検出 (Emulator Detection)
      - [MASTG-KNOW-0089](knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0089.md) 難読化 (Obfuscation)
      - [MASTG-KNOW-0090](knowledge/ios/MASVS-RESILIENCE/MASTG-KNOW-0090.md) デバイスバインディング (Device Binding)

### テスト

- [テスト一覧](tests.md)
  - Android
    - MASVS-STORAGE: ストレージ

    - MASVS-CRYPTO: 暗号
      - [MASTG-TEST-0013 対称暗号のテスト (Testing Symmetric Cryptography)](tests/android/MASVS-CRYPTO/MASTG-TEST-0013.md)
      - [MASTG-TEST-0014 暗号標準アルゴリズムの設定のテスト (Testing the Configuration of Cryptographic Standard Algorithms)](tests/android/MASVS-CRYPTO/MASTG-TEST-0014.md)
      - [MASTG-TEST-0015 鍵の目的のテスト (Testing the Purposes of Keys)](tests/android/MASVS-CRYPTO/MASTG-TEST-0015.md)
      - [MASTG-TEST-0016 乱数生成のテスト (Testing Random Number Generation)](tests/android/MASVS-CRYPTO/MASTG-TEST-0016.md)

    - MASVS-AUTH: 認証と認可
      - [MASTG-TEST-0017 認証情報確認のテスト (Testing Confirm Credentials)](tests/android/MASVS-AUTH/MASTG-TEST-0017.md)
      - [MASTG-TEST-0018 生体認証のテスト (Testing Biometric Authentication)](tests/android/MASVS-AUTH/MASTG-TEST-0018.md)

    - MASVS-NETWORK: ネットワーク通信
      - [MASTG-TEST-0019 ネットワーク上のデータ暗号化のテスト (Testing Data Encryption on the Network)](tests/android/MASVS-NETWORK/MASTG-TEST-0019.md)
      - [MASTG-TEST-0020 TLS 設定のテスト (Testing the TLS Settings)](tests/android/MASVS-NETWORK/MASTG-TEST-0020.md)
      - [MASTG-TEST-0021 エンドポイント同一性検証のテスト (Testing Endpoint Identify Verification)](tests/android/MASVS-NETWORK/MASTG-TEST-0021.md)
      - [MASTG-TEST-0022 カスタム証明書ストアおよび証明書ピン留めのテスト (Testing Custom Certificate Stores and Certificate Pinning)](tests/android/MASVS-NETWORK/MASTG-TEST-0022.md)
      - [MASTG-TEST-0023 セキュリティプロバイダのテスト (Testing the Security Provider)](tests/android/MASVS-NETWORK/MASTG-TEST-0023.md)

    - MASVS-PLATFORM: プラットフォーム連携

    - MASVS-CODE: コード品質
      - [MASTG-TEST-0002 ローカルストレージの入力バリデーションのテスト (Testing Local Storage for Input Validation)](tests/android/MASVS-CODE/MASTG-TEST-0002.md)
      - [MASTG-TEST-0025 インジェクション欠陥のテスト (Testing for Injection Flaws)](tests/android/MASVS-CODE/MASTG-TEST-0025.md)
      - [MASTG-TEST-0026 暗黙的インテントのテスト (Testing Implicit Intents)](tests/android/MASVS-CODE/MASTG-TEST-0026.md)
      - [MASTG-TEST-0027 WebView での URL ローディングのテスト (Testing for URL Loading in WebViews)](tests/android/MASVS-CODE/MASTG-TEST-0027.md)
      - [MASTG-TEST-0034 オブジェクト永続化のテスト (Testing Object Persistence)](tests/android/MASVS-CODE/MASTG-TEST-0034.md)
      - [MASTG-TEST-0036 強制更新のテスト (Testing Enforced Updating)](tests/android/MASVS-CODE/MASTG-TEST-0036.md)
      - [MASTG-TEST-0042 サードパーティーライブラリの脆弱性の確認 (Checking for Weaknesses in Third Party Libraries)](tests/android/MASVS-CODE/MASTG-TEST-0042.md)
      - [MASTG-TEST-0043 メモリ破損バグ (Memory Corruption Bugs)](tests/android/MASVS-CODE/MASTG-TEST-0043.md)
      - [MASTG-TEST-0044 フリーのセキュリティ機能が有効であることの確認 (Make Sure That Free Security Features Are Activated)](tests/android/MASVS-CODE/MASTG-TEST-0044.md)

    - MASVS-RESILIENCE: リバースエンジニアリングと改竄に対する耐性
      - [MASTG-TEST-0038 アプリが正しく署名されていることの確認 (Making Sure that the App is Properly Signed)](tests/android/MASVS-RESILIENCE/MASTG-TEST-0038.md)
      - [MASTG-TEST-0039 アプリがデバッグ可能であるかのテスト (Testing whether the App is Debuggable)](tests/android/MASVS-RESILIENCE/MASTG-TEST-0039.md)
      - [MASTG-TEST-0040 デバッグシンボルに関するテスト (Testing for Debugging Symbols)](tests/android/MASVS-RESILIENCE/MASTG-TEST-0040.md)
      - [MASTG-TEST-0041 デバッグコードと詳細エラーログに関するテスト (Testing for Debugging Code and Verbose Error Logging)](tests/android/MASVS-RESILIENCE/MASTG-TEST-0041.md)
      - [MASTG-TEST-0045 ルート検出のテスト (Testing Root Detection)](tests/android/MASVS-RESILIENCE/MASTG-TEST-0045.md)
      - [MASTG-TEST-0046 アンチデバッグ検出のテスト (Testing Anti-Debugging Detection)](tests/android/MASVS-RESILIENCE/MASTG-TEST-0046.md)
      - [MASTG-TEST-0047 ファイル完全性チェックのテスト (Testing File Integrity Checks)](tests/android/MASVS-RESILIENCE/MASTG-TEST-0047.md)
      - [MASTG-TEST-0048 リバースエンジニアリングツール検出のテスト (Testing Reverse Engineering Tools Detection)](tests/android/MASVS-RESILIENCE/MASTG-TEST-0048.md)
      - [MASTG-TEST-0049 エミュレータ検出のテスト (Testing Emulator Detection)](tests/android/MASVS-RESILIENCE/MASTG-TEST-0049.md)
      - [MASTG-TEST-0050 ランタイム完全性チェックのテスト (Testing Runtime Integrity Checks)](tests/android/MASVS-RESILIENCE/MASTG-TEST-0050.md)
      - [MASTG-TEST-0051 難読化のテスト (Testing Obfuscation)](tests/android/MASVS-RESILIENCE/MASTG-TEST-0051.md)

  - iOS
    - MASVS-STORAGE: ストレージ

    - MASVS-CRYPTO: 暗号
      - [MASTG-TEST-0061 暗号標準アルゴリズムの構成の検証 (Verifying the Configuration of Cryptographic Standard Algorithms)](tests/ios/MASVS-CRYPTO/MASTG-TEST-0061.md)
      - [MASTG-TEST-0062 鍵管理のテスト (Testing Key Management)](tests/ios/MASVS-CRYPTO/MASTG-TEST-0062.md)
      - [MASTG-TEST-0063 乱数生成のテスト (Testing Random Number Generation)](tests/ios/MASVS-CRYPTO/MASTG-TEST-0063.md)

    - MASVS-AUTH: 認証と認可
      - [MASTG-TEST-0064 生体認証のテスト (Testing Biometric Authentication)](tests/ios/MASVS-AUTH/MASTG-TEST-0064.md)

    - MASVS-NETWORK: ネットワーク通信
      - [MASTG-TEST-0065 ネットワーク上のデータ暗号化のテスト (Testing Data Encryption on the Network)](tests/ios/MASVS-NETWORK/MASTG-TEST-0065.md)
      - [MASTG-TEST-0066 TLS 設定のテスト (Testing the TLS Settings)](tests/ios/MASVS-NETWORK/MASTG-TEST-0066.md)
      - [MASTG-TEST-0067 エンドポイント同一性検証のテスト (Testing Endpoint Identity Verification)](tests/ios/MASVS-NETWORK/MASTG-TEST-0067.md)
      - [MASTG-TEST-0068 カスタム証明書ストアおよび証明書ピン留めのテスト (Testing Custom Certificate Stores and Certificate Pinning)](tests/ios/MASVS-NETWORK/MASTG-TEST-0068.md)

    - MASVS-PLATFORM: プラットフォーム連携
      - [MASTG-TEST-0073 UIPasteboard のテスト (Testing UIPasteboard)](tests/ios/MASVS-PLATFORM/MASTG-TEST-0073.md)

    - MASVS-CODE: コード品質
      - [MASTG-TEST-0079 オブジェクト永続化のテスト (Testing Object Persistence)](tests/ios/MASVS-CODE/MASTG-TEST-0079.md)
      - [MASTG-TEST-0080 強制更新のテスト (Testing Enforced Updating)](tests/ios/MASVS-CODE/MASTG-TEST-0080.md)
      - [MASTG-TEST-0085 サードパーティライブラリの脆弱性のチェック (Checking for Weaknesses in Third Party Libraries)](tests/ios/MASVS-CODE/MASTG-TEST-0085.md)
      - [MASTG-TEST-0086 メモリ破損バグ (Memory Corruption Bugs)](tests/ios/MASVS-CODE/MASTG-TEST-0086.md)
      - [MASTG-TEST-0087 フリーなセキュリティ機能が有効であることの確認 (Make Sure That Free Security Features Are Activated)](tests/ios/MASVS-CODE/MASTG-TEST-0087.md)

    - MASVS-RESILIENCE: リバースエンジニアリングと改竄に対する耐性
      - [MASTG-TEST-0081 アプリが正しく署名されていることの確認 (Making Sure that the App Is Properly Signed)](tests/ios/MASVS-RESILIENCE/MASTG-TEST-0081.md)
      - [MASTG-TEST-0082 アプリがデバッグ可能かどうかのテスト (Testing whether the App is Debuggable)](tests/ios/MASVS-RESILIENCE/MASTG-TEST-0082.md)
      - [MASTG-TEST-0083 デバッグシンボルのテスト (Testing for Debugging Symbols)](tests/ios/MASVS-RESILIENCE/MASTG-TEST-0083.md)
      - [MASTG-TEST-0084 デバッグコードと詳細エラーログのテスト (Testing for Debugging Code and Verbose Error Logging)](tests/ios/MASVS-RESILIENCE/MASTG-TEST-0084.md)
      - [MASTG-TEST-0088 脱獄検出のテスト (Testing Jailbreak Detection)](tests/ios/MASVS-RESILIENCE/MASTG-TEST-0088.md)
      - [MASTG-TEST-0089 アンチデバッグ検出のテスト (Testing Anti-Debugging Detection)](tests/ios/MASVS-RESILIENCE/MASTG-TEST-0089.md)
      - [MASTG-TEST-0090 ファイル完全性チェックのテスト (Testing File Integrity Checks)](tests/ios/MASVS-RESILIENCE/MASTG-TEST-0090.md)
      - [MASTG-TEST-0091 リバースエンジニアリングツール検出のテスト (Testing Reverse Engineering Tools Detection)](tests/ios/MASVS-RESILIENCE/MASTG-TEST-0091.md)
      - [MASTG-TEST-0092 エミュレータ検出のテスト (Testing Emulator Detection)](tests/ios/MASVS-RESILIENCE/MASTG-TEST-0092.md)
      - [MASTG-TEST-0093 難読化のテスト (Testing Obfuscation)](tests/ios/MASVS-RESILIENCE/MASTG-TEST-0093.md)

- [テスト一覧 (beta)](tests-beta.md)
  - Android
    - MASVS-STORAGE: ストレージ
      - [MASTG-TEST-0200 外部ストレージに書き込まれたファイル (Files Written to External Storage)](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0200.md)
      - [MASTG-TEST-0201 外部ストレージにアクセスするための API の実行時使用 (Runtime Use of APIs to Access External Storage)](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0201.md)
      - [MASTG-TEST-0202 外部ストレージにアクセスするための API とパーミッションへの参照 (References to APIs and Permissions for Accessing External Storage)](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0202.md)
      - [MASTG-TEST-0203 ログ記録 API の実行時使用 (Runtime Use of Logging APIs)](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0203.md)
      - [MASTG-TEST-0207 アプリのサンドボックスでの暗号化していないデータの実行時保存 (Runtime Storage of Unencrypted Data in the App Sandbox)](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0207.md)
      - [MASTG-TEST-0216 バックアップから除外されない機密データ (Sensitive Data Not Excluded From Backup)](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0216.md)
      - [MASTG-TEST-0231 ログ記録 API への参照 (References to Logging APIs)](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0231.md)
      - [MASTG-TEST-0262 機密データを除外しないバックアップ構成への参照 (References to Backup Configurations Not Excluding Sensitive Data)](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0262.md)
      - [MASTG-TEST-0287 SharedPreferences API を介してアプリサンドボックスに暗号化されずに保存される機密データ (Sensitive Data Stored Unencrypted via the SharedPreferences API to the App Sandbox)](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0287.md)
      - [MASTG-TEST-0304 SQLite 経由で暗号化されずに保存される機密データ (Sensitive Data Stored Unencrypted via SQLite)](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0304.md)
      - [MASTG-TEST-0305 DataStore 経由で暗号化されずに保存される機密データ (Sensitive Data Stored Unencrypted via DataStore)](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0305.md)
      - [MASTG-TEST-0306 Android Room DB 経由で暗号化されずに保存される機密データ (Sensitive Data Stored Unencrypted via Android Room DB)](tests-beta/android/MASVS-STORAGE/MASTG-TEST-0306.md)

    - MASVS-CRYPTO: 暗号
      - [MASTG-TEST-0204 安全でないランダム API の使用 (Insecure Random API Usage)](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0204.md)
      - [MASTG-TEST-0205 ランダムでないソースの使用 (Non-random Sources Usage)](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0205.md)
      - [MASTG-TEST-0208 不十分な鍵サイズ (Insufficient Key Sizes)](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0208.md)
      - [MASTG-TEST-0212 コード内にハードコードされた暗号鍵の使用 (Use of Hardcoded Cryptographic Keys in Code)](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0212.md)
      - [MASTG-TEST-0221 不備のある対称暗号アルゴリズム (Broken Symmetric Encryption Algorithms)](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0221.md)
      - [MASTG-TEST-0232 不備のある対称暗号モード (Broken Symmetric Encryption Modes)](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0232.md)
      - [MASTG-TEST-0307 複数の目的で使用される非対称鍵ペアへの参照 (References to Asymmetric Key Pairs Used For Multiple Purposes)](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0307.md)
      - [MASTG-TEST-0308 複数の目的で使用される非対称鍵ペアの実行時使用 (Runtime Use of Asymmetric Key Pairs Used For Multiple Purposes)](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0308.md)
      - [MASTG-TEST-0309 対称暗号化での再使用される初期化ベクトルへの参照 (References to Reused Initialization Vectors in Symmetric Encryption)](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0309.md)
      - [MASTG-TEST-0310 対称暗号化での再使用される初期化ベクトルの実行時使用 (Runtime Use of Reused Initialization Vectors in Symmetric Encryption)](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0310.md)
      - [MASTG-TEST-0312 暗号 API での明示的なセキュリティプロバイダへの参照 (References to Explicit Security Provider in Cryptographic APIs)](tests-beta/android/MASVS-CRYPTO/MASTG-TEST-0312.md)

    - MASVS-NETWORK: ネットワーク通信
      - [MASTG-TEST-0217 コード内で明示的に許可された安全でない TLS プロトコル (Insecure TLS Protocols Explicitly Allowed in Code)](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0217.md)
      - [MASTG-TEST-0218 ネットワークトラフィックにおける安全でない TLS プロトコル (Insecure TLS Protocols in Network Traffic)](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0218.md)
      - [MASTG-TEST-0233 ハードコードされた HTTP URL  (Hardcoded HTTP URLs)](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0233.md)
      - [MASTG-TEST-0234 SSLSocket でのサーバーホスト名検証の実装の欠如 (Missing Implementation of Server Hostname Verification with SSLSockets)](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0234.md)
      - [MASTG-TEST-0235 クリアテキストトラフィックを許可する Android アプリ構成 (Android App Configurations Allowing Cleartext Traffic)](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0235.md)
      - [MASTG-TEST-0236 ネットワーク上で観測されるクリアテキストトラフィック (Cleartext Traffic Observed on the Network)](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0236.md)
      - [MASTG-TEST-0237 クリアテキストトラフィックを許可するクロスプラットフォーム構成 (Cross-Platform Framework Configurations Allowing Cleartext Traffic)](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0237.md)
      - [MASTG-TEST-0238 クリアテキストトラフィックを転送するネットワーク API の実行時使用 (Runtime Use of Network APIs Transmitting Cleartext Traffic)](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0238.md)
      - [MASTG-TEST-0239 カスタム HTTP 接続をセットアップする低レベル API (Socket など) の使用 (Using low-level APIs (e.g. Socket) to set up a custom HTTP connection)](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0239.md)
      - [MASTG-TEST-0242 Network Security Configuration での証明書ピン留めの欠如 (Missing Certificate Pinning in Network Security Configuration)](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0242.md)
      - [MASTG-TEST-0243 Network Security Configuration での証明書ピン留めの期限切れ (Expired Certificate Pins in the Network Security Configuration)](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0243.md)
      - [MASTG-TEST-0244 ネットワークトラフィックでの証明書ピン留めの欠如 (Missing Certificate Pinning in Network Traffic)](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0244.md)
      - [MASTG-TEST-0282 安全でないカスタムトラスト評価 (Unsafe Custom Trust Evaluation)](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0282.md)
      - [MASTG-TEST-0283 サーバーホスト名検証の正しくない実装 (Incorrect Implementation of Server Hostname Verification)](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0283.md)
      - [MASTG-TEST-0284 WebView での正しくない SSL エラー処理 (Incorrect SSL Error Handling in WebViews)](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0284.md)
      - [MASTG-TEST-0285 ユーザー提供の CA を信頼する古い Android バージョン (Outdated Android Version Allowing Trust in User-Provided CAs)](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0285.md)
      - [MASTG-TEST-0286 ユーザー提供の CA を信頼する Network Security Configuration (Network Security Configuration Allowing Trust in User-Provided CAs)](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0286.md)
      - [MASTG-TEST-0295 更新されていない GMS セキュリティプロバイダ (GMS Security Provider Not Updated)](tests-beta/android/MASVS-NETWORK/MASTG-TEST-0295.md)

    - MASVS-PLATFORM: プラットフォーム連携
      - [MASTG-TEST-0250 WebView におけるコンテンツプロバイダアクセスへの参照 (References to Content Provider Access in WebViews)](tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0250.md)
      - [MASTG-TEST-0251 WebView におけるコンテンツプロバイダアクセス API の実行時使用 (Runtime Use of Content Provider Access APIs in WebViews)](tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0251.md)
      - [MASTG-TEST-0252 WebView におけるローカルファイルアクセスへの参照 (References to Local File Access in WebViews)](tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0252.md)
      - [MASTG-TEST-0253 WebView におけるローカルファイルアクセス API の実行時使用 (Runtime Use of Local File Access APIs in WebViews)](tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0253.md)
      - [MASTG-TEST-0258 UI 要素のキーボードキャッシュ属性への参照 (References to Keyboard Caching Attributes in UI Elements)](tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0258.md)
      - [MASTG-TEST-0289 アプリのバックグラウンド時のスクリーンショットでの機密コンテンツ露出の実行時検証 (Runtime Verification of Sensitive Content Exposure in Screenshots During App Backgrounding)](tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0289.md)
      - [MASTG-TEST-0291 スクリーンキャプチャ防止 API への参照 (References to Screen Capturing Prevention APIs)](tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0291.md)
      - [MASTG-TEST-0292 バックグラウンド時にスクリーンショットを防止するために使用されていない `setRecentsScreenshotEnabled` (`setRecentsScreenshotEnabled` Not Used to Prevent Screenshots When Backgrounded)](tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0292.md)
      - [MASTG-TEST-0293 SurfaceView でのスクリーンショットを防止するために使用されていない `setSecure` (`setSecure` Not Used to Prevent Screenshots in SurfaceViews)](tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0293.md)
      - [MASTG-TEST-0294 Compose ダイアログのスクリーンショットを防止するために使用されていない `SecureOn` (`SecureOn` Not Used to Prevent Screenshots in Compose Dialogs)](tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0294.md)
      - [MASTG-TEST-0315 通知を介して露出する機密データ (Sensitive Data Exposed via Notifications)](tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0315.md)
      - [MASTG-TEST-0316 テキスト入力フィールドにユーザー認証データを露出するアプリ (App Exposing User Authentication Data in Text Input Fields)](tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0316.md)
      - [MASTG-TEST-0320 機密データをクリーンアップしない WebView (WebViews Not Cleaning Up Sensitive Data)](tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0320.md)

    - MASVS-CODE: コード品質
      - [MASTG-TEST-0222 位置独立コード (PIC) が有効でない (Position Independent Code (PIC) Not Enabled)](tests-beta/android/MASVS-CODE/MASTG-TEST-0222.md)
      - [MASTG-TEST-0223 スタックカナリアが有効でない (Stack Canaries Not Enabled)](tests-beta/android/MASVS-CODE/MASTG-TEST-0223.md)
      - [MASTG-TEST-0245 プラットフォームバージョン API への参照 (References to Platform Version APIs)](tests-beta/android/MASVS-CODE/MASTG-TEST-0245.md)
      - [MASTG-TEST-0272 Android プロジェクトでの既知の脆弱性を持つ依存関係を特定する (Identify Dependencies with Known Vulnerabilities in the Android Project)](tests-beta/android/MASVS-CODE/MASTG-TEST-0272.md)
      - [MASTG-TEST-0274 アプリの SBOM での既知の脆弱性を持つ依存関係 (Dependencies with Known Vulnerabilities in the App's SBOM)](tests-beta/android/MASVS-CODE/MASTG-TEST-0274.md)

    - MASVS-RESILIENCE: リバースエンジニアリングと改竄に対する耐性
      - [MASTG-TEST-0224 安全でない署名バージョンの使用 (Usage of Insecure Signature Version)](tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0224.md)
      - [MASTG-TEST-0225 安全でない署名鍵サイズの使用 (Usage of Insecure Signature Key Size)](tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0225.md)
      - [MASTG-TEST-0226 AndroidManifest で有効になっているデバッグフラグ (Debuggable Flag Enabled in the AndroidManifest)](tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0226.md)
      - [MASTG-TEST-0227 WebView のデバッグが有効 (Debugging Enabled for WebViews)](tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0227.md)
      - [MASTG-TEST-0247 安全な画面ロックを検出するための API への参照 (References to APIs for Detecting Secure Screen Lock)](tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0247.md)
      - [MASTG-TEST-0249 安全な画面ロック検出 API の実行時使用 (Runtime Use of Secure Screen Lock Detection APIs)](tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0249.md)
      - [MASTG-TEST-0263 StrictMode 違反のログ記録 (Logging of StrictMode Violations)](tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0263.md)
      - [MASTG-TEST-0264 StrictMode API の実行時使用 (Runtime Use of StrictMode APIs)](tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0264.md)
      - [MASTG-TEST-0265 StrictMode API への参照 (References to StrictMode APIs)](tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0265.md)
      - [MASTG-TEST-0288 ネイティブバイナリのデバッグシンボル (Debugging Symbols in Native Binaries)](tests-beta/android/MASVS-RESILIENCE/MASTG-TEST-0288.md)

    - MASVS-PRIVACY: プライバシー
      - [MASTG-TEST-0206 ネットワークトラフィックキャプチャにおける宣言されていない PII (Undeclared PII in Network Traffic Capture)](tests-beta/android/MASVS-PRIVACY/MASTG-TEST-0206.md)
      - [MASTG-TEST-0254 危険なアプリパーミッション (Dangerous App Permissions)](tests-beta/android/MASVS-PRIVACY/MASTG-TEST-0254.md)
      - [MASTG-TEST-0255 最低限でないパーミッションリクエスト (Permission Requests Not Minimized)](tests-beta/android/MASVS-PRIVACY/MASTG-TEST-0255.md)
      - [MASTG-TEST-0256 パーミッションの理由付けの欠如 (Missing Permission Rationale)](tests-beta/android/MASVS-PRIVACY/MASTG-TEST-0256.md)
      - [MASTG-TEST-0257 リセットしていない未使用のパーミッション (Not Resetting Unused Permissions)](tests-beta/android/MASVS-PRIVACY/MASTG-TEST-0257.md)
      - [MASTG-TEST-0318 機密ユーザーデータを扱うことが知られている SDK API への参照 (References to SDK APIs Known to Handle Sensitive User Data)](tests-beta/android/MASVS-PRIVACY/MASTG-TEST-0318.md)
      - [MASTG-TEST-0319 機密ユーザーデータを扱うことが知られている SDK API の実行時使用 (Runtime Use of SDK APIs Known to Handle Sensitive User Data)](tests-beta/android/MASVS-PRIVACY/MASTG-TEST-0319.md)

  - iOS
    - MASVS-STORAGE: ストレージ
      - [MASTG-TEST-0215 バックアップ除外としてマークされていない機密データ (Sensitive Data Not Marked For Backup Exclusion)](tests-beta/ios/MASVS-STORAGE/MASTG-TEST-0215.md)
      - [MASTG-TEST-0296 安全でないログ記録による機密データ露出 (Sensitive Data Exposure Through Insecure Logging)](tests-beta/ios/MASVS-STORAGE/MASTG-TEST-0296.md)
      - [MASTG-TEST-0297 ログへの機密データの挿入 (Insertion of Sensitive Data into Logs)](tests-beta/ios/MASVS-STORAGE/MASTG-TEST-0297.md)
      - [MASTG-TEST-0298 バックアップ対象のファイルの実行時監視 (Runtime Monitoring of Files Eligible for Backup)](tests-beta/ios/MASVS-STORAGE/MASTG-TEST-0298.md)
      - [MASTG-TEST-0299 プライベートストレージでのファイルのデータ保護クラス (Data Protection Classes for Files in Private Storage)](tests-beta/ios/MASVS-STORAGE/MASTG-TEST-0299.md)
      - [MASTG-TEST-0300 プライベートストレージに暗号化されていないデータを保存するための API への参照 (References to APIs for Storing Unencrypted Data in Private Storage)](tests-beta/ios/MASVS-STORAGE/MASTG-TEST-0300.md)
      - [MASTG-TEST-0301 プライベートストレージに暗号化されていないデータを保存するための API の実行時使用 (Runtime Use of APIs for Storing Unencrypted Data in Private Storage)](tests-beta/ios/MASVS-STORAGE/MASTG-TEST-0301.md)
      - [MASTG-TEST-0302 プライベートストレージファイル内の暗号化されていない機密データ (Sensitive Data Unencrypted in Private Storage Files)](tests-beta/ios/MASVS-STORAGE/MASTG-TEST-0302.md)
      - [MASTG-TEST-0303 共有ストレージに暗号化されていないデータを保存するための API への参照 (References to APIs for Storing Unencrypted Data in Shared Storage)](tests-beta/ios/MASVS-STORAGE/MASTG-TEST-0303.md)
      - [MASTG-TEST-0313 テキストフィールドのキーボードキャッシュを防止するための API への参照 (References to APIs for Preventing Keyboard Caching of Text Fields)](tests-beta/ios/MASVS-STORAGE/MASTG-TEST-0313.md)
      - [MASTG-TEST-0314 キーボードキャッシュの対象となるテキストフィールドの実行時監視 (Runtime Monitoring of Text Fields Eligible for Keyboard Caching)](tests-beta/ios/MASVS-STORAGE/MASTG-TEST-0314.md)

    - MASVS-CRYPTO: 暗号
      - [MASTG-TEST-0209 不十分な鍵サイズ (Insufficient Key Sizes)](tests-beta/ios/MASVS-CRYPTO/MASTG-TEST-0209.md)
      - [MASTG-TEST-0210 不備のある対称暗号アルゴリズム (Broken Symmetric Encryption Algorithms)](tests-beta/ios/MASVS-CRYPTO/MASTG-TEST-0210.md)
      - [MASTG-TEST-0211 不備のあるハッシュアルゴリズム (Broken Hashing Algorithms)](tests-beta/ios/MASVS-CRYPTO/MASTG-TEST-0211.md)
      - [MASTG-TEST-0213 コード内にハードコードされた暗号鍵の使用 (Use of Hardcoded Cryptographic Keys in Code)](tests-beta/ios/MASVS-CRYPTO/MASTG-TEST-0213.md)
      - [MASTG-TEST-0214 ファイル内にハードコードされた暗号鍵 (Hardcoded Cryptographic Keys in Files)](tests-beta/ios/MASVS-CRYPTO/MASTG-TEST-0214.md)
      - [MASTG-TEST-0311 安全でないランダム API の使用 (Insecure Random API Usage)](tests-beta/ios/MASVS-CRYPTO/MASTG-TEST-0311.md)
      - [MASTG-TEST-0317 不備のある対称暗号モード (Broken Symmetric Encryption Modes)](tests-beta/ios/MASVS-CRYPTO/MASTG-TEST-0317.md)

    - MASVS-AUTH: 認証と認可
      - [MASTG-TEST-0266 イベントバウンド型生体認証用の API への参照 (References to APIs for Event-Bound Biometric Authentication)](tests-beta/ios/MASVS-AUTH/MASTG-TEST-0266.md)
      - [MASTG-TEST-0267 イベントバウンド型生体認証の実行時使用 (Runtime Use Of Event-Bound Biometric Authentication)](tests-beta/ios/MASVS-AUTH/MASTG-TEST-0267.md)
      - [MASTG-TEST-0268 非生体認証へのフォールバックを許可する API への参照 (References to APIs Allowing Fallback to Non-Biometric Authentication)](tests-beta/ios/MASVS-AUTH/MASTG-TEST-0268.md)
      - [MASTG-TEST-0269 非生体認証へのフォールバックを許可する API の実行時使用 (Runtime Use Of APIs Allowing Fallback to Non-Biometric Authentication)](tests-beta/ios/MASVS-AUTH/MASTG-TEST-0269.md)
      - [MASTG-TEST-0270 生体認証登録の変更を検出する API への参照 (References to APIs Detecting Biometric Enrollment Changes)](tests-beta/ios/MASVS-AUTH/MASTG-TEST-0270.md)
      - [MASTG-TEST-0271 生体認証登録の変更を検出する API の実行時使用 (Runtime Use Of APIs Detecting Biometric Enrollment Changes)](tests-beta/ios/MASVS-AUTH/MASTG-TEST-0271.md)

    - MASVS-NETWORK: ネットワーク通信
      - [MASTG-TEST-0321 ハードコードされた HTTP URL (Hardcoded HTTP URLs)](tests-beta/ios/MASVS-NETWORK/MASTG-TEST-0321.md)
      - [MASTG-TEST-0322 クリアテキストトラフィックを許可する App Transport Security 構成 (App Transport Security Configurations Allowing Cleartext Traffic)](tests-beta/ios/MASVS-NETWORK/MASTG-TEST-0322.md)
      - [MASTG-TEST-0323 クリアテキストトラフィックのための低レベルネットワーク API の使用 (Uses of Low-Level Networking APIs for Cleartext Traffic)](tests-beta/ios/MASVS-NETWORK/MASTG-TEST-0323.md)

    - MASVS-PLATFORM: プラットフォーム連携
      - [MASTG-TEST-0276 iOS の汎用ペーストボードの使用 (Use of the iOS General Pasteboard)](tests-beta/ios/MASVS-PLATFORM/MASTG-TEST-0276.md)
      - [MASTG-TEST-0277 実行時の iOS の汎用ペーストボード内の機密データ (Sensitive Data in the iOS General Pasteboard at Runtime)](tests-beta/ios/MASVS-PLATFORM/MASTG-TEST-0277.md)
      - [MASTG-TEST-0278 使用後にクリアされないペーストボードコンテンツ (Pasteboard Contents Not Cleared After Use)](tests-beta/ios/MASVS-PLATFORM/MASTG-TEST-0278.md)
      - [MASTG-TEST-0279 期限切れにならないペーストボードコンテンツ (Pasteboard Contents Not Expiring)](tests-beta/ios/MASVS-PLATFORM/MASTG-TEST-0279.md)
      - [MASTG-TEST-0280 ローカルデバイスに制限されていないペーストボードコンテンツ (Pasteboard Contents Not Restricted to Local Device)](tests-beta/ios/MASVS-PLATFORM/MASTG-TEST-0280.md)
      - [MASTG-TEST-0290 アプリのバックグラウンド時のスクリーンショットでの機密コンテンツ露出の実行時検証 (Runtime Verification of Sensitive Content Exposure in Screenshots During App Backgrounding)](tests-beta/ios/MASVS-PLATFORM/MASTG-TEST-0290.md)

    - MASVS-CODE: コード品質
      - [MASTG-TEST-0228 位置独立コード (PIC) が有効でない (Position Independent Code (PIC) not Enabled)](tests-beta/ios/MASVS-CODE/MASTG-TEST-0228.md)
      - [MASTG-TEST-0229 スタックカナリアが有効でない (Stack Canaries Not enabled)](tests-beta/ios/MASVS-CODE/MASTG-TEST-0229.md)
      - [MASTG-TEST-0230 自動参照カウント (ARC) が有効でない (Automatic Reference Counting (ARC) not enabled)](tests-beta/ios/MASVS-CODE/MASTG-TEST-0230.md)
      - [MASTG-TEST-0273 依存関係マネージャのアーティファクトをスキャンして既知の脆弱性を持つ依存関係を特定する (Identify Dependencies with Known Vulnerabilities by Scanning Dependency Managers Artifacts)](tests-beta/ios/MASVS-CODE/MASTG-TEST-0273.md)
      - [MASTG-TEST-0275 アプリの SBOM での既知の脆弱性を持つ依存関係 (Dependencies with Known Vulnerabilities in the App's SBOM)](tests-beta/ios/MASVS-CODE/MASTG-TEST-0275.md)

    - MASVS-RESILIENCE: リバースエンジニアリングと改竄に対する耐性
      - [MASTG-TEST-0219 デバッグシンボルのテスト (Testing for Debugging Symbols)](tests-beta/ios/MASVS-RESILIENCE/MASTG-TEST-0219.md)
      - [MASTG-TEST-0220 古いコード署名フォーマットの使用 (Usage of Outdated Code Signature Format)](tests-beta/ios/MASVS-RESILIENCE/MASTG-TEST-0220.md)
      - [MASTG-TEST-0240 コード内の脱獄検出 (Jailbreak Detection in Code)](tests-beta/ios/MASVS-RESILIENCE/MASTG-TEST-0240.md)
      - [MASTG-TEST-0241 脱獄検出技法の実行時使用 (Runtime Use of Jailbreak Detection Techniques)](tests-beta/ios/MASVS-RESILIENCE/MASTG-TEST-0241.md)
      - [MASTG-TEST-0246 安全な画面ロック検出 API の実行時使用 (Runtime Use of Secure Screen Lock Detection APIs)](tests-beta/ios/MASVS-RESILIENCE/MASTG-TEST-0246.md)
      - [MASTG-TEST-0248 安全な画面ロックを検出するための API への参照 (References to APIs for Detecting Secure Screen Lock)](tests-beta/ios/MASVS-RESILIENCE/MASTG-TEST-0248.md)
      - [MASTG-TEST-0261 entitlements.plist で有効になっているデバッグ可能なエンタイトルメント (Debuggable Entitlement Enabled in the entitlements.plist)](tests-beta/ios/MASVS-RESILIENCE/MASTG-TEST-0261.md)

    - MASVS-PRIVACY: プライバシー
      - [MASTG-TEST-0281 未宣言の既知のトラッキングドメイン (Undeclared Known Tracking Domains)](tests-beta/ios/MASVS-PRIVACY/MASTG-TEST-0281.md)

### デモ

<!-- - [デモ一覧](demo.md) -->

### テクニック

<!-- - [テクニック一覧](techniques.md) -->

### ツール

- [ツール一覧](tools.md)
  - Android
    - [MASTG-TOOL-0001 Frida for Android](tools/android/MASTG-TOOL-0001.md)
    - [MASTG-TOOL-0002 MobSF for Android](tools/android/MASTG-TOOL-0002.md)
    - [MASTG-TOOL-0003 nm - Android](tools/android/MASTG-TOOL-0003.md)
    - [MASTG-TOOL-0004 adb](tools/android/MASTG-TOOL-0004.md)
    - [MASTG-TOOL-0005 Android NDK](tools/android/MASTG-TOOL-0005.md)
    - [MASTG-TOOL-0006 Android SDK](tools/android/MASTG-TOOL-0006.md)
    - [MASTG-TOOL-0007 Android Studio](tools/android/MASTG-TOOL-0007.md)
    - [MASTG-TOOL-0008 Android-SSL-TrustKiller](tools/android/MASTG-TOOL-0008.md)
    - [MASTG-TOOL-0009 APKiD](tools/android/MASTG-TOOL-0009.md)
    - [MASTG-TOOL-0010 APKLab](tools/android/MASTG-TOOL-0010.md)
    - [MASTG-TOOL-0011 Apktool](tools/android/MASTG-TOOL-0011.md)
    - [MASTG-TOOL-0012 apkx](tools/android/MASTG-TOOL-0012.md)
    - [MASTG-TOOL-0013 Busybox](tools/android/MASTG-TOOL-0013.md)
    - [MASTG-TOOL-0014 Bytecode Viewer](tools/android/MASTG-TOOL-0014.md)
    - [MASTG-TOOL-0015 Drozer](tools/android/MASTG-TOOL-0015.md)
    - [MASTG-TOOL-0016 gplaycli](tools/android/MASTG-TOOL-0016.md)
    - [MASTG-TOOL-0017 House](tools/android/MASTG-TOOL-0017.md)
    - [MASTG-TOOL-0018 jadx](tools/android/MASTG-TOOL-0018.md)
    - [MASTG-TOOL-0019 jdb](tools/android/MASTG-TOOL-0019.md)
    - [MASTG-TOOL-0020 JustTrustMe](tools/android/MASTG-TOOL-0020.md)
    - [MASTG-TOOL-0021 Magisk](tools/android/MASTG-TOOL-0021.md)
    - [MASTG-TOOL-0022 Proguard](tools/android/MASTG-TOOL-0022.md)
    - [MASTG-TOOL-0023 RootCloak Plus](tools/android/MASTG-TOOL-0023.md)
    - [MASTG-TOOL-0024 Scrcpy](tools/android/MASTG-TOOL-0024.md)
    - [MASTG-TOOL-0025 SSLUnpinning](tools/android/MASTG-TOOL-0025.md)
    - [MASTG-TOOL-0026 Termux](tools/android/MASTG-TOOL-0026.md)
    - [MASTG-TOOL-0027 Xposed](tools/android/MASTG-TOOL-0027.md)
    - [MASTG-TOOL-0028 radare2 for Android](tools/android/MASTG-TOOL-0028.md)
    - [MASTG-TOOL-0029 objection for Android](tools/android/MASTG-TOOL-0029.md)
    - [MASTG-TOOL-0030 Angr](tools/android/MASTG-TOOL-0030.md)
    - [MASTG-TOOL-0099 FlowDroid](tools/android/MASTG-TOOL-0099.md)
    - [MASTG-TOOL-0103 uber-apk-signer](tools/android/MASTG-TOOL-0103.md)
    - [MASTG-TOOL-0107 JNITrace](tools/android/MASTG-TOOL-0107.md)
    - [MASTG-TOOL-0112 pidcat](tools/android/MASTG-TOOL-0112.md)
    - [MASTG-TOOL-0116 Blutter](tools/android/MASTG-TOOL-0116.md)
    - [MASTG-TOOL-0120 ProxyDroid](tools/android/MASTG-TOOL-0120.md)
    - [MASTG-TOOL-0123 apksigner](tools/android/MASTG-TOOL-0123.md)
    - [MASTG-TOOL-0124 aapt2](tools/android/MASTG-TOOL-0124.md)
    - [MASTG-TOOL-0125 Apkleaks](tools/android/MASTG-TOOL-0125.md)
    - [MASTG-TOOL-0130 blint](tools/android/MASTG-TOOL-0130.md)
    - [MASTG-TOOL-0140 frida-multiple-unpinning](tools/android/MASTG-TOOL-0140.md)
    - [MASTG-TOOL-0146 RootBeer](tools/android/MASTG-TOOL-0146.md)
    - [MASTG-TOOL-0147 Android RASP](tools/android/MASTG-TOOL-0147.md)

  - Generic
    - [MASTG-TOOL-0031 Frida](tools/generic/MASTG-TOOL-0031.md)
    - [MASTG-TOOL-0032 Frida CodeShare](tools/generic/MASTG-TOOL-0032.md)
    - [MASTG-TOOL-0033 Ghidra](tools/generic/MASTG-TOOL-0033.md)
    - [MASTG-TOOL-0034 LIEF](tools/generic/MASTG-TOOL-0034.md)
    - [MASTG-TOOL-0035 MobSF](tools/generic/MASTG-TOOL-0035.md)
    - [MASTG-TOOL-0036 r2frida](tools/generic/MASTG-TOOL-0036.md)
    - [MASTG-TOOL-0037 RMS Runtime Mobile Security](tools/generic/MASTG-TOOL-0037.md)
    - [MASTG-TOOL-0038 objection](tools/generic/MASTG-TOOL-0038.md)
    - [MASTG-TOOL-0098 iaito](tools/generic/MASTG-TOOL-0098.md)
    - [MASTG-TOOL-0100 re-flutter](tools/generic/MASTG-TOOL-0100.md)
    - [MASTG-TOOL-0101 disable-flutter-tls-verification](tools/generic/MASTG-TOOL-0101.md)
    - [MASTG-TOOL-0104 hermes-dec](tools/generic/MASTG-TOOL-0104.md)
    - [MASTG-TOOL-0106 Fridump](tools/generic/MASTG-TOOL-0106.md)
    - [MASTG-TOOL-0108 Corellium](tools/generic/MASTG-TOOL-0108.md)
    - [MASTG-TOOL-0110 semgrep](tools/generic/MASTG-TOOL-0110.md)
    - [MASTG-TOOL-0129 rabin2](tools/generic/MASTG-TOOL-0129.md)
    - [MASTG-TOOL-0131 dependency-check](tools/generic/MASTG-TOOL-0131.md)
    - [MASTG-TOOL-0132 dependency-track](tools/generic/MASTG-TOOL-0132.md)
    - [MASTG-TOOL-0133 Visual Studio Code (vscode)](tools/generic/MASTG-TOOL-0133.md)
    - [MASTG-TOOL-0134 cdxgen](tools/generic/MASTG-TOOL-0134.md)
    - [MASTG-TOOL-0144 gitleaks](tools/generic/MASTG-TOOL-0144.md)
    - [MASTG-TOOL-0145 Frooky](tools/generic/MASTG-TOOL-0145.md)

  - iOS
    - [MASTG-TOOL-0039 Frida for iOS](tools/ios/MASTG-TOOL-0039.md)
    - [MASTG-TOOL-0040 MobSF for iOS](tools/ios/MASTG-TOOL-0040.md)
    - [MASTG-TOOL-0041 nm - iOS](tools/ios/MASTG-TOOL-0041.md)
    - [MASTG-TOOL-0042 BinaryCookieReader](tools/ios/MASTG-TOOL-0042.md)
    - [MASTG-TOOL-0043 class-dump](tools/ios/MASTG-TOOL-0043.md)
    - [MASTG-TOOL-0044 class-dump-z](tools/ios/MASTG-TOOL-0044.md)
    - [MASTG-TOOL-0045 class-dump-dyld](tools/ios/MASTG-TOOL-0045.md)
    - [MASTG-TOOL-0046 Cycript](tools/ios/MASTG-TOOL-0046.md)
    - [MASTG-TOOL-0047 Cydia](tools/ios/MASTG-TOOL-0047.md)
    - [MASTG-TOOL-0048 dsdump](tools/ios/MASTG-TOOL-0048.md)
    - [MASTG-TOOL-0049 Frida-cycript](tools/ios/MASTG-TOOL-0049.md)
    - [MASTG-TOOL-0050 Frida-ios-dump](tools/ios/MASTG-TOOL-0050.md)
    - [MASTG-TOOL-0051 gdb](tools/ios/MASTG-TOOL-0051.md)
    - [MASTG-TOOL-0053 iOSbackup](tools/ios/MASTG-TOOL-0053.md)
    - [MASTG-TOOL-0054 ios-deploy](tools/ios/MASTG-TOOL-0054.md)
    - [MASTG-TOOL-0055 iproxy](tools/ios/MASTG-TOOL-0055.md)
    - [MASTG-TOOL-0056 Keychain-Dumper](tools/ios/MASTG-TOOL-0056.md)
    - [MASTG-TOOL-0057 lldb](tools/ios/MASTG-TOOL-0057.md)
    - [MASTG-TOOL-0058 MachOView](tools/ios/MASTG-TOOL-0058.md)
    - [MASTG-TOOL-0059 optool](tools/ios/MASTG-TOOL-0059.md)
    - [MASTG-TOOL-0060 otool](tools/ios/MASTG-TOOL-0060.md)
    - [MASTG-TOOL-0061 Grapefruit](tools/ios/MASTG-TOOL-0061.md)
    - [MASTG-TOOL-0062 Plutil](tools/ios/MASTG-TOOL-0062.md)
    - [MASTG-TOOL-0063 security](tools/ios/MASTG-TOOL-0063.md)
    - [MASTG-TOOL-0064 Sileo](tools/ios/MASTG-TOOL-0064.md)
    - [MASTG-TOOL-0065 simctl](tools/ios/MASTG-TOOL-0065.md)
    - [MASTG-TOOL-0066 SSL Kill Switch 2](tools/ios/MASTG-TOOL-0066.md)
    - [MASTG-TOOL-0067 swift-demangle](tools/ios/MASTG-TOOL-0067.md)
    - [MASTG-TOOL-0068 SwiftShield](tools/ios/MASTG-TOOL-0068.md)
    - [MASTG-TOOL-0069 Usbmuxd](tools/ios/MASTG-TOOL-0069.md)
    - [MASTG-TOOL-0070 Xcode](tools/ios/MASTG-TOOL-0070.md)
    - [MASTG-TOOL-0071 Xcode Command Line Tools](tools/ios/MASTG-TOOL-0071.md)
    - [MASTG-TOOL-0072 xcrun](tools/ios/MASTG-TOOL-0072.md)
    - [MASTG-TOOL-0073 radare2 for iOS](tools/ios/MASTG-TOOL-0073.md)
    - [MASTG-TOOL-0074 objection for iOS](tools/ios/MASTG-TOOL-0074.md)
    - [MASTG-TOOL-0102 ios-app-signer](tools/ios/MASTG-TOOL-0102.md)
    - [MASTG-TOOL-0105 IPSW](tools/ios/MASTG-TOOL-0105.md)
    - [MASTG-TOOL-0111 ldid](tools/ios/MASTG-TOOL-0111.md)
    - [MASTG-TOOL-0114 codesign](tools/ios/MASTG-TOOL-0114.md)
    - [MASTG-TOOL-0117 fastlane](tools/ios/MASTG-TOOL-0117.md)
    - [MASTG-TOOL-0118 Sideloadly](tools/ios/MASTG-TOOL-0118.md)
    - [MASTG-TOOL-0121 objdump - iOS](tools/ios/MASTG-TOOL-0121.md)
    - [MASTG-TOOL-0122 c++filt](tools/ios/MASTG-TOOL-0122.md)
    - [MASTG-TOOL-0126 libimobiledevice suite](tools/ios/MASTG-TOOL-0126.md)
    - [MASTG-TOOL-0127 AppSync Unified](tools/ios/MASTG-TOOL-0127.md)
    - [MASTG-TOOL-0128 Filza](tools/ios/MASTG-TOOL-0128.md)
    - [MASTG-TOOL-0135 PlistBuddy](tools/ios/MASTG-TOOL-0135.md)
    - [MASTG-TOOL-0136 plistlib](tools/ios/MASTG-TOOL-0136.md)
    - [MASTG-TOOL-0137 GlobalWebInspect](tools/ios/MASTG-TOOL-0137.md)
    - [MASTG-TOOL-0138 ipainstaller](tools/ios/MASTG-TOOL-0138.md)
    - [MASTG-TOOL-0139 ElleKit](tools/ios/MASTG-TOOL-0139.md)
    - [MASTG-TOOL-0141 IOSSecuritySuite](tools/ios/MASTG-TOOL-0141.md)
    - [MASTG-TOOL-0142 Choicy](tools/ios/MASTG-TOOL-0142.md)

  - Network
    - [MASTG-TOOL-0075 Android tcpdump](tools/network/MASTG-TOOL-0075.md)
    - [MASTG-TOOL-0076 bettercap](tools/network/MASTG-TOOL-0076.md)
    - [MASTG-TOOL-0077 Burp Suite](tools/network/MASTG-TOOL-0077.md)
    - [MASTG-TOOL-0078 MITM Relay](tools/network/MASTG-TOOL-0078.md)
    - [MASTG-TOOL-0079 ZAP](tools/network/MASTG-TOOL-0079.md)
    - [MASTG-TOOL-0080 tcpdump](tools/network/MASTG-TOOL-0080.md)
    - [MASTG-TOOL-0081 Wireshark](tools/network/MASTG-TOOL-0081.md)
    - [MASTG-TOOL-0097 mitmproxy](tools/network/MASTG-TOOL-0097.md)
    - [MASTG-TOOL-0109 Nope-Proxy](tools/network/MASTG-TOOL-0109.md)
    - [MASTG-TOOL-0115 HTTP Toolkit](tools/network/MASTG-TOOL-0115.md)
    - [MASTG-TOOL-0143 badssl](tools/network/MASTG-TOOL-0143.md)

### アプリ

- [アプリ一覧](apps.md)
  - Android
    - [MASTG-APP-0001 AndroGoat](apps/android/MASTG-APP-0001.md)
    - [MASTG-APP-0002 Android License Validator](apps/android/MASTG-APP-0002.md)
    - [MASTG-APP-0003 Android UnCrackable L1](apps/android/MASTG-APP-0003.md)
    - [MASTG-APP-0004 Android UnCrackable L2](apps/android/MASTG-APP-0004.md)
    - [MASTG-APP-0005 Android UnCrackable L3](apps/android/MASTG-APP-0005.md)
    - [MASTG-APP-0006 Digitalbank](apps/android/MASTG-APP-0006.md)
    - [MASTG-APP-0007 DIVA Android](apps/android/MASTG-APP-0007.md)
    - [MASTG-APP-0008 DodoVulnerableBank](apps/android/MASTG-APP-0008.md)
    - [MASTG-APP-0009 DVHMA](apps/android/MASTG-APP-0009.md)
    - [MASTG-APP-0010 InsecureBankv2](apps/android/MASTG-APP-0010.md)
    - [MASTG-APP-0011 MASTG Hacking Playground (Java)](apps/android/MASTG-APP-0011.md)
    - [MASTG-APP-0012 MASTG Hacking Playground (Kotlin)](apps/android/MASTG-APP-0012.md)
    - [MASTG-APP-0013 OVAA](apps/android/MASTG-APP-0013.md)
    - [MASTG-APP-0014 InsecureShop](apps/android/MASTG-APP-0014.md)
    - [MASTG-APP-0015 Android UnCrackable L4](apps/android/MASTG-APP-0015.md)
    - [MASTG-APP-0016 Finstergram](apps/android/MASTG-APP-0016.md)
    - [MASTG-APP-0017 Disable-flutter-tls-verification](apps/android/MASTG-APP-0017.md)
    - [MASTG-APP-0018 MASTestApp-Android-NETWORK](apps/android/MASTG-APP-0018.md)
    - [MASTG-APP-0029 BugBazaar](apps/android/MASTG-APP-0029.md)
    - [MASTG-APP-0031 VulnForum](apps/android/MASTG-APP-0031.md)
    - [MASTG-APP-0032 RootBeer Sample](apps/android/MASTG-APP-0032.md)
    - [MASTG-APP-0033 Android RASP Sample](apps/android/MASTG-APP-0033.md)

  - iOS
    - [MASTG-APP-0023 DVIA](apps/ios/MASTG-APP-0023.md)
    - [MASTG-APP-0024 DVIA-v2](apps/ios/MASTG-APP-0024.md)
    - [MASTG-APP-0025 iOS UnCrackable L1](apps/ios/MASTG-APP-0025.md)
    - [MASTG-APP-0026 iOS UnCrackable L2](apps/ios/MASTG-APP-0026.md)
    - [MASTG-APP-0027 Disable-flutter-tls-verification](apps/ios/MASTG-APP-0027.md)
    - [MASTG-APP-0028 iGoat-Swift](apps/ios/MASTG-APP-0028.md)
    - [MASTG-APP-0030 iBugBazaar](apps/ios/MASTG-APP-0030.md)
