---
masvs_category: MASVS-CRYPTO
platform: android
---

# Android の暗号化 API

## 概要

["モバイルアプリの暗号化"](0x04g-Testing-Cryptography.md) の章では、一般的な暗号のベストプラクティスを紹介し、暗号が間違って使用される場合に起こりうる典型的な問題について説明しました。この章では、Android の暗号化 API について詳しく説明します。ソースコード内でのこれらの API の使用を特定する方法とその暗号設定を判断する方法を示します。コードをレビューする際には、使用されている暗号パラメータをこのガイドにリンクされている現行のベストプラクティスと比較するようにしてください。

Android 上の暗号化システムの主要コンポーネントを特定できます。

- [セキュリティプロバイダ (Security Provider)](../knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0011.md)
- [Android キーストア (Android KeyStore)](../knowledge/android/MASVS-STORAGE/MASTG-KNOW-0043.md)
- [キーチェーン (KeyChain)](../knowledge/android/MASVS-STORAGE/MASTG-KNOW-0048.md)

Android 暗号化 API は Java Cryptography Architecture (JCA) をベースとしています。JCA はインタフェースと実装を分離し、暗号化アルゴリズムのセットを実装できる複数の [セキュリティプロバイダ](https://developer.android.com/reference/java/security/Provider.html "Android Security Providers") を含めることを可能にしています。 JCA インタフェースのほとんどは `java.security.*` および `javax.crypto.*` パッケージで定義されています。さらに、 Android 固有のパッケージ `android.security.*` および `android.security.keystore.*` があります。

KeyStore および KeyChain は鍵を保存および使用するための API を提供しています (裏では、 KeyChain API は KeyStore システムを使用しています) 。これらのシステムは暗号鍵のライフサイクル全体を管理することを可能にします。暗号鍵管理を実装するための要件およびガイダンスは [Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html "Key Management Cheat Sheet") に記載されています。以下のフェーズが考えられます。

- 鍵の生成
- 鍵の使用
- 鍵の保管
- 鍵のアーカイブ
- 鍵の削除

### !!! 注記
鍵の保管については ["データストレージのテスト"](0x05d-Testing-Data-Storage.md) の章で解析しています。

これらのフェーズは KeyStore/KeyChain システムにより管理されます。ただしシステムの動作はアプリケーション開発者の実装方法により異なります。解析プロセスではアプリケーション開発者が使用する機能に焦点を当てる必要があります。以下の機能を特定および検証する必要があります。

- [鍵生成 (Key Generation)](../knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0012.md)
- [乱数生成 (Random number generation)](../knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0013.md)
- 鍵ローテーション

最新の API レベルをターゲットとするアプリでは、以下の変更が行われました。

- Android 7.0 (API level 24) 以上について [Android 開発者ブログでは以下のように記しています](https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html "Security provider Crypto deprecated in Android N") 。
    - セキュリティプロバイダの指定を停止することを推奨します。代わりに、常にパッチされた [セキュリティプロバイダ (Security Provider)](../knowledge/android/MASVS-CRYPTO/MASTG-KNOW-0011.md) を使用します。
    - `Crypto` プロバイダのサポートは中止されており、このプロバイダは非推奨です。同じことがセキュアランダムのための `SHA1PRNG` にも当てはまります。
- Android 8.1 (API レベル 27) 以上について [開発者ドキュメント](https://developer.android.com/about/versions/oreo/android-8.1 "Cryptography updates") は以下のように記しています。
    - `AndroidOpenSSL` として知られる Conscrypt は上述の Bouncy Castle を使用することをお勧めします。これは次の新しい実装を有します。 `AlgorithmParameters:GCM` , `KeyGenerator:AES`, `KeyGenerator:DESEDE`, `KeyGenerator:HMACMD5`, `KeyGenerator:HMACSHA1`, `KeyGenerator:HMACSHA224`, `KeyGenerator:HMACSHA256`, `KeyGenerator:HMACSHA384`, `KeyGenerator:HMACSHA512`, `SecretKeyFactory:DESEDE`, `Signature:NONEWITHECDSA`
    - GCM にはもはや `IvParameterSpec.class` を使用すべきではありません。代わりに `GCMParameterSpec.class` を使用します。
    - ソケットは `OpenSSLSocketImpl` から `ConscryptFileDescriptorSocket` および `ConscryptEngineSocket` に変更されています。
    - ヌルパラメータを持つ `SSLSession` は NullPointerException を返します。
    - 鍵を生成するために入力バイトとして十分な大きさの配列を持つ必要があります。そうでない場合 InvalidKeySpecException がスローされます。
    - ソケット読み込みが中断された場合は `SocketException` を取得します。
- Android 9 (API レベル 28) 以上について [Android 開発者ブログ](https://android-developers.googleblog.com/2018/03/cryptography-changes-in-android-p.html "Cryptography Changes in Android P") はさらに多くの変更を記しています。
    - `getInstance` メソッドを使用してセキュリティプロバイダを指定し、 28 未満の API をターゲットにすると、警告が発生します。 Android 9 (API レベル 28) 以上をターゲットにした場合、エラーが発生します。
    - `Crypto` プロバイダは現在削除されています。これをコールすると `NoSuchProviderException` が返されます。
- Android 10 (API レベル 29) について [開発者ドキュメント](https://developer.android.com/about/versions/10/behavior-changes-all#security "Security Changes in Android 10") にすべてのネットワークセキュリティの変更がリストされています。

**一般的な改善方法:**

アプリ審査の際には以下の推奨事項リストを考慮する必要があります。

- ["モバイルアプリの暗号化"](0x04g-Testing-Cryptography.md) の章で説明されているベストプラクティスが守られていることを確認します。
- セキュリティプロバイダが最新アップデートであることを確認します - [セキュリティプロバイダの更新](https://developer.android.com/training/articles/security-gms-provider "Updating security provider") 。
- セキュリティプロバイダの指定を停止し、デフォルト実装 (AndroidOpenSSL, Conscrypt) を使用します。
- Crypto セキュリティプロバイダとその `SHA1PRNG` は非推奨であるため使用を停止します。
- Android KeyStore システムに対してのみセキュリティプロバイダを指定します。
- IV なしでのパスワードベースの暗号化方式の使用を停止します。
- KeyPairGeneratorSpec の代わりに KeyGenParameterSpec を使用します。
