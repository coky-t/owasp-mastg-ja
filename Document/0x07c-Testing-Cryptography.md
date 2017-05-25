## 暗号化のテスト

The following chapter outlines cryptography requirements of the MASVS into technical test cases. Test cases listed in this chapter are focused on server side and therefore are not relying on a specific implementation on iOS or Android.

Proper cryptographic key management is a common pitfall when designing mobile applications.

### 安全でないもしくは廃止された暗号化アルゴリズムに関するテスト

#### 概要

Choosing good cryptographic algorithm alone is not enough. Often security of otherwise sound algorithms can be affected if misconfigured. Many previously strong algorithms and their configurations are now considered vulnerable or non-compliant with best practices. It is therefore important to periodically check current best practices and adjust configurations accordingly.  

多くの暗号アルゴリズムおよびプロトコルは重大な弱点があることが示されているか、現代のセキュリティ要件には不十分であるため、使用してはいけません。

#### 静的解析

* Cryptographic algorithms are up to date and in-line with industry standards. This includes, but is not limited to outdated block ciphers (e.g. DES), stream ciphers (e.g. RC4), as well as hash functions (e.g. MD5) and broken random number generators like Dual_EC_DRBG (even if they are NIST certified). All of these should be marked as insecure and should not be used and removed from the application and server.
* Key lengths are in-line with industry standards and provide protection for sufficient amount of time. An online comparison of different key lengths and protection they provide taking into account Moore's law is available online<sup>[3]</sup>.
* Cryptographic parameters are well defined within reasonable range. This includes, but is not limited to: cryptographic salt, which should be at least the same length as hash function output, reasonable choice of password derivation function and iteration count (e.g. PBKDF2, scrypt or bcrypt), IVs being random and unique, fit-for-purpose block encryption modes (e.g. ECB should not be used, except specific cases), key management being done properly (e.g. 3DES should have three independent keys) and so on.

アプリケーション全体で暗号アルゴリズムのインスタンスを特定するためにソースコードを調査して、以下のような既知の脆弱なものを探します。

* DES
* RC2
* RC4
* BLOWFISH
* CRC32
* MD4
* MD5
* SHA1 and others.

推奨されるアルゴリズムの基本的なリストについては「改善方法」セクションを参照ください。

脆弱とみなされる DES アルゴリズムの初期化の例：
```Java
Cipher cipher = Cipher.getInstance("DES");
```

#### 動的解析

-- TODO [Give examples of Dynamic Testing for "Testing for Insecure and/or Deprecated Cryptographic Algorithms"] --

#### 改善方法

暗号化手法が廃止されていないことを定期的に確認します。以前、10億年の計算時間を要すると考えられていた一部の古いアルゴリズムは数日もしくは数時間で破られる可能性があります。これには MD4, MD5, SHA1, DES, および以前は強力であると考えられて他のアルゴリズムが含まれます。現在推奨されているアルゴリズムの例です。<sup>[1][2]</sup>

* 機密性: AES-256
* 完全性: SHA-256, SHA-384, SHA-512
* デジタル署名: RSA (3072 ビット以上), ECDSA with NIST P-384
* 鍵確立: RSA (3072 ビット以上), DH (3072 ビット以上), ECDH with NIST P-384

#### 参考情報

##### OWASP Mobile Top 10
* M6 - Broken Cryptography

##### OWASP MASVS
- V3.3: "アプリは特定のユースケースに適した暗号化プリミティブを使用している。業界のベストプラクティスに基づくパラメータで構成されている。"
- V3.4: "アプリはセキュリティ上の目的で広く廃止対象と考えられる暗号プロトコルやアルゴリズムを使用していない。"

##### CWE
* CWE-326: Inadequate Encryption Strength
* CWE-327: Use of a Broken or Risky Cryptographic Algorithm

##### その他
- [1] Commercial National Security Algorithm Suite and Quantum Computing FAQ - https://cryptome.org/2016/01/CNSA-Suite-and-Quantum-Computing-FAQ.pdf
- [2] NIST Special Publication 800-57 - http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf
- [3] Security "Crypto" provider deprecated in Android N -  https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html
- [4] NIST recommendations (2016) - https://www.keylength.com/en/4/
- [5] BSI recommendations (2017) - https://www.keylength.com/en/8/

##### ツール
* QARK - https://github.com/linkedin/qark
* Mobile Security Framework - https://github.com/ajinabraham/Mobile-Security-Framework-MobSF

### 暗号のカスタム実装に関するテスト

-- [TODO - needs more review / editing ] --

#### 概要

暗号機能に非標準のカスタムビルドアルゴリズムを使用することは危険です。特定の攻撃者がアルゴリズムを破り、保護されているデータを侵害する可能性があります。暗号化機能の実装には時間がかかり、困難であり、失敗する可能性があります。代わりに既にセキュアであることが証明されている既知のアルゴリズムを使用すべきです。すべての成熟したフレームワークやライブラリはモバイルアプリを実装する際にも使用すべき暗号化機能を提供します。

#### 静的解析

ソースコードに含まれるすべての暗号手法、特に機密データに直接適用されている手法を注意深く調べます。一見標準のようにみえるが改変されたアルゴリズムに細心の注意を払います。エンコーディングは暗号化ではないことを忘れないでください。排他的 OR オペレーションなどのビットシフトオペレータが現れたら深く掘り下げてみる良い兆候かもしれません。

-- [TODO - The below content was merged from the old iOS 'Verifying Cryptographic Key Management' section. This section needs some review and editing] --

During static analysis, it is important understand how cryptographic algorithms used by the particular target app. Let us divide applications into three main categories:

1. An application is a pure online application, where authentication, authorization is done online with application server and no information is stored locally.
2. An application is mainly an offline application, where authentication and authorization is done purely locally. Application information is stored also locally.
3. An application is a mixture of the first two, i.e. it supports both: online and offline authentication, some information may be stored locally and some or all actions that are performed online may be performed offline.
   * A good example of such an app, may be point of sale (POS), where seller may sell products. The app requires connection to the internet, so that it can communicate with backend and update information on products that were sold, cash amount, etc. However, there might be a business requirement that this app must also work in offline mode and would synchronize all information once it connects back to the internet. This will be a mixed app type, i.e. online and offline.

The following checks would be performed in the last two app categories:

* Ensure that no keys/passwords are hardcoded and stored within the source code. Pay special attention to any 'administrative' or backdoor accounts enabled in the source code. Storing fixed salt within application or password hashes may cause problems too.
* Ensure that no obfuscated keys or passwords are in the source code. Obfuscation is easily bypassed by dynamic instrumentation and in principle does not differ from hardcoded keys.
* If the application is using two-way SSL (i.e. there is both server and client certificate validated) check if:
   * the password to the client certificate is not stored locally, it should be in the Keychain
   * the client certificate is not shared among all installations (e.g. hardcoded in the app)

A proper way would be to generate the client certificate upon user registration/first login and then store it in the Keychain.

* Ensure that the keys/passwords/logins are not stored in application data. This can be included in the iTunes backup and increase attack surface. Keychain is the only appropriate place to store credentials of any type (password, certificate, etc.).
* Ensure that keychain entries have appropriate protection class. The most rigorous being `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` which translates to: entry unlocked only if passcode on the device is set and device is unlocked; the entry is not exportable in backups or by any other means.

The following checks would be performed in the offline application:

* if the app relies on an additional encrypted container stored in app data, ensure how the encryption key is used;
   * if key wrapping scheme is used, ensure that the master secret is initialized for each user, or container is re-encrypted with new key;
   * check how password change is handled and specifically, if you can use master secret or previous password to decrypt the container.

#### 動的解析

カスタム暗号化方式が本当に適切かどうか確認するために、APK を逆コンパイルしてアルゴリズムを調べることをお勧めします(「静的解析」を参照ください)。

#### 改善方法

カスタム暗号アルゴリズムを開発してはいけません。これは暗号技術者によりよく知られている攻撃を受ける可能性が高いためです。

機密データを格納する必要がある場合は強力な最新の暗号アルゴリズムを使用します。この分野の専門家により現時点で強力であると見なされている十分に検証されたアルゴリズムを選択し、十分にテストされた実装を使用します。KeyStore は機密情報を格納するのに適しており、Android のドキュメントには提供される強力な暗号のリストがあります <sup>[1]</sup>。

#### 参考情報

##### OWASP Mobile Top 10 2016
* M6 - Broken Cryptography

##### OWASP MASVS
- V3.2: "アプリは実績のある暗号プリミティブの実装を使用している。"

##### CWE
* CWE-327: Use of a Broken or Risky Cryptographic Algorithm

##### その他
[1] Supported Ciphers in KeyStore - https://developer.android.com/training/articles/keystore.html#SupportedCiphers
