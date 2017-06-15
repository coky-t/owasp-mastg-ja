## モバイルアプリでの暗号化

以下の章では MASVS の暗号化要件の技術的なテストケースを説明します。この章に記載されているテストケースは一般的な暗号の概念に基づいており、iOS や Android の特定の実装に依存していません。
This chapter strives to provide recommendations for static testing methods where possible. However, dynamic testing methods are not generally applicable for the problems discussed below and, correspondingly, are not listed here.

#### Background on cryptography

The primary goal of cryptography is to provide confidentiality, data integrity, and authenticity, even in the face of an attack. Confidentiality is achieved through use of encryption, with the aim of ensuring secrecy of the contents. Data integrity deals with maintaining and ensuring consistency of data and detection of tampering/modification. Authenticity ensures that the data comes from a trusted source. Since this is a testing guide and not a cryptography textbook, the following paragraphs provide only a very limited outline of relevant techniques and their usages in the context of mobile applications.

* Encryption ensures data confidentiality by using special algorithms to convert the plaintext data into cipher text, which does not reveal any information about the original contents. The plaintext data can be restored from the cipher text through decryption. Two main forms of encryption are symmetric (or secret key) and asymmetric (or public key). In general, encryption operations do not protect integrity, but some symmetric encryption modes also feature that protection (see “Testing Sensitive Data Protection” section).
  - Symmetric-key encryption algorithms use the same key for both encryption and decryption. It is fast and suitable for bulk data processing. Since everybody who has access to the key is able to decrypt the encrypted content, they require careful key management.
  - Public-key (or asymmetric) encryption algorithms operate with two separate keys: the public key and the private key. The public key can be distributed freely, while the private key should not be shared with anyone. A message encrypted with the public key can only be decrypted with the private key. Since asymmetric encryption is several times slower than symmetric operations, it is typically only used to encrypt small amounts of data, such as symmetric keys for bulk encryption.
* Hash functions deterministically map arbitrary pieces of data into fixed-length values. It is typically easy to compute the hash, but difficult (or impossible) to determine the original input based on the hash. Cryptographic hash functions additionally guarantee that even small changes to the input data result in large changes to the resulting hash values. Cryptographic hash functions are used for integrity verification, but do not provide authenticity guarantees.
* Message Authentication Codes, or MACs, combine other cryptographic mechanism, such as symmetric encryption or hashes, with secret keys to provide both integrity and authenticity protection. However, in order to verify a MAC, multiple entities have to share the same secret key, and any of those entities will be able to generate a valid MAC. The most commonly used type of MAC, called HMAC, relies on hash as the underlying cryptographic primitive. As a rule, full name of an HMAC algorithm also includes the name of the underlying hash, e.g. - HMAC-SHA256.
* Signatures combine asymmetric cryptography (i.e. - using a public/private keypair) with hashing to provide integrity and authenticity by encrypting hash of the message with the private key. However, unlike MACs, signatures also provide non-repudiation property, as the private key should remain unique to the data signer.
* Key Derivation Functions, or KDFs, are often confused with password hashing functions. KDFs do have many useful properties for password hashing, but were created with different purposes in mind. In context of mobile applications, it is the password hashing functions that are typically meant for protecting stored passwords.

Two uses of cryptography are covered in other chapters:

* Secure communications. TLS (Transport Layer Security) uses most of the primitives named above, as well a number of others. It is covered in the “Testing Network Communication” chapter.
* Secure storage. Тhis chapter includes high-level considerations for using cryptography for secure data storage, and specific content for secure data storage capabilities will be found in OS-specific data storage chapters.

#### References
- [1] Password Hashing Competition - https://password-hashing.net/
-- TODO - list references to sources of algorithm definitions (RFCs, NIST SP, etc)


### 暗号のカスタム実装に関するテスト

#### 概要

非標準の暗号アルゴリズムやカスタムビルドの暗号アルゴリズムの使用は危険です。特定の攻撃者がアルゴリズムを破り、保護されているデータを侵害する可能性があります。暗号化機能の実装には時間がかかり、困難であり、失敗する可能性が非常に高くなります。代わりに既にセキュアであることが証明されている既知のアルゴリズムを使用すべきです。すべての成熟したフレームワークやライブラリはモバイルアプリを実装する際にも使用すべき暗号化機能を提供します。

#### 静的解析

ソースコードに含まれるすべての暗号手法、特に機密データに直接適用されている手法を注意深く調べます。All cryptographic operations (see the list in the introduction section) should come from the standard providers (for standard APIs for Android and iOS, see cryptography chapters for the respective platforms). Any cryptographic invocations which do not invoke standard routines from known providers should be candidates for closer inspection.一見標準のようにみえるが改変されたアルゴリズムに細心の注意を払います。エンコーディングは暗号化ではないことを忘れないでください。XOR (排他的 OR) などのビット操作演算子が現れたら深く掘り下げてみる良い兆候かもしれません。

#### 改善方法

カスタム暗号アルゴリズムを開発してはいけません。これは暗号技術者によりよく知られている攻撃を受ける可能性が高いためです。その分野の専門家により現在強力であると考えられている十分に検証されたアルゴリズムを選択し、十分にテストされた実装を使用します。

#### 参考情報

##### OWASP Mobile Top 10 2016
- M6 - Broken Cryptography

##### OWASP MASVS
- V3.2: "アプリは実績のある暗号プリミティブの実装を使用している。"

##### CWE
- CWE-327: Use of a Broken or Risky Cryptographic Algorithm

##### その他
- [1] Supported Ciphers in KeyStore - https://developer.android.com/training/articles/keystore.html#SupportedCiphers


### 安全ではない暗号アルゴリズムや廃止された暗号アルゴリズムに関するテスト

#### 概要

多くの暗号アルゴリズムやプロトコルは使用すべきではありません。それらには重大な脆弱性があることが示されているか、現代のセキュリティ要件には不十分であるためです。以前はセキュアであると考えられていたアルゴリズムが時間の経過とともにセキュアではなくなることがあります。したがって、最新のベストプラクティスを定期的に確認し、それに応じて設定を調整することが重要です。

#### 静的解析

ソースコードは暗号アルゴリズムが最新で業界標準に適合していることを確認されるべきです。これには、古いブロック暗号 (DES など)、ストリーム暗号 (RC4 など)、ハッシュ関数 (MD5 など)、Dual_EC_DRBG などの不十分な乱数生成器が含まれますが、これに限定されません。NIST などにより認定されたアルゴリズムは時間の経過とともにセキュアではなくなる可能性があることにも注意します。認定はアルゴリズムの堅牢性の定期的な検証に置き換えられるものではありません。これらはすべてセキュアではないとマークすべきであり、使用すべきではなく、アプリケーションコードベースから削除すべきです。

ソースコードを調査し、アプリケーション全体の暗号アルゴリズムのインスタンスを特定し、以下のような既知の脆弱なものを探します。

* DES, 3DES <sup>[6]</sup>
* RC2
* RC4
* BLOWFISH <sup>[6]</sup>
* MD4
* MD5
* SHA1 など

On Android (via Java Cryptography APIs), selecting an algorithm is done by requesting an instance of the `Cipher` (or other primitive) by passing a string containing the algorithm name. For example, `Cipher cipher = Cipher.getInstance("DES");`. On iOS, algorithms are typically selected using predefined constants defined in CommonCryptor.h, e.g., `kCCAlgorithmDES`. Thus, searching the source code for the presence of these algorithm names would indicate that they are used. Note that since the constants on iOS are numeric, an additional check needs to be performed to check whether the algorithm values sent to CCCrypt function map to one of the deprecated/insecure algorithms.

Other uses of cryptography require careful adherence to best practices:
* For encryption, use a strong, modern cipher with the appropriate, secure mode and a strong key. Examples:
    * 256-bit key AES in GCM mode (provides both encryption and integrity verification.)
    * 4096-bit RSA with OAEP padding.
    * 224/256-bit elliptic curve cryptography.
* Do not use known weak algorithms. For example:
    * AES in ECB mode is not considered secure, because it leaks information about the structure of the original data.
    * Several other AES modes can be weak.
* RSA with 768-bit and weaker keys can be broken. Older PKCS#1 padding leaks information.
* Rely on secure hardware, if available, for storing encryption keys, performing cryptographic operations, etc.

#### 改善方法

暗号化が廃止されたものではないことを定期的に確認します。かつては何年もの計算時間を要すると考えられていた一部の古いアルゴリズムは、数日または数時間で破られる可能性があります。これには以前は強力であると考えられていた MD4, MD5, SHA1, DES やその他のアルゴリズムが含まれます。現在推奨されるアルゴリズムの例です <sup>[1], [2]</sup> ：

* 機密性: AES-GCM-256, ChaCha20-Poly1305
* 完全性: SHA-256, SHA-384, SHA-512, Blake2
* デジタル署名: RSA (3072 ビット以上), ECDSA with NIST P-384
* 鍵共有: RSA (3072 ビット以上), DH (3072 ビット以上), ECDH with NIST P-384

#### 参考情報

##### OWASP Mobile Top 10
- M6 - Broken Cryptography

##### OWASP MASVS
- V3.3: "アプリは特定のユースケースに適した暗号化プリミティブを使用している。業界のベストプラクティスに基づくパラメータで構成されている。"
- V3.4: "アプリはセキュリティ上の目的で広く廃止対象と考えられる暗号プロトコルやアルゴリズムを使用していない。"

##### CWE
- CWE-326: Inadequate Encryption Strength
- CWE-327: Use of a Broken or Risky Cryptographic Algorithm

##### その他
- [1] Commercial National Security Algorithm Suite and Quantum Computing FAQ - https://cryptome.org/2016/01/CNSA-Suite-and-Quantum-Computing-FAQ.pdf
- [2] NIST Special Publication 800-57 - http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf
- [4] NIST recommendations (2016) - https://www.keylength.com/en/4/
- [5] BSI recommendations (2017) - https://www.keylength.com/en/8/
- [6] Sweet32 attack -- https://sweet32.info/

##### ツール
- QARK - https://github.com/linkedin/qark
- Mobile Security Framework - https://github.com/ajinabraham/Mobile-Security-Framework-MobSF


### 安全ではない暗号アルゴリズム設定と誤用に関するテスト

#### 概要

強力な暗号アルゴリズムを選択するだけでは十分ではありません。多くの場合、そのような堅牢なアルゴリズムのセキュリティはその構成により影響を受けることがあります。暗号アルゴリズムに対して最も顕著なものは使用される鍵長の選択です。

#### 静的解析

ソースコード解析を行い、以下のような検討されていない設定オプションをチェックすべきです。

* 暗号ソルト、少なくともハッシュ関数出力と同じ長さであるべきです
* * パスワード導出関数を使用する場合の反復カウントの合理的な選択
* ランダムかつユニークである IV
* 目的に合ったブロック暗号モード
* 適切に行われている鍵管理

#### 改善方法

使用されている鍵長が業界標準 <sup>[6]</sup> を満たしていることを定期的に確認します。

#### 参考情報

##### OWASP Mobile Top 10
- M6 - Broken Cryptography

##### OWASP MASVS
- V3.3: "アプリは特定のユースケースに適した暗号化プリミティブを使用している。業界のベストプラクティスに基づくパラメータで構成されている。"
- V3.4: "アプリはセキュリティ上の目的で広く廃止対象と考えられる暗号プロトコルやアルゴリズムを使用していない。"

##### CWE
- CWE-326: Inadequate Encryption Strength
- CWE-327: Use of a Broken or Risky Cryptographic Algorithm

##### その他
- [1] Commercial National Security Algorithm Suite and Quantum Computing FAQ - https://cryptome.org/2016/01/CNSA-Suite-and-Quantum-Computing-FAQ.pdf
- [2] NIST Special Publication 800-57 - http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf
- [3] Security "Crypto" provider deprecated in Android N -  https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html
- [4] NIST recommendations (2016) - https://www.keylength.com/en/4/
- [5] BSI recommendations (2017) - https://www.keylength.com/en/8/
- [6] ENISA Algorithms, key size and parameters report 2014 - https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014

##### ツール
- QARK - https://github.com/linkedin/qark
- Mobile Security Framework - https://github.com/ajinabraham/Mobile-Security-Framework-MobSF
- hashcat - https://hashcat.net/hashcat/
- hashID - https://pypi.python.org/pypi/hashID


### Testing for Hardcoded Cryptographic Keys

#### Overview

The security of symmetric encryption and keyed hashes (MACs) is highly dependent upon the secrecy of the used secret key. If the secret key is disclosed, the security gained by encryption/MACing is rendered naught.
This mandates, that the secret key is protected and should not be stored together with the encrypted data.

#### Static Analysis

The following checks would be performed against the used source code:

* Ensure that no keys/passwords are hard coded and stored within the source code. Pay special attention to any 'administrative' or backdoor accounts enabled in the source code. Storing fixed salt within application or password hashes may cause problems too.
* Ensure that no obfuscated keys or passwords are in the source code. Obfuscation is easily bypassed by dynamic instrumentation and in principle does not differ from hard coded keys.
* If the application is using two-way SSL (i.e. there is both server and client certificate validated) check if:
    * the password to the client certificate is not stored locally, it should be in the Keychain
    * the client certificate is not shared among all installations (e.g. hard coded in the app)
* if the app relies on an additional encrypted container stored in app data, ensure how the encryption key is used;
    * if key wrapping scheme is used, ensure that the master secret is initialized for each user, or container is re-encrypted with new key;
    * check how password change is handled and specifically, if you can use master secret or previous password to decrypt the container.

Mobile operating systems provide a specially protected storage area for secret keys, commonly named key stores or key chains. Those storage areas will not be part of normal backup routines and might even be protected by hardware means. The application should use this special storage locations/mechanisms for all secret keys.

#### Remediation
-- TODO --

#### References

##### OWASP Mobile Top 10

- M6 - Broken Cryptography

##### OWASP MASVS

- V3.1: "The app does not rely on symmetric cryptography with hardcoded keys as a sole method of encryption."

##### CWE

- CWE-321 - Use of Hard-coded Cryptographic Key

##### Info

- [1] iOS: Managing Keys, Certificates, and Passwords - https://developer.apple.com/library/content/documentation/Security/Conceptual/cryptoservices/KeyManagementAPIs/KeyManagementAPIs.html
- [2] Android: The Android Keystore System - https://developer.android.com/training/articles/keystore.html
- [3] Android: Hardware-backed Keystore - https://source.android.com/security/keystore/

##### Tools

-- TODO --


### Testing Key Generation Techniques

#### 概要

対称暗号化や MAC などの暗号アルゴリズムは 128 ビットや 256 ビットなどの所定のサイズの秘密の入力を期待しています。単純な実装ではユーザー提供のパスワードを入力鍵として直接使用することがあります。このアプローチにはいくつかの問題があります。

* パスワードが鍵より小さい場合、完全な鍵空間は使用されません (残りは多くの場合スペースで埋められます)。
* ユーザー提供のパスワードは現実的には大部分が表示可能かつ発音可能な文字で構成されます。したがって、完全なエントロピー (すなわち ASCII を使用する場合には 2<sup>8</sup>) ではなく、小さなサブセット (およそ 2<sup>6</sup>) のみが使用されます。
* 二人のユーザーが同じパスワードを選択した場合、攻撃者は暗号化されたファイルと一致させることができます。これはレインボーテーブル攻撃の可能性が広がります。

#### 静的解析

ソースコードを使用して、パスワードが暗号化機能に直接渡されていないことを確認します。

#### 改善方法

ユーザー提供のパスワードをソルトされたハッシュ関数もしくは KDF に渡します。その結果を暗号機能の鍵として使用します。

#### 参考情報

ユーザー提供のパスワードをソルトされたハッシュ関数もしくは KDF に渡します。その結果を暗号機能の鍵として使用します。

#### 参考情報

##### OWASP Mobile Top 10

- M6 - Broken Cryptography

##### OWASP MASVS

- V3.3: "アプリは特定のユースケースに適した暗号化プリミティブを使用している。業界のベストプラクティスに基づくパラメータで構成されている。"

##### CWE

-- TODO --

##### その他

- Wikipedia -- https://en.wikipedia.org/wiki/Key_stretching

##### ツール

- hashcat - https://hashcat.net/hashcat/
- hashID - https://pypi.python.org/pypi/hashID


### Testing Sensitive Data Protection

#### 概要

アプリケーションの攻撃領域は潜在的なすべての入力パスの合計として定義されます。よく忘れられる攻撃ベクトルにはクラウドストレージやローカルファイルストレージなどの安全でない場所に格納されたファイルがあります。

潜在的に安全でない場所に格納されているすべてのデータは完全性を保護すべきです。つまり、データが使用される前にアプリケーションが変更を検出することなく攻撃者がコンテンツを変更できてはいけません。

ほとんどの対策は格納されているデータのチェックサムを計算してから、データをインポートする前に取得したデータのチェックサムを比較することによって機能します。チェックサムやハッシュが安全でない場所にデータとともに格納されている場合、一般的なハッシュアルゴリズムは十分ではありません。それらは秘密鍵を持っていないため、格納されたデータを変更することができる攻撃者は容易にハッシュを再計算して新たに計算されたハッシュを格納することができます。

#### 静的解析

-- TODO --

使用されているアルゴリズムについてソースコードを確認します

#### 改善方法

完全性保護について2つの典型的な暗号対策があります。

* MAC (Message Authentication Codes, メッセージ認証コード、鍵付きハッシュとも呼ばれます) はハッシュと秘密鍵を結合します。MAC は秘密鍵が分かっている場合にのみ計算もしくは検証することができます。ハッシュとは対照的に、これは攻撃者が元のデータを改変した後、MAC を容易に計算できないことを意味します。これはアプリケーションが秘密鍵を独自のストレージに格納し、他の当事者がデータの信頼性を検証する必要がない場合に適しています。
* デジタル署名は公開鍵ベースのスキームです。単一の秘密鍵の代わりに、秘密鍵と公開鍵の組み合わせを使用します。署名は秘密鍵を利用して生成され、公開鍵を利用して検証することができます。MAC と同様に、攻撃者は新しい署名を簡単に作成できません。MAC とは対照的に、署名は秘密鍵を開示する必要なしで検証を可能にします。誰もが MAC の代わりに署名を使用しているのはなぜでしょう。主にパフォーマンス上の理由からです。

もうひとつの可能性として AEAD スキームを使用した暗号化の使用があります (「暗号化がデータの完全性保護を提供しているかどうかのテスト」を参照ください)。

#### 参考情報

##### OWASP Mobile Top 10

- M6 - Broken Cryptography

##### OWASP MASVS

- V3.3: "アプリは特定のユースケースに適した暗号化プリミティブを使用している。業界のベストプラクティスに基づくパラメータで構成されている。"

##### CWE

-- TODO --

##### その他

-- TODO --

##### ツール

-- TODO --


### Testing for Stored Passwords

#### Overview

Normal hashes are optimized for speed, e.g., optimized to verify large media in short time. For password storage this property is not desirable as it implies that an attacker can crack retrieved password hashes (using rainbow tables or through brute-force attacks) in a short time. For example, when the insecure MD5 hash has been used, an attacker with access to eight high-level graphics cards can test 200.3 Giga-Hashes per Second<sup>[1]</sup>.
A solution to this are Key-Derivation Functions (KDFs) that have a configurable calculation time. While this imposes a larger performance overhead this is negligible during normal operation but prevents brute-force attacks. Recently developed key derivation functions such as Argon2 or scrypt have been hardened against GPU-based password cracking.

#### Static Analysis

Use the source code to determine how the hash is calculated.

#### Remediation

Use an established key derivation function such as PBKDF2 (RFC 2898<sup>[5]</sup>), Argon2<sup>[4]</sup>, bcrypt<sup>[3]</sup> or scrypt (RFC 7914<sup>[2]</sup>).

#### References

##### OWASP Mobile Top 10

- M6 - Broken Cryptography

##### OWASP MASVS

- V3.3: "The app uses cryptographic primitives that are appropriate for the particular use-case, configured with parameters that adhere to industry best practices"
- V3.4: "The app does not use cryptographic protocols or algorithms that are widely considered depreciated for security purposes"

##### CWE

-- TODO --

##### Info

- [1] 8x Nvidia GTX 1080 Hashcat Benchmarks -- https://gist.github.com/epixoip/a83d38f412b4737e99bbef804a270c40
- [2] The scrypt Password-Based Key Derivation Function -- https://tools.ietf.org/html/rfc7914
- [3] A Future-Adaptable Password Scheme -- https://www.usenix.org/legacy/events/usenix99/provos/provos_html/node1.html
- [4] https://github.com/p-h-c/phc-winner-argon2
- [5] PKCS #5: Password-Based Cryptographic Specification Version 2.0 -- https://tools.ietf.org/html/rfc2898

##### Tools

- hashcat - https://hashcat.net/hashcat/
- hashID - https://pypi.python.org/pypi/hashID
