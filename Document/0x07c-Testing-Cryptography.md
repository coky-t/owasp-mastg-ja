## 暗号化のテスト

以下の章ではテクニカルテストケースでの MASVS の暗号化要件について説明します。この章に記載されるテストケースはサーバー側に焦点を当てているため、iOS や Android の特定の実装に依存しません。

適切な暗号鍵管理はモバイルアプリケーションを設計する際の共通の落とし穴です。

暗号システムはさまざまなビルディングブロックで構成されています。重要なのはビルディングブロックを意図した方法で使用することです (加えて、最新のセキュアなビルディングブロックとセキュアな構成を使用します) 。

一般的に遭遇するビルディングブロックは以下のとおりです。

* ハッシュは元のデータに基づく固定長のチェックサムを迅速に計算するために使用されます。同じ入力データは同じ出力ハッシュを生成します。暗号学的ハッシュは、生成されたハッシュが元のデータについて推論することを制限すること、元のデータ内の小さな変更が完全に異なるハッシュを生成すること、ハッシュを取得してあらかじめ決定されたハッシュとなる元のデータを取得することが困難であること、を保証します。秘密鍵は使用されないため、攻撃者はデータが変更された後に新しいハッシュを再計算できます。
* 暗号化はプレーンテキストデータを暗号化されたテキストに変換して、その後暗号化されたテキスト (暗号テキストしても知られています) から元のデータを再構築することを可能にします。したがってデータの機密性を提供します。暗号化はデータの完全性を提供しないことに注意します。つまり、攻撃者が暗号テキストを改変して、ユーザーが改変された暗号テキストを復号した場合、得られたプレーンテキストはがらくたです (ただし復号化操作自体は正常に実行されます) 。
* 対称暗号化は秘密鍵を使用します。暗号化されたデータの機密性は機密鍵の機密性にのみ依存します。
* 非対称暗号化は2つの鍵を使用します。プレーンテキストを暗号化するために使用できる公開鍵とプレーンテキストから元のデータを再構築するために使用できる秘密鍵です。

### 安全でないもしくは廃止された暗号化アルゴリズムに関するテスト

#### 概要

多くの暗号アルゴリズムおよびプロトコルは重大な弱点があることが示されているか、現代のセキュリティ要件には不十分であるため、使用してはいけません。以前はセキュアであると考えられていたアルゴリズム時間の経過とともにセキュアではなくなる可能性があります。したがって最新のベストプラクティスを定期的に確認し、それに応じて構成を調整することが重要です。

#### 静的解析

以下のリストはソースコードの暗号アルゴリズムの使用を検証するためのさまざまなチェックを示しています。

* 暗号アルゴリズムは最新のもので業界標準に準拠している。これには、古いブロック暗号 (DES など)、ストリーム暗号 (RC4 など)、ハッシュ関数 (MD5 など)、(NIST 認定であっても) Dual_EC_DRBG などの不十分な乱数生成器などがあります。これらはすべて非セキュアであるとマークされ、使用すべきではなく、アプリやサーバーのコードベースから削除すべきです。
* 暗号パラメータは妥当な範囲内で十分に定義されている。これには、ハッシュ関数出力と少なくとも同じ長さであるべき暗号ソルト、パスワード導出関数と反復回数の妥当な選択肢 (PBKDF2, scrypt, bcrypt など)、ランダムでユニークな IV、適切なブロック暗号モード (ECV は特定のケースを除いて使用すべきではないなど)、適切な鍵管理 (3DES は3つの独立した鍵を持つべきであるなど) など。

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

暗号化手法が廃止されていないことを定期的に確認します。以前、年単位の計算時間を要すると考えられていた一部の古いアルゴリズムは数日もしくは数時間で破られる可能性があります。これには MD4, MD5, SHA1, DES, および以前は強力であると考えられて他のアルゴリズムが含まれます。現在推奨されているアルゴリズムの例です。<sup>[1] [2]</sup>

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
- [4] NIST recommendations (2016) - https://www.keylength.com/en/4/
- [5] BSI recommendations (2017) - https://www.keylength.com/en/8/

##### ツール
* QARK - https://github.com/linkedin/qark
* Mobile Security Framework - https://github.com/ajinabraham/Mobile-Security-Framework-MobSF




### Testing for Insecure Cryptographic Algorihm Configuration

#### Overview

Choosing strong cryptographic algorithm alone is not enough. Often security of otherwise sound algorithms can be affected if misconfigured.

#### Static Analysis

The following list shows different checks to validate the usage of cryptographic algorithms in source code:

* Key lengths are in-line with industry standards and provide protection for sufficient amount of time. An online comparison of different key lengths and protection they provide taking into account Moore's law is available online<sup>[3]</sup>.
* Cryptographic parameters are well defined within reasonable range. This includes, but is not limited to: cryptographic salt, which should be at least the same length as hash function output, reasonable choice of password derivation function and iteration count (e.g. PBKDF2, scrypt or bcrypt), IVs being random and unique, fit-for-purpose block encryption modes (e.g. ECB should not be used, except specific cases), key management being done properly (e.g. 3DES should have three independent keys) and so on.

#### Dynamic Analysis

-- TODO [Give examples of Dynamic Testing for "Testing for Insecure and/or Deprecated Cryptographic Algorithms"] --

#### Remediation

Periodically ensure that used key length fulfill accepted industry standards.

#### References

##### OWASP Mobile Top 10
* M6 - Broken Cryptography

##### OWASP MASVS
- V3.3: "The app uses cryptographic primitives that are appropriate for the particular use-case, configured with parameters that adhere to industry best practices"
- V3.4: "The app does not use cryptographic protocols or algorithms that are widely considered depreciated for security purposes"

##### CWE
* CWE-326: Inadequate Encryption Strength
* CWE-327: Use of a Broken or Risky Cryptographic Algorithm

##### Info
- [1] Commercial National Security Algorithm Suite and Quantum Computing FAQ - https://cryptome.org/2016/01/CNSA-Suite-and-Quantum-Computing-FAQ.pdf
- [2] NIST Special Publication 800-57 - http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf
- [3] Security "Crypto" provider deprecated in Android N -  https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html
- [4] NIST recommendations (2016) - https://www.keylength.com/en/4/
- [5] BSI recommendations (2017) - https://www.keylength.com/en/8/

##### Tools
* QARK - https://github.com/linkedin/qark
* Mobile Security Framework - https://github.com/ajinabraham/Mobile-Security-Framework-MobSF



### 暗号のカスタム実装に関するテスト

#### 概要

暗号機能に非標準のカスタムビルドアルゴリズムを使用することは危険です。特定の攻撃者がアルゴリズムを破り、保護されているデータを侵害する可能性があります。暗号化機能の実装には時間がかかり、困難であり、失敗する可能性があります。代わりに既にセキュアであることが証明されている既知のアルゴリズムを使用すべきです。すべての成熟したフレームワークやライブラリはモバイルアプリを実装する際にも使用すべき暗号化機能を提供します。

#### 静的解析

ソースコードに含まれるすべての暗号手法、特に機密データに直接適用されている手法を注意深く調べます。一見標準のようにみえるが改変されたアルゴリズムに細心の注意を払います。エンコーディングは暗号化ではないことを忘れないでください。排他的 OR オペレーションなどのビットシフトオペレータが現れたら深く掘り下げてみる良い兆候かもしれません。

#### 動的解析

カスタム暗号化方式が本当に適切かどうか確認するために、APK を逆コンパイルしてアルゴリズムを調べることをお勧めします(「静的解析」を参照ください)。

#### 改善方法

カスタム暗号アルゴリズムを開発してはいけません。これは暗号技術者によりよく知られている攻撃を受ける可能性が高いためです。

#### 参考情報

##### OWASP Mobile Top 10 2016
* M6 - Broken Cryptography

##### OWASP MASVS
- V3.2: "アプリは実績のある暗号プリミティブの実装を使用している。"

##### CWE
* CWE-327: Use of a Broken or Risky Cryptographic Algorithm

##### その他
[1] Supported Ciphers in KeyStore - https://developer.android.com/training/articles/keystore.html#SupportedCiphers




### Testing for Usage of ECB Mode

#### Overview

-- TODO: write Introduction --

ECB (Electronic Codebook) encryption mode should not be used, as it is basically a raw cipher. A message is divided into blocks of fixed size and each block is encrypted separately<sup>[6]</sup>.

![Electronic Codebook (ECB mode encryption)](Images/Chapters/0x07c/ECB.png)

The problem with this encryption method is that any resident properties of the plaintext might well show up in the cipher text, just possibly not as clearly. That's what blocks and key schedules are supposed to protect against, but analyzing the patterns you may be able to deduce properties that you otherwise thought were hidden.

![Difference of encryption modes](Images/Chapters/0x07c/EncryptionMode.png)

#### Static Analysis

The following list shows different checks to validate the usage of cryptographic algorithms in source code:

-- TODO --

See "Remediation" section for a basic list of recommended algorithms.

#### Dynamic Analysis

-- TODO [Give examples of Dynamic Testing for "Testing for Insecure and/or Deprecated Cryptographic Algorithms"] --

#### Remediation

-- TODO --

Periodically ensure that the cryptography has not become obsolete. Some older algorithms, once thought to require years of computing time, can now be broken in days or hours. This includes MD4, MD5, SHA1, DES, and other algorithms that were once considered as strong. Examples of currently recommended algorithms<sup>[1] [2]</sup>:

#### References

##### OWASP Mobile Top 10
* M6 - Broken Cryptography

##### OWASP MASVS
- V3.3: "The app uses cryptographic primitives that are appropriate for the particular use-case, configured with parameters that adhere to industry best practices"
- V3.4: "The app does not use cryptographic protocols or algorithms that are widely considered depreciated for security purposes"

##### CWE
* CWE-326: Inadequate Encryption Strength
* CWE-327: Use of a Broken or Risky Cryptographic Algorithm

##### Info
- [1] Commercial National Security Algorithm Suite and Quantum Computing FAQ - https://cryptome.org/2016/01/CNSA-Suite-and-Quantum-Computing-FAQ.pdf
- [2] NIST Special Publication 800-57 - http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf
- [6] Electronic Codebook (ECB) - https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_.28ECB.29

##### Tools
* QARK - https://github.com/linkedin/qark
* Mobile Security Framework - https://github.com/ajinabraham/Mobile-Security-Framework-MobSF



### Testing if anything but a KDF (key-derivation function) is used for storing passwords

#### Overview

-- TODO: write Introduction --

* move text from generic description to this section
* describe hashes vs key-derivation-function
*
* Key Derivation Functions (KDFs): normal hashes are optimized for speed, e.g., optimized to verify large media in short time. For password storage this property is not desirable as it implies that an attacker can crack retrieved password hashes (using rainbow tables or through brute-force attacks) in a short time. A solution this are Key-Derivation Functions (KDFs) that have a configurable calculation time. While this imposes a larger performance overhead this is neglectable during normal operation but prevents brute-force attacks.

#### Static Analysis

-- TODO --

* check source code for used algorithm

#### Dynamic Analysis

-- TODO [Give examples of Dynamic Testing for "Testing for Insecure and/or Deprecated Cryptographic Algorithms"] --

* check extracted hashes with ocl hashcat

#### Remediation

-- TODO --

* use bcrypt/scrypt

#### References

##### OWASP Mobile Top 10

-- TODO --

##### OWASP MASVS

-- TODO --

##### CWE

-- TODO --

##### Info

-- TODO --

* link to oclhashcat performance values

##### Tools

-- TODO --

* link to ocl hashcat



### Test if user-supplied credentials are not directly used as key material

#### Overview

-- TODO: write Introduction --

* sometimes a password is directly used as key for cryptographic functions
* sometimes it is even filled with spaces to achieve the cryptographic' algorithm's requirements

#### Static Analysis

-- TODO --

* check source code for used algorithm

#### Dynamic Analysis

-- TODO [Give examples of Dynamic Testing for "Testing for Insecure and/or Deprecated Cryptographic Algorithms"] --

* check extracted hashes with ocl hashcat

#### Remediation

-- TODO --

* use password as input data for a secure hashing function
* this improves the keyspace of the selected cryptographic function

#### References

##### OWASP Mobile Top 10

-- TODO --

##### OWASP MASVS

-- TODO --

##### CWE

-- TODO --

##### Info

-- TODO --

* link to oclhashcat performance values

##### Tools

-- TODO --

* link to ocl hashcat


### Test if sensitive data is integrity protected

#### Overview

-- TODO: write Introduction --


* MACs (Message Authentication Codes, also known as keyed hashes) combine hashes with a secret key. The MAC can only be calculated or verified if the secret key is known. In contrast to hashes this means, that an attacker cannot easily calculate a MAC after the original data was modified.
* Digital Signatures are a public key-based scheme where, instead of a single secret key, a combination of a secret private key and a a public key is sued. The signature is created utilizing the secret key and can be verified utilizing the public key. Similar to MACs, an attacker cannot easily create a new signature. In contrast to MACs, signatures allow verification without needed to disclose the secret key. Why is not everyone using Signatures instead of MACs? Mostly for performance reasons.

* maybe mention the whole mac-then-encrypt vs encrypt-then-mac problems
*
#### Static Analysis

-- TODO --

* check source code for used algorithm

#### Dynamic Analysis

-- TODO --


#### Remediation

-- TODO --

* use integrity-preserving encryption
* use AEAD based encryption for data storage (provides confidenciality as well as integrity protection)
* use digital signatures

#### References

##### OWASP Mobile Top 10

-- TODO --

##### OWASP MASVS

-- TODO --

##### CWE

-- TODO --

##### Info

-- TODO --

##### Tools

-- TODO --


### Test if encryption provides data integrity protection

#### Overview

-- TODO: write Introduction --

* encryption only protects data confidenciality, not integrity
* e.g., bit-flip attacks are possible

#### Static Analysis

-- TODO --

* check source code for used algorithm

#### Dynamic Analysis

-- TODO [Give examples of Dynamic Testing for "Testing for Insecure and/or Deprecated Cryptographic Algorithms"] --

#### Remediation

-- TODO --

* use integrity-preserving encryption
* maybe mention the whole mac-then-encrypt vs encrypt-then-mac problems
* use AEAD based encryption for data storage (provides confidenciality as well as integrity protection)

#### References

##### OWASP Mobile Top 10

-- TODO --

##### OWASP MASVS

-- TODO --

##### CWE

-- TODO --

##### Info

-- TODO --

##### Tools

-- TODO --




### if symmetric encryption or MACs are used, test for hard coded secret keys

#### Overview

-- TODO: write Introduction --

The following checks would be performed in the last two app categories:

* Ensure that no keys/passwords are hardcoded and stored within the source code. Pay special attention to any 'administrative' or backdoor accounts enabled in the source code. Storing fixed salt within application or password hashes may cause problems too.
* Ensure that no obfuscated keys or passwords are in the source code. Obfuscation is easily bypassed by dynamic instrumentation and in principle does not differ from hardcoded keys.
* If the application is using two-way SSL (i.e. there is both server and client certificate validated) check if:
   * the password to the client certificate is not stored locally, it should be in the Keychain
   * the client certificate is not shared among all installations (e.g. hardcoded in the app)


The following checks would be performed in the offline application:

* if the app relies on an additional encrypted container stored in app data, ensure how the encryption key is used;
   * if key wrapping scheme is used, ensure that the master secret is initialized for each user, or container is re-encrypted with new key;
   * check how password change is handled and specifically, if you can use master secret or previous password to decrypt the container.


#### Static Analysis

-- TODO --

* check source code for used key strings
* check property files for used keys
* check files for used keys

A proper way would be to generate the client certificate upon user registration/first login and then store it in the Keychain.

* Ensure that the keys/passwords/logins are not stored in application data. This can be included in the iTunes backup and increase attack surface. Keychain is the only appropriate place to store credentials of any type (password, certificate, etc.).
* Ensure that keychain entries have appropriate protection class. The most rigorous being `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` which translates to: entry unlocked only if passcode on the device is set and device is unlocked; the entry is not exportable in backups or by any other means.
*
#### Dynamic Analysis

-- TODO [Give examples of Dynamic Testing for "Testing for Insecure and/or Deprecated Cryptographic Algorithms"] --

* reverse engineer source code, then do the same

#### Remediation

-- TODO --

#### References

##### OWASP Mobile Top 10

-- TODO --

##### OWASP MASVS

-- TODO --

##### CWE

-- TODO --

##### Info

-- TODO --

##### Tools

-- TODO --
