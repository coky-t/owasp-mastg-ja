## 暗号化のテスト

以下の章では MASVS の暗号化要件の技術的なテストケースを説明します。この章に記載されているテストケースは一般的な暗号の概念に基づいており、iOS や Android の特定の実装に依存していません。

適切な暗号システムの設計はモバイルアプリケーション開発での一般的な落とし穴です。適切なセキュリティを実現するには、開発者は適切な暗号化ディレクティブ (対称暗号化など) を選択し、そのディレクティブに対する適切な実装 (AES-GCM など) を選択し、その実装を正しく設定する (鍵長、ブロックモード、鍵管理など) 必要があります。この章では暗号の説明はしませんが、その質問は前述の選択と実装のプロセスで共通の問題を見つけるように設計されています。

この章では、複数の基本的な暗号化ビルディングブロックが使用されています。以下に一般的に言及されている概念を紹介します。

* ハッシュは元のデータに基づく固定長のチェックサムを迅速に計算するために使用されます。同じ入力データは同じ出力ハッシュを生成します。暗号学的ハッシュは、生成されたハッシュが元のデータについて推論することを制限すること、元のデータ内の小さな変更が完全に異なるハッシュを生成すること、ハッシュを取得して同じハッシュにつながる入力データを提供することが実現可能でないこと、を保証します。秘密鍵は使用されないため、攻撃者はデータが変更された後に新しいハッシュを再計算できます。
* 暗号化は元のプレーンテキストデータを暗号化されたテキストに変換して、その後暗号化されたテキスト (暗号テキストともいいます) から元のデータを再構築することを可能にします。したがってデータの機密性を提供します。
* 対称暗号化は秘密鍵を使用します。暗号化されたデータの機密性は機密鍵の機密性にのみ依存します。これは、秘密鍵は秘密でなければならず、したがって予測可能ではないことを意味します。
* 非対称暗号化は2つの鍵を使用します。プレーンテキストを暗号化するために使用できる公開鍵とプレーンテキストから元のデータを再構築するために使用できる秘密鍵です。

### 暗号のカスタム実装に関するテスト

#### 概要

非標準の暗号アルゴリズムやカスタムビルドの暗号アルゴリズムの使用は危険です。特定の攻撃者がアルゴリズムを破り、保護されているデータを侵害する可能性があります。暗号化機能の実装には時間がかかり、困難であり、失敗する可能性が非常に高くなります。代わりに既にセキュアであることが証明されている既知のアルゴリズムを使用すべきです。すべての成熟したフレームワークやライブラリはモバイルアプリを実装する際にも使用すべき暗号化機能を提供します。

#### 静的解析

ソースコードに含まれるすべての暗号手法、特に機密データに直接適用されている手法を注意深く調べます。一見標準のようにみえるが改変されたアルゴリズムに細心の注意を払います。エンコーディングは暗号化ではないことを忘れないでください。排他的 OR 演算などのビットシフト演算子が現れたら深く掘り下げてみる良い兆候かもしれません。

#### 動的解析

カスタム暗号化方式の使用について、APK を逆コンパイルして得られたソースコードを調べることをお勧めします(「静的解析」を参照ください)。

#### 改善方法

カスタム暗号アルゴリズムを開発してはいけません。これは暗号技術者によりよく知られている攻撃を受ける可能性が高いためです。その分野の専門家により現在強力であると考えられている十分に検証されたアルゴリズムを選択し、十分にテストされた実装を使用します。

#### 参考情報

##### OWASP Mobile Top 10 2016
* M6 - Broken Cryptography

##### OWASP MASVS
- V3.2: "アプリは実績のある暗号プリミティブの実装を使用している。"

##### CWE
* CWE-327: Use of a Broken or Risky Cryptographic Algorithm

##### その他
[1] Supported Ciphers in KeyStore - https://developer.android.com/training/articles/keystore.html#SupportedCiphers

### Testing for Insecure and/or Deprecated Cryptographic Algorithms

#### Overview

Many cryptographic algorithms and protocols should not be used because they have been shown to have significant weaknesses or are otherwise insufficient for modern security requirements. Previously thought secure algorithms may become insecure over time. It is therefore important to periodically check current best practices and adjust configurations accordingly.

#### Static Analysis

The source code should be checked that cryptographic algorithms are up to date and in-line with industry standards. This includes, but is not limited to outdated block ciphers (e.g. DES), stream ciphers (e.g. RC4), as well as hash functions (e.g. MD5) and broken random number generators like Dual_EC_DRBG. Please note, that an algorithm that was certified, e.g., by the NIST, can also become insecure over time. A certification does not replace periodic verification of an algorithm's soundness. All of these should be marked as insecure and should not be used and removed from the application code base.

Inspect the source code to identify the instances of cryptographic algorithms throughout the application, and look for known weak ones, such as:

* DES, 3DES<sup>[6]</sup>
* RC2
* RC4
* BLOWFISH<sup>[6]</sup>
* CRC32
* MD4
* MD5
* SHA1 and others.

Example initialization of DES algorithm, that is considered weak:
```Java
Cipher cipher = Cipher.getInstance("DES");
```

#### Dynamic Analysis

The recommended approach is be to decompile the APK and inspect the resulting source code for usage of custom encryption schemes (see "Static Analysis").

If you encounter locally stored data during the test, try to identify the used algorithm and verify them against a list of known insecure algorithms.

#### Remediation

Periodically ensure that the cryptography has not become obsolete. Some older algorithms, once thought to require years of computing time, can now be broken in days or hours. This includes MD4, MD5, SHA1, DES, and other algorithms that were once considered as strong. Examples of currently recommended algorithms<sup>[1] [2]</sup>:

* Confidentiality: AES-GCM-256 or ChaCha20-Poly1305
* Integrity: SHA-256, SHA-384, SHA-512, Blake2
* Digital signature: RSA (3072 bits and higher), ECDSA with NIST P-384
* Key establishment: RSA (3072 bits and higher), DH (3072 bits or higher), ECDH with NIST P-384

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
- [4] NIST recommendations (2016) - https://www.keylength.com/en/4/
- [5] BSI recommendations (2017) - https://www.keylength.com/en/8/
- [6] Sweet32 attack -- https://sweet32.info/

##### Tools
* QARK - https://github.com/linkedin/qark
* Mobile Security Framework - https://github.com/ajinabraham/Mobile-Security-Framework-MobSF

 
### If symmetric encryption or MACs are used, test for hard coded secret keys

#### Overview

The security of symmetric encryption and keyed hashes (MACs) is highly dependent upon the secrecy of the used secret key. If the secret key is disclosed, the security gained by encryption/MACing is rendered naught.

This mandates, that the secret key is protected and should not be stored together with the encrypted data.

#### Static Analysis

The following checks would be performed against the used source code:

* Ensure that no keys/passwords are hard coded and stored within the source code. Pay special attention to any 'administrative' or backdoor accounts enabled in the source code. Storing fixed salt within application or password hashes may cause problems too.
*
* Ensure that no obfuscated keys or passwords are in the source code. Obfuscation is easily bypassed by dynamic instrumentation and in principle does not differ from hard coded keys.
*
* If the application is using two-way SSL (i.e. there is both server and client certificate validated) check if:
   * the password to the client certificate is not stored locally, it should be in the Keychain
   * the client certificate is not shared among all installations (e.g. hard coded in the app)
* if the app relies on an additional encrypted container stored in app data, ensure how the encryption key is used;
   * if key wrapping scheme is used, ensure that the master secret is initialized for each user, or container is re-encrypted with new key;
   * check how password change is handled and specifically, if you can use master secret or previous password to decrypt the container.

Mobile operating systems provide a specially protected storage area for secret keys, commonly named key stores or key chains. Those storage areas will not be part of normal backup routines and might even be protected by hardware means. The application should use this special storage locations/mechanisms for all secret keys.

#### Dynamic Analysis

The recommended approach is be to decompile the APK and inspect the resulting source code for usage of custom encryption schemes (see "Static Analysis").

#### Remediation

-- TODO --

#### References

##### OWASP Mobile Top 10

* M6 - Broken Cryptography

##### OWASP MASVS

-- TODO --

##### CWE

-- TODO --

##### Info

* iOS: Managing Keys, Certificates, and Passwords -- https://developer.apple.com/library/content/documentation/Security/Conceptual/cryptoservices/KeyManagementAPIs/KeyManagementAPIs.html
* Android: The Android Keystore System -- https://developer.android.com/training/articles/keystore.html
* Android: Hardware-backed Keystore -- https://source.android.com/security/keystore/

##### Tools

-- TODO --

### Testing for Insecure Cryptographic Algorithm Configuration

#### Overview

Choosing strong cryptographic algorithm alone is not enough. Often security of otherwise sound algorithms can be affected through their configuration. Most prominent for cryptographic algorithms is the selection of their used key length.

#### Static Analysis

Through source code analysis the following non-exhausting configuration options should be checked:

* cryptographic salt, which should be at least the same length as hash function output
* * reasonable choice of iteration counts when using password derivation functions
* IVs being random and unique
* fit-for-purpose block encryption modes
* key management being done properly

#### Dynamic Analysis

If hashes were extracted during the analysis, and they have been configured in an insecure manner, a brute-force password cracking tool, e.g. hashcat, can be used to extract the original plain-text passwords from the encrypted hashes. Hashcat's wiki contains examples of cracking speeds for different algorithms, this can be utilized to estimate the effort that an attacker would have to recover plain-text passwords.

To utilize brute-force tools, the used hash algorithm (e.g., MD5 or SHA1) must be known. If this knowledge is not gathered during the Testing, tools like hashID can be used to automatically identify hash algorithms.

#### Remediation

Periodically ensure that used key length fulfill accepted industry standards<sup>[6]</sup>.

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
- [6] ENISA Algorithms, key size and parameters report 2014 - https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014

##### Tools
* QARK - https://github.com/linkedin/qark
* Mobile Security Framework - https://github.com/ajinabraham/Mobile-Security-Framework-MobSF
* hashcat - https://hashcat.net/hashcat/
* hashID - https://pypi.python.org/pypi/hashID

### Testing for Usage of ECB Mode

#### Overview

As the name implies, block-based encryption is performed upon discrete input blocks, e.g., 128 bit blocks when using AES. If the plain-text is larger than the block-size, it is internally split up into blocks of the given input size and encryption is performed upon each block. The so called block mode defines, if the result of one encrypted block has any impact upon subsequently encrypted blocks.

The ECB (Electronic Codebook) encryption mode should not be used, as it is basically divides the input into blocks of fixed size and each block is encrypted separately<sup>[6]</sup>. For example, if an image is encrypted utilizing the ECB block mode, then the input image is split up into multiple smaller blocks. Each block might represent a small area of the original image. Each of which is encrypted using the same secret input key. If input blocks are similar, e.g., each input block is just a white background, the resulting encrypted output block will also be the same. While each block of the resulting encrypted image is encrypted, the overall structure of the image will still be recognizable within the resulting encrypted image.

![Electronic Codebook (ECB mode encryption)](Images/Chapters/0x07c/ECB.png)

![Difference of encryption modes](Images/Chapters/0x07c/EncryptionMode.png)

#### Static Analysis

Use the source code to verify the used blcok mode. Especially check for ECB mode, e.g.:

```
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
```

#### Dynamic Analysis

Test encrypted data for reoccuring patterns -- those can be an indication of ECB mode being used.

#### Remediation

Use an established block mode that provides a feedback mechanism for subsequent blocks, e.g. Counter Mode (CTR). For storing encrypted data it is often advisable to use a block mode that additionally protects the integrity of the stored data, e.g. Galois/Counter Mode (GCM). The latter has the additional benefit that the algorithm is mandatory for each TLSv1.2 implementation -- thus being available on all modern plattforms.

Consult the NIST guidelines on block mode selection<sup>[1]</sup>.

#### References

##### OWASP Mobile Top 10
* M6 - Broken Cryptography

##### OWASP MASVS
- V3.3: "The app uses cryptographic primitives that are appropriate for the particular use-case, configured with parameters that adhere to industry best practices"

##### CWE
* CWE-326: Inadequate Encryption Strength
* CWE-327: Use of a Broken or Risky Cryptographic Algorithm

##### Info

- [1] NIST Modes Development, Proposed Modes - http://csrc.nist.gov/groups/ST/toolkit/BCM/modes_development.html
- [6] Electronic Codebook (ECB) - https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_.28ECB.29

##### Tools
* QARK - https://github.com/linkedin/qark
* Mobile Security Framework - https://github.com/ajinabraham/Mobile-Security-Framework-MobSF



### Testing if anything but a KDF (key-derivation function) is used for storing passwords

#### Overview

Normal hashes are optimized for speed, e.g., optimized to verify large media in short time. For password storage this property is not desirable as it implies that an attacker can crack retrieved password hashes (using rainbow tables or through brute-force attacks) in a short time. For example, when the insecure MD5 hash has been used, an attacker with access to eight high-level graphics cards can test 200.3 Giga-Hashes per Second<sup>[1]</sup>.

A solution this are Key-Derivation Functions (KDFs) that have a configurable calculation time. While this imposes a larger performance overhead this is negligible during normal operation but prevents brute-force attacks. Recently developed key derivation functions such as Argon2 or scrypt have been hardened against GPU-based password cracking.

#### Static Analysis

Use the source code to determine how the hash is calculated, an exmaple of an insecure instantiation would be:

```
MessageDigest md = MessageDigest.getInstance("MD5");
md.updat("too many secrets");
byte[] digest = md.digest();
```

#### Dynamic Analysis

If hashes were extracted and they have been configured in an insecure manner, a brute-force password cracking tool, e.g. hashcat, can be used to extract the original plain-text passwords from the encrypted hashes. Hashcat's wiki contains examples of cracking speeds for different algorithms, this can be utilized to estimate the effort that an attacker would have to recover plain-text passwords.

To utilize brute-force tools, the used hash algorithm (e.g., MD5 or SHA1) must be known. If this knowledge is not gathered during the Testing, tools like hashID can be used to automatically identify hash algorithms.

#### Remediation

Use an established key derivation function such as PBKDF2 (RFC 2898<sup>[5]</sup>), Argon2<sup>[4]</sup>, bcrypt<sup>[3]</sup> or scrypt (RFC 7914<sup>[2]</sup>).

#### References

##### OWASP Mobile Top 10

* M6 - Broken Cryptography

##### OWASP MASVS

- V3.3: "The app uses cryptographic primitives that are appropriate for the particular use-case, configured with parameters that adhere to industry best practices"
- V3.4: "The app does not use cryptographic protocols or algorithms that are widely considered depreciated for security purposes"

##### CWE

-- TODO --

##### Info

[1] 8x Nvidia GTX 1080 Hashcat Benchmarks -- https://gist.github.com/epixoip/a83d38f412b4737e99bbef804a270c40
[2] The scrypt Password-Based Key Derivation Function -- https://tools.ietf.org/html/rfc7914
[3] A Future-Adaptable Password Scheme -- https://www.usenix.org/legacy/events/usenix99/provos/provos_html/node1.html
[4] https://github.com/p-h-c/phc-winner-argon2
[5] PKCS #5: Password-Based Cryptographic Specification Version 2.0 -- https://tools.ietf.org/html/rfc2898

##### Tools

* hashcat - https://hashcat.net/hashcat/
* hashID - https://pypi.python.org/pypi/hashID

### Test if user-supplied credentials are not directly used as key material

#### Overview

Cryptographic algorithms -- such as symmetric encryption or MACs -- expect a secret input of a a given size, e.g. 128 or 256 bit. A naive implementation might use the use-supplied password directly as an input key. There are a couple of problems with this approach:

* if the password is smaller than the key, then not the full key-space is used (the rest is padded, sometimes even with spaces)
* A user-supplied password will realistically consist mostly of display- and pronounce-able characters. So instead of the full entropy, i.e. 2<sup>8</sup> when using ASCII, only a small subset is (approx. 2<sup>6</sup>) is used.
* If two users select the same password an attacker can match the encrypted files. This opens up the possibility of rainbow table attacks.

#### Static Analysis

Use the source code to verify that no password is directly passed into an encryption function, e.g.:


```
String userKeyString = "trustno1"; // given by user
byte[] userKeyByte = userKeyString.getBytes();
byte[] validKey = new byte[16]; // needed input key, filled with 0

System.arraycopy(userKeyByte, 0, validKey, 0, (userKeyByte.length > 16) ? 16 : userKeyByte.length));

Key theAESKEy = new SecretKeySpec(validKey, "AES");
```

#### Dynamic Analysis

Test extrated hashes as within "Testing if anything but a KDF (key-derivation function) is used for storing passwords". If no hash or KDF has been used, brute-force attacks or attacks using dictionaries will be more efficient due to the reduced key space.

#### Remediation

Pass the user-supplied password into a salted hash funcation or KDF; use its resuls as key for the cryptographic function.

#### References

##### OWASP Mobile Top 10

* M6 - Broken Cryptography

##### OWASP MASVS

- V3.3: "The app uses cryptographic primitives that are appropriate for the particular use-case, configured with parameters that adhere to industry best practices"

##### CWE

-- TODO --

##### Info

* Wikipedia -- https://en.wikipedia.org/wiki/Key_stretching

##### Tools

* hashcat - https://hashcat.net/hashcat/
* hashID - https://pypi.python.org/pypi/hashID

### Test if sensitive data is integrity protected

#### Overview

The attack surface of an application is defined as the sum of all potential input paths. An often forgotten attack vector are files stored on insecure locations, e.g., cloud storage or local file storage.

All data that is stored on potential insecure locations should be integrity protected, i.e., an attacker should not be able to change their content without the application detecting the change prior to the data being used.

Most countermeasures work by calculating a checksum for the stored data, and then by comparing the checksum with the retrieved data prior to the data's import. If the checksum/hash is stored with the data on the insecure location, typical hash algorithms will not be sufficient. As they do not posess a secret key, an attacker that is able to change the stored data, can easily recalculate the hash and store the newly calculated hash.

#### Static Analysis

-- TODO --

* check source code for used algorithm

#### Dynamic Analysis

-- TODO --


#### Remediation

Two typical cryptographic counter-measures for integrity protection are:

* MACs (Message Authentication Codes, also known as keyed hashes) combine hashes with a secret key. The MAC can only be calculated or verified if the secret key is known. In contrast to hashes this means, that an attacker cannot easily calculate a MAC after the original data was modified. This is well suited, if the application can store the secret key within its own storage and no other party needs to verify the authenticity of the data.

* Digital Signatures are a public key-based scheme where, instead of a single secret key, a combination of a secret private key and a a public key is sued. The signature is created utilizing the secret key and can be verified utilizing the public key. Similar to MACs, an attacker cannot easily create a new signature. In contrast to MACs, signatures allow verification without needed to disclose the secret key. Why is not everyone using Signatures instead of MACs? Mostly for performance reasons.

* Another possibility is the usage of encryption using AEAD schemes (see "Test if encryption provides data integrity protection")

#### References

##### OWASP Mobile Top 10

* M6 - Broken Cryptography

##### OWASP MASVS

- V3.3: "The app uses cryptographic primitives that are appropriate for the particular use-case, configured with parameters that adhere to industry best practices"

##### CWE

-- TODO --

##### Info

-- TODO --

##### Tools

-- TODO --


### Test if encryption provides data integrity protection

#### Overview

Please note that, encryption does not provide data integrity, i.e., if an attacker modifies the cipher text and a user decrypts the modified cipher text, the resulting plain-text will be garbage (but the decryption operation itself will perform successfully).

A good example for an symmetric algorithm that does not protect integrity is One-Time-Pad. This algorithm XORs the input data with a secret input key. This leads to a cipher text which's data confidenciality is information theoretical secure -- i.e. even an attacker with unlimited processing power would not be able to crack the encryption. But data integrity is not protected.

For example, image that you have a message with an amount of money to be transfered. Let the amount be 1000 Euro/Dollars, which would be `0x0011 1110 1000` the secret key that you are using is `0x0101 0101 0101` (not very random, I know). XORing those two leads to a transfered message of `0x0110 1011 1101`. The attacker has no idea of knowning the plain-text. But she imagines that normally a low amount of money is transfered and bit-flips the highest bit of the message, making it `0x1110 1011 1101`. The victim now retrieves the message, decrypts it through XORing it with the secret key and has retrieved the value of `0x1011 1110 1000` which amounts to 3048 Euro/Dollars. So while the attacker was not able to break the encryption, she was able to change the undelying message as the underlying message was not integrity protected.

#### Static Analysis

-- TODO --

* check source code for used algorithm

#### Dynamic Analysis

-- TODO [Give examples of Dynamic Testing for "Testing for Insecure and/or Deprecated Cryptographic Algorithms"] --

#### Remediation

The cryptographic method that secures encrypted data is unsurprisingly called Authenticated Encryption<sup>[1]</sup>. The basic primitive used for creating the checksum is a MAC (also known as keyed hash). The exact selection what data is MACed (plain-text or cipher-text) is highly complex<sup>[2]</sup>.

It is recommended to use an AEAD scheme for integrity-protecting encryption such as AES-GCM.

#### References

##### OWASP Mobile Top 10

* M6 - Broken Cryptography

##### OWASP MASVS

- V3.3: "The app uses cryptographic primitives that are appropriate for the particular use-case, configured with parameters that adhere to industry best practices"

##### CWE

-- TODO --

##### Info

* [1] Wikipedia: Authenticated Encryption -- https://en.wikipedia.org/wiki/Authenticated_encryption
* [2] Luck Thirteen: Breaking the TLS and DTLS Record Protocols -- http://www.isg.rhul.ac.uk/tls/TLStiming.pdf

##### Tools

-- TODO --
