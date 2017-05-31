## 暗号化のテスト (iOS アプリ)

### ハードコードされた暗号鍵のテスト

#### 概要

-- TODO [Note: The content originally found in this test case was moved to 0x07c - Testing cryptography. This test case should pertain only to finding hardcoded keys on iOS (how are they typically used and stored,... )] --

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

#### 動的解析

-- TODO [Describe how to test for this issue "Verifying Cryptographic Key Management" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Verifying Cryptographic Key Management".] --

#### 参考情報

##### OWASP Mobile Top 10 2016
* M5 - 不十分な暗号化 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M5-Insufficient_Cryptography

##### OWASP MASVS
* V3.1: "アプリは暗号化の唯一の方法としてハードコードされた鍵による対称暗号化に依存していない。"
* V3.5: "アプリは複数の目的のために同じ暗号化鍵を再利用していない。"

##### CWE
* CWE-320: Key Management Errors
* CWE-321: Use of Hard-coded Cryptographic Key

##### その他
- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### ツール

-- TODO [Add links to relevant tools] --

### 暗号化標準アルゴリズムの構成の検証

#### 概要

Apple は最も一般的に使用される暗号アルゴリズムの実装でのライブラリを提供しています。Apple の Cryptographic Services Guide <sup>[1]</sup> が参考になります。標準ライブラリを使用して暗号プリミティブを初期化および使用する方法に関する広範囲なドキュメントが含まれています。これはソースコード解析を実行する場合にも便利です。
動的テストでは、暗号操作を実行する際に最も頻繁に使用される CommonCryptor などのネイティブ C API がより便利です。ソースコードは Apple Open Source リポジトリ <sup>[2]</sup> で部分的に利用可能です。

#### 静的解析

静的解析の主な目的は以下を確認することです。

* 暗号アルゴリズムは最新のものであり業界標準に準拠している。これには古いブロック暗号(DESなど)、ストリーム暗号(RC4など)、ハッシュ関数(MD5など)、Dual_EC_DRBG などの破られた乱数生成器などが(NIST認定されているものも)あります。これらはすべて安全でないとマークされ、使用すべきではなく、アプリケーションやサーバーから削除される必要があります。
* 鍵長は業界標準に準拠しており、十分な時間の保護を提供している。ムーアの法則を考慮した、さまざまな鍵長や保護機能のオンライン比較はオンライン <sup>[3]</sup> を参照ください。
* 暗号パラメータは合理的な範囲で明確に定義されている。これには次を含みますが、これに限定されません。暗号ソルト(ハッシュ関数出力と少なくとも同じ長さである必要がある)、パスワード導出関数および反復カウントの合理的な選択(PBKDF2, scrypt, bcrypt など)、IV がランダムかつユニークである、目的に沿ったブロック暗号化モード(特定の場合を除いて ECB を使用すべきではないなど)、鍵管理が適切に行われている(3DES は3つの独立した鍵を持つなど)、など。

アプリが Apple により提供される標準的な暗号実装を使用している場合、最も簡単な方法はアプリケーションを逆コンパイルし、`CCCrypt`, `CCCryptorCreate` などの `CommonCryptor` から関数への呼び出しををチェックすることです。ソースコード <sup>[4]</sup> にはすべての関数の署名が含まれています。
例えば、`CCCryptorCreate` は以下のシグネチャを持っています。
```
CCCryptorStatus CCCryptorCreate(
	CCOperation op,             /* kCCEncrypt, etc. */
	CCAlgorithm alg,            /* kCCAlgorithmDES, etc. */
	CCOptions options,          /* kCCOptionPKCS7Padding, etc. */
	const void *key,            /* raw key material */
	size_t keyLength,
	const void *iv,             /* optional initialization vector */
	CCCryptorRef *cryptorRef);  /* RETURNED */
```

すべての `enum` 型を比較して、どのアルゴリズム、パディング、鍵マテリアルが使用されているかを理解することができます。(悪い)パスワードが直接入力された場合や、鍵生成機能(PBKDF2など)から入力された場合は、鍵マテリアルに注意します。
明らかに、アプリケーションが使用している可能性がある他の非標準のライブラリ(`openssl`など)がある場合、それらもチェックします。

#### 動的解析

-- TODO [Describe how to test for this issue "Verifying the Configuration of Cryptographic Standard Algorithms" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Verifying the Configuration of Cryptographic Standard Algorithms".] --

#### 参考情報

##### OWASP Mobile Top 10 2016
* M5 - 不十分な暗号化 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M5-Insufficient_Cryptography

##### OWASP MASVS
* V3.3: "アプリは特定のユースケースに適した暗号化プリミティブを使用している。業界のベストプラクティスに基づくパラメータで構成されている。"
* V3.4: "アプリはセキュリティ上の目的で広く廃止対象と考えられる暗号プロトコルやアルゴリズムを使用していない。"

##### CWE
-- TODO [Add relevant CWE for "Verifying the Configuration of Cryptographic Standard Algorithms"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

* [1] Apple Cryptographic Services Guide - https://developer.apple.com/library/content/documentation/Security/Conceptual/cryptoservices/GeneralPurposeCrypto/GeneralPurposeCrypto.html
* [2] Apple Open Source - https://opensource.apple.com
* [3] Keylength comparison - https://www.keylength.com/
* [4] CommonCryptoer.h - https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h

##### ツール

-- TODO [Add links to relevant tools for "Verifying the Configuration of Cryptographic Standard Algorithms"] --
* Enjarify - https://github.com/google/enjarify


### 乱数生成器のテスト

#### 概要

It is fundamentally impossible to produce truly random numbers on any deterministic device. Pseudo-random number generators (RNG) compensate for this by producing a stream of pseudo-random numbers - a stream of numbers that *appear* as if they were randomly generated. The quality of the generated numbers varies with the type of algorihm used. *Cryptographically secure* RNGs generate random numbers that that pass statistical randomness tests, and are resilient against prediction attacks.

Mobile SDKs offer standard implementations of RNG algorithms that produce numbers with sufficient artificial randomness.

#### 静的解析

Apple provides developers with the Randomisation Services application programming interface (API) that generates cryptographically secure random numbers<sup>[1]</sup>.

The Randomisation Services API uses the `SecRandomCopyBytes` function to perform the numbers generation. This is a wrapper function for the <code>/dev/random</code> device file, which provides cryptographically secure pseudorandom value from 0 to 255 and performs concatenation<sup>[2]</sup>. 

In Swift, the `SecRandomCopyBytes` API is defined as follows:<sup>[3]</sup>:
```
func SecRandomCopyBytes(_ rnd: SecRandomRef?, 
                      _ count: Int, 
                      _ bytes: UnsafeMutablePointer<UInt8>) -> Int32
```

The Objective-C is version looks as follows <sup>[4]</sup>:
```
int SecRandomCopyBytes(SecRandomRef rnd, size_t count, uint8_t *bytes);
```

The following is an example of its usage:
```
int result = SecRandomCopyBytes(kSecRandomDefault, 16, randomBytes);
```

#### 動的解析

-- TODO [Describe how to test for this issue "Testing Random Number Generation" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

-- TODO [Can probably write about generating multiple values via the random number generation and compare them to analyse the entropy] --

#### 改善方法

The recommended remediation to fix this issue is to always use the Randomisation Services API for any random number generation purposes. 
Avoid implementing custom cryptography algorithms and standards. Also, only supply cryptographically strong random numbers to cryptographic functions. 

#### 参考情報

##### OWASP Mobile Top 10 2016
* M5 - 不十分な暗号化 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M5-Insufficient_Cryptography

##### OWASP MASVS
* V3.6: "すべての乱数値は、十分に安全な乱数生成器を用いて生成している。"

##### CWE
- CWE-337 - Predictable Seed in PRNG
- CWE-338 - Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)

##### その他
- [1] Randomization Services - https://developer.apple.com/reference/security/randomization_services
- [2] Generating Random Numbers - https://developer.apple.com/library/content/documentation/Security/Conceptual/cryptoservices/RandomNumberGenerationAPIs/RandomNumberGenerationAPIs.html
- [3] SecRandomCopyBytes (Swift) - https://developer.apple.com/reference/security/1399291-secrandomcopybytes
- [4] SecRandomCopyBytes (Objective-C) - https://developer.apple.com/reference/security/1399291-secrandomcopybytes?language=objc

##### ツール
-- TODO [Add links to relavant tools for "Testing Random Number Generation"] --
* Enjarify - https://github.com/google/enjarify
