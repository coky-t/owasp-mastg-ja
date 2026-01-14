---
masvs_category: MASVS-CRYPTO
platform: android
title: 鍵生成 (Key Generation)
---

Android SDK は鍵をどのように生成し、どのような状況で使用できるかを指定できます。Android 6.0 (API レベル 23) ではアプリケーションで正しい鍵の使用を保証するために使用できる `KeyGenParameterSpec` クラスを導入しました。以下に例を示します。

```java
String keyAlias = "MySecretKey";

KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(keyAlias,
        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
        .setRandomizedEncryptionRequired(true)
        .build();

KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,
        "AndroidKeyStore");
keyGenerator.init(keyGenParameterSpec);

SecretKey secretKey = keyGenerator.generateKey();
```

`KeyGenParameterSpec` は鍵を暗号化および復号化に使用できることを示しますが、署名や検証などの他の目的には使用できません。さらに、ブロックモード (CBC) 、パディング (PKCS #7) を指定し、ランダム化された暗号化が必要である (これがデフォルトです) ことを明示的に指定します。次に、`KeyGenerator.getInstance` 呼び出しでプロバイダの名前として `AndroidKeyStore` を入力し、鍵が Android KeyStore に保存されることを確保します。

GCM は [認証付き暗号](https://en.wikipedia.org/wiki/Authenticated_encryption "Authenticated encryption") を提供する AES モードであり、HMAC などの別のメカニズムを必要とする CBC などの古いモードとは異なり、暗号化とデータ認証を単一プロセスに統合することでセキュリティを強化します。さらに、GCM はパディングを必要としないため、実装を簡易化し、脆弱性を最小限に抑えます。

上記の仕様に違反して生成された鍵の使用を試みるとセキュリティ例外が発生します。

その鍵を使用して暗号化する例を以下に示します。

```java
String AES_MODE = KeyProperties.KEY_ALGORITHM_AES
        + "/" + KeyProperties.BLOCK_MODE_CBC
        + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7;
KeyStore AndroidKeyStore = AndroidKeyStore.getInstance("AndroidKeyStore");

// byte[] input
Key key = AndroidKeyStore.getKey(keyAlias, null);

Cipher cipher = Cipher.getInstance(AES_MODE);
cipher.init(Cipher.ENCRYPT_MODE, key);

byte[] encryptedBytes = cipher.doFinal(input);
byte[] iv = cipher.getIV();
// save both the IV and the encryptedBytes
```

IV (初期化ベクトル) および暗号化されたバイト列の両方を保存する必要があります。そうしないと復号はできません。

暗号文を復号する方法を以下に示します。 `input` は暗号化されたバイト配列であり、 `iv` は暗号ステップからの初期化ベクトルです。

```java
// byte[] input
// byte[] iv
Key key = AndroidKeyStore.getKey(AES_KEY_ALIAS, null);

Cipher cipher = Cipher.getInstance(AES_MODE);
IvParameterSpec params = new IvParameterSpec(iv);
cipher.init(Cipher.DECRYPT_MODE, key, params);

byte[] result = cipher.doFinal(input);
```

IV は毎回ランダムに生成されるため、後で復号するために暗号文 (`encryptedBytes`) とともに保存する必要があります。

Android 6.0 (API レベル 23) より前では AES 鍵の生成はサポートされていませんでした。結果として、多くの実装では RSA を使用することを選択し、 `KeyPairGeneratorSpec` を使用して非対称暗号化用の公開鍵と秘密鍵のペアを生成するか、あるいは `SecureRandom` を使用して AES 鍵を生成していました。

RSA 鍵ペアの作成に使用される `KeyPairGenerator` および `KeyPairGeneratorSpec` の例を以下の示します。

```java
Date startDate = Calendar.getInstance().getTime();
Calendar endCalendar = Calendar.getInstance();
endCalendar.add(Calendar.YEAR, 1);
Date endDate = endCalendar.getTime();
KeyPairGeneratorSpec keyPairGeneratorSpec = new KeyPairGeneratorSpec.Builder(context)
        .setAlias(RSA_KEY_ALIAS)
        .setKeySize(4096)
        .setSubject(new X500Principal("CN=" + RSA_KEY_ALIAS))
        .setSerialNumber(BigInteger.ONE)
        .setStartDate(startDate)
        .setEndDate(endDate)
        .build();

KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA",
        "AndroidKeyStore");
keyPairGenerator.initialize(keyPairGeneratorSpec);

KeyPair keyPair = keyPairGenerator.generateKeyPair();
```

この例では 4096 ビットの鍵サイズ (すなわち、モジュラスサイズ) で RSA 鍵ペアを作成します。楕円曲線 (Elliptic Curve, EC) 鍵も同様の方法で生成できます。ただし、Android 11 (API レベル 30) 以降、[AndroidKeyStore は EC 鍵での暗号化や復号化をサポートしていません](https://developer.android.com/guide/topics/security/cryptography#SupportedCipher) 。これらは署名にのみ使用できます。

対称暗号鍵は Password Based Key Derivation Function version 2 (PBKDF2) を使用してパスフレーズから生成できます。この暗号プロトコルは暗号鍵を生成するように設計されており、暗号化の目的で使用できます。アルゴリズムの入力パラメータは [脆弱な鍵生成関数](0x04g-Testing-Cryptography.md#improper-key-derivation-functions) セクションに従って調整します。以下のコードはパスワードに基づいて強力な暗号鍵を生成する方法を示しています。

```java
public static SecretKey generateStrongAESKey(char[] password, int keyLength)
{
    //Initialize objects and variables for later use
    int iterationCount = 10000;
    int saltLength     = keyLength / 8;
    SecureRandom random = new SecureRandom();
    //Generate the salt
    byte[] salt = new byte[saltLength];
    random.nextBytes(salt);
    KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, keyLength);
    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    byte[] keyBytes = keyFactory.generateSecret(keySpec).getEncoded();
    return new SecretKeySpec(keyBytes, "AES");
}
```

上記の手法ではパスワードと必要なビット長の鍵 (例えば 128 または 256 ビットの AES 鍵) を含む文字配列が必要です。 PBKDF2 アルゴリズムにより使用される 10,000 ラウンドの反復回数を定義します。反復回数を増やすことでパスワードに対するブルートフォース攻撃の作業負荷が大幅に増加しますが、鍵導出にはより多くの計算能力が必要になるためパフォーマンスに影響を与える可能性があります。ビットからバイトに変換するために鍵長を 8 で除算した値に等しいソルトサイズを定義し、 `SecureRandom` クラスを使用してランダムにソルトを生成します。同じパスワードが与えられた際には何度でも同じ暗号鍵が生成されることを確実にするために、このソルトは一定に保つ必要があります。ソルトを `SharedPreferences` に非公開で格納できることに注意します。リスクの高いデータの場合には同期を防ぐために Android のバックアップメカニズムからソルトを除外することを推奨します。

### !!! 注記
ルート化デバイスやパッチ適用 (再パッケージなど) されたアプリケーションをデータの脅威として考慮すると、 `AndroidKeystore` に配置された鍵でソルトを暗号化するほうがよいかもしれません。 Password-Based Encryption (PBE) 鍵は Android 8.0 (API レベル 26) まで、推奨される `PBKDF2WithHmacSHA1` アルゴリズムを使用して生成されます。より高い API レベルでは、より長いハッシュ値を生成する `PBKDF2withHmacSHA256` を使用することが最適です。

### !!! 注記
NDK を使用して暗号化操作とハードコードされた鍵を隠す必要があるという誤解が広まっています。しかし、このメカニズムは効果的ではありません。攻撃者は依然としてツールを使用して、使用されているメカニズムを特定し、メモリ内の鍵のダンプを作成します。次に、制御フローは例えば radare2 と、 Frida で抽出された鍵、またはその両方を組み合わせた [r2frida](../tools/generic/MASTG-TOOL-0036.md) (詳細は [ネイティブコードの逆アセンブル (Disassembling Native Code)](../techniques/android/MASTG-TECH-0018.md), [プロセス調査 (Process Exploration)](../techniques/android/MASTG-TECH-0044.md) を参照) で解析することができます。Android 7.0 (API レベル 24) 以降では、プライベート API の使用が許可されていません。代わりにパブリック API を呼び出す必要があります。これは [Android 開発者ブログ](https://android-developers.googleblog.com/2016/06/android-changes-for-ndk-developers.html "Android changes for NDK developers") で説明されているように隠蔽の有効性にさらに影響を与えます。
