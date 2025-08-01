---
masvs_category: MASVS-RESILIENCE
platform: android
title: デバイスバインディング (Device Binding)
---

デバイスバインディングの目的はアプリとその状態をデバイス A からデバイス B にコピーし、デバイス B でアプリの実行を継続しようとする攻撃者を阻止することです。デバイス A が信頼できると判断された後、デバイス B よりも多くの権限を持つ可能性があります。このような差分の権限はアプリがデバイス A からデバイス B にコピーされても変更すべきではありません。

使用可能な識別子を説明する前に、それらをバインディングに使用できる方法について簡単に説明します。デバイスバインディングを可能にする三つの方法があります。

- 認証に使用されるクレデンシャルをデバイス識別子で補強します。これはアプリケーション自体やユーザーを頻繁に再認証する必要がある場合に意味があります。

- デバイスに強くバインドされている鍵マテリアルでデバイスに保存されるデータを暗号化することでデバイスバインディングを強化できます。Android Keystore はエクスポートできない鍵を提供しており、これに使用できます。悪意のある攻撃者がデバイスからそのようなデータを抽出した場合、鍵にアクセスできないため、データを復号できないでしょう。これを実装するには、以下の手順を行います。

    - `KeyGenParameterSpec` API を使用して Android Keystore の鍵ペアを生成します。

      ```java
      //Source: <https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.html>
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
              KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
      keyPairGenerator.initialize(
              new KeyGenParameterSpec.Builder(
                      "key1",
                      KeyProperties.PURPOSE_DECRYPT)
                      .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                      .build());
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
      cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
      ...

      // The key pair can also be obtained from the Android Keystore any time as follows:
      KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
      keyStore.load(null);
      PrivateKey privateKey = (PrivateKey) keyStore.getKey("key1", null);
      PublicKey publicKey = keyStore.getCertificate("key1").getPublicKey();
      ```

    - AES-GCM の暗号鍵 (secret key) を生成します。

      ```java
      //Source: <https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.html>
      KeyGenerator keyGenerator = KeyGenerator.getInstance(
              KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
      keyGenerator.init(
              new KeyGenParameterSpec.Builder("key2",
                      KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                      .build());
      SecretKey key = keyGenerator.generateKey();

      // The key can also be obtained from the Android Keystore any time as follows:
      KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
      keyStore.load(null);
      key = (SecretKey) keyStore.getKey("key2", null);
      ```

    - AES-GCM 暗号の暗号鍵 (secret key) を使用して、アプリケーションによって保存されている認証データやその他の機密データを暗号化し、インスタンス ID などのデバイス固有のパラメータを関連データとして使用します。

      ```java
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      final byte[] nonce = new byte[GCM_NONCE_LENGTH];
      random.nextBytes(nonce);
      GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
      cipher.init(Cipher.ENCRYPT_MODE, key, spec);
      byte[] aad = "<deviceidentifierhere>".getBytes();;
      cipher.updateAAD(aad);
      cipher.init(Cipher.ENCRYPT_MODE, key);

      //use the cipher to encrypt the authentication data see 0x50e for more details.
      ```

    - Android Keystore に保存されている公開鍵 (public key) を使用して暗号鍵 (secret key) を暗号化し、暗号化された暗号鍵 (secret key) をアプリケーションのプライベートストレージに保存します。
    - アクセストークンやその他の機密データなどの認証データが必要な場合、Android Keystore に保存されている秘密鍵 (private key) を使用して暗号鍵 (secret key) を復号し、復号した暗号鍵 (secret key) を使用して暗号文を復号します。

- トークンベースのデバイス認証 (インスタンス ID) を使用して、アプリの同じインスタンスが使用されることを確保します。
