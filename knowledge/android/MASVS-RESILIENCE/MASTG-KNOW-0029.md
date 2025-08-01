---
masvs_category: MASVS-RESILIENCE
platform: android
title: ファイル完全性チェック (File Integrity Checks)
---

ファイル完全性に関連するトピックは二つあります。

 1. コード完全性チェック: アプリのバイトコード、ネイティブライブラリ、重要なデータファイルに対する追加の保護レイヤとして、CRC チェックを使用できます。この方法では、コード署名が有効であっても、アプリが変更されていない状態でのみ正しく動作します。
 2. ファイルストレージ完全性チェック: アプリケーションが SD カードやパブリックストレージに保存するファイルの完全性、および `SharedPreferences` に保存されるキー・バリューペアの完全性を保護する必要があります。

## サンプル実装 - アプリケーションソースコード

完全性チェックではたいてい選択したファイルに対してチェックサムやハッシュを計算します。一般的に保護されるファイルは以下のとおりです。

- AndroidManifest.xml
- クラスファイル *.dex
- ネイティブライブラリ (*.so)

以下の [Android Cracking ブログのサンプル実装](https://androidcracking.blogspot.com/2011/06/anti-tampering-with-crc-check.html "anti-tampering with crc check") では `classes.dex` の CRC を計算し、それを期待値と比較しています。

```java
private void crcTest() throws IOException {
 boolean modified = false;
 // required dex crc value stored as a text string.
 // it could be any invisible layout element
 long dexCrc = Long.parseLong(Main.MyContext.getString(R.string.dex_crc));

 ZipFile zf = new ZipFile(Main.MyContext.getPackageCodePath());
 ZipEntry ze = zf.getEntry("classes.dex");

 if ( ze.getCrc() != dexCrc ) {
  // dex has been modified
  modified = true;
 }
 else {
  // dex not tampered with
  modified = false;
 }
}
```

## サンプル実装 - ストレージ

ストレージ自体に完全性を提供する場合、特定のキー・バリューペア (Android の `SharedPreferences` など) に対して HMAC を作成するか、ファイルシステムが提供するファイル全体に対して HMAC を作成することができます。

HMAC を使用する場合、[bouncy castle 実装または AndroidKeyStore を使用して、指定されたコンテンツを HMAC する](https://web.archive.org/web/20210804035343/https://cseweb.ucsd.edu/~mihir/papers/oem.html "Authenticated Encryption: Relations among notions and analysis of the generic composition paradigm") ことができます。

BouncyCastle で HMAC を生成する場合は以下の手順を実行します。

1. BounceyCastle または SpongeyCastle がセキュリティプロバイダとして登録されていることを確認します。
2. HMAC をキーで初期化します (キーはキーストアに格納します) 。
3. HMAC を必要とするコンテンツのバイト配列を取得します。
4. HMAC とバイトコードで `doFinal` を呼び出します。
5. 手順 3 で取得したバイト配列に HMAC を追加します。
6. 手順 5 の結果を保存します。

BouncyCastle で HMAC を検証する場合は以下の手順を実行します。

1. BounceyCastle または SpongeyCastle がセキュリティプロバイダとして登録されていることを確認します。
2. メッセージと HMAC-bytes を個別の配列として抽出します。
3. HMAC を生成する手順 1-4 を繰り返します。
4. 抽出された HMAC-bytes を手順 3 の結果と比較します。

[Android Keystore](https://developer.android.com/training/articles/keystore.html "Android Keystore") に基づいて HMAC を生成する場合、Android 6.0 (API レベル 23) 以上でのみ行うことをお勧めします。

以下は `AndroidKeyStore` を使用しない便利な HMAC 実装です。

```java
public enum HMACWrapper {
    HMAC_512("HMac-SHA512"), //please note that this is the spec for the BC provider
    HMAC_256("HMac-SHA256");

    private final String algorithm;

    private HMACWrapper(final String algorithm) {
        this.algorithm = algorithm;
    }

    public Mac createHMAC(final SecretKey key) {
        try {
            Mac e = Mac.getInstance(this.algorithm, "BC");
            SecretKeySpec secret = new SecretKeySpec(key.getKey().getEncoded(), this.algorithm);
            e.init(secret);
            return e;
        } catch (NoSuchProviderException | InvalidKeyException | NoSuchAlgorithmException e) {
            //handle them
        }
    }

    public byte[] hmac(byte[] message, SecretKey key) {
        Mac mac = this.createHMAC(key);
        return mac.doFinal(message);
    }

    public boolean verify(byte[] messageWithHMAC, SecretKey key) {
        Mac mac = this.createHMAC(key);
        byte[] checksum = extractChecksum(messageWithHMAC, mac.getMacLength());
        byte[] message = extractMessage(messageWithHMAC, mac.getMacLength());
        byte[] calculatedChecksum = this.hmac(message, key);
        int diff = checksum.length ^ calculatedChecksum.length;

        for (int i = 0; i < checksum.length && i < calculatedChecksum.length; ++i) {
            diff |= checksum[i] ^ calculatedChecksum[i];
        }

        return diff == 0;
    }

    public byte[] extractMessage(byte[] messageWithHMAC) {
        Mac hmac = this.createHMAC(SecretKey.newKey());
        return extractMessage(messageWithHMAC, hmac.getMacLength());
    }

    private static byte[] extractMessage(byte[] body, int checksumLength) {
        if (body.length >= checksumLength) {
            byte[] message = new byte[body.length - checksumLength];
            System.arraycopy(body, 0, message, 0, message.length);
            return message;
        } else {
            return new byte[0];
        }
    }

    private static byte[] extractChecksum(byte[] body, int checksumLength) {
        if (body.length >= checksumLength) {
            byte[] checksum = new byte[checksumLength];
            System.arraycopy(body, body.length - checksumLength, checksum, 0, checksumLength);
            return checksum;
        } else {
            return new byte[0];
        }
    }

    static {
        Security.addProvider(new BouncyCastleProvider());
    }
}
```

完全性を持たせるもう一つの方法は取得したバイト配列に署名を行い、元のバイト配列に署名を加えることです。
