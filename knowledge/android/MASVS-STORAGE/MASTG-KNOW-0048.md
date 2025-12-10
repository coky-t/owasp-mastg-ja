---
masvs_category: MASVS-STORAGE
platform: android
title: キーチェーン (KeyChain)
---

[KeyChain](https://developer.android.com/reference/android/security/KeyChain.html "Android KeyChain") クラスは _システム全体_ の秘密鍵 (private keys) とそれに対応する証明書 (チェーン) を保存および取得するために使用されます。何かを KeyChain に初めてインポートする場合、クレデンシャルストレージを保護するために、ユーザーはロック画面の PIN やパスワードを設定するように促されます。KeyChain はシステム全体にわたり、すべてのアプリケーションが KeyChain に保存されているマテリアルにアクセスできることに注意します。

ソースコードを検査し、ネイティブ Android メカニズムが機密情報を識別しているかどうかを判断します。機密情報は暗号化される必要があり、クリアテキストで保存してはいけません。デバイスに保存する必要がある機密情報については、`KeyChain` クラスを介してデータを保護するためのいくつかの API 呼び出しが利用可能です。以下の手順を実行します。

- アプリが Android KeyStore と Cipher メカニズムを使用して、暗号化された情報をデバイスに安全に保存していることを確認します。`AndroidKeystore`, `import java.security.KeyStore`, `import javax.crypto.Cipher`, `import java.security.SecureRandom` というパターンと、それに対応する使用箇所を探します。
- `store(OutputStream stream, char[] password)` 関数を使用して、KeyStore をパスワード付きでディスクに保存します。パスワードはユーザーによって提供されるものであり、ハードコードされていないことを確認します。
