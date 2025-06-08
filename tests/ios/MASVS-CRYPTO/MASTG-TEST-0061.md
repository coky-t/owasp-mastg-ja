---
masvs_v1_id:
- MSTG-CRYPTO-2
- MSTG-CRYPTO-3
masvs_v2_id:
- MASVS-CRYPTO-1
platform: ios
title: 暗号標準アルゴリズムの構成の検証 (Verifying the Configuration of Cryptographic Standard Algorithms)
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
status: deprecated
covered_by: [MASTG-TEST-0209, MASTG-TEST-0210, MASTG-TEST-0211]
deprecation_note: New version available in MASTG V2
---

## 概要

## 静的解析

アプリケーションで使用される各ライブラリについて、使用されるアルゴリズムや暗号構成を検証し、それらが非推奨ではなく、正しく使用されていることを確認する必要があります。

鍵を保持するデータ構造とプレーンテキストデータ構造の削除方法がどのように定義されているかに注意します。キーワード `let` が使用されている場合、メモリから消去するのが難しい不変 (immutable) 構造を作成します。メモリから簡単に削除できる  (たとえば、一時的に存在する `struct` などの) 親構造の一部であることを確認します。

"[モバイルアプリの暗号化](../../../Document/0x04g-Testing-Cryptography.md)" の章で説明されているベストプラクティスに従っていることを確認します。[非セキュアな暗号アルゴリズムや非推奨の暗号アルゴリズム](../../../Document/0x04g-Testing-Cryptography.md#identifying-insecure-andor-deprecated-cryptographic-algorithms) および [よくある設定の問題](../../../Document/0x04g-Testing-Cryptography.md#common-configuration-issues) を見直しましょう。

### CommonCryptor

アプリが Apple により提供されている標準暗号実装を使用する場合、関連するアルゴリズムのステータスを判断する最も簡単な方法は `CCCrypt` や `CCCryptorCreate` など、`CommonCryptor` からの関数呼び出しをチェックすることです。[ソースコード](https://web.archive.org/web/20240606000307/https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h "CommonCryptor.h") には CommonCryptor.h のすべての関数のシグネチャが含まれています。例えば、`CCCryptorCreate` は以下のシグネチャを持ちます。

```c
CCCryptorStatus CCCryptorCreate(
    CCOperation op,             /* kCCEncrypt, etc. */
    CCAlgorithm alg,            /* kCCAlgorithmDES, etc. */
    CCOptions options,          /* kCCOptionPKCS7Padding, etc. */
    const void *key,            /* raw key material */
    size_t keyLength,
    const void *iv,             /* optional initialization vector */
    CCCryptorRef *cryptorRef);  /* RETURNED */
```

それからすべての `enum` タイプを比較して、使用されているアルゴリズム、パディング、鍵マテリアルを確定します。鍵マテリアルに注意します。鍵は鍵導出関数または乱数生成関数を使用してセキュアに生成されるべきです。
「モバイルアプリの暗号化」の章で非推奨として記載されている機能は、依然としてプログラムでサポートされていることに注意します。それらを使用すべきではありません。

### サードパーティーライブラリ

すべてのサードパーティーライブラリの継続的に進化していることを考えると、ここは静的解析の観点から各ライブラリを評価する適切な機会ではありません。それでも注意すべき点がいくつかあります。

- **利用されているライブラリを見つけます**: これは以下の手法を使用して実行できます。
    - [cartfile](https://github.com/Carthage/Carthage/blob/master/Documentation/Artifacts.md#cartfile "cartfile") をチェックします (Carthage が使用されている場合) 。
    - [podfile](https://guides.cocoapods.org/syntax/podfile.html "podfile")  をチェックします (Cocoapods が使用されている場合) 。
    - リンクされたライブラリをチェックします。xcodeproj ファイルを開き、プロジェクトのプロパティをチェックします。**Build Phases** タブに移動し、いずれかのライブラリの **Link Binary With Libraries** のエントリをチェックします。[MobSF](../../../tools/generic/MASTG-TOOL-0035.md) を使用して同様の情報を取得する方法については以前のセクションを参照してください。
    - ソースをコピー＆ペーストした場合、既知のライブラリの既知のメソッド名でヘッダファイル (Objective-C を使用している場合) およびその他の Swift ファイルを検索します。
- **使用しているバージョンを確定します**: 使用しているライブラリのバージョンを常にチェックし、潜在的な脆弱性や不具合にパッチ適用した新しいバージョンが利用可能かどうかをチェックします。ライブラリの新しいバージョンがない場合でも、暗号機能はまだレビューされていない場合があります。そのため確認済みライブラリを使用することを常に推奨します。もしくは、自分で確認できる能力、知識、経験があることを確認します。
- **手製か？**: 独自の暗号を動かしたり、既存の暗号機能を自分自身で実装したりしないことをお勧めします。
