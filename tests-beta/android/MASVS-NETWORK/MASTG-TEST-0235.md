---
title: クリアテキストトラフィックを許可している Android アプリ構成 (Android App Configurations Allowing Cleartext Traffic)
platform: android
id: MASTG-TEST-0235
type: [static]
weakness: MASWE-0050
---

## 概要

Android 9 (API レベル 28) 以降、クリアテキストの HTTP トラフィックはデフォルトでブロックされます ([デフォルト Network Security Configuration](../../../Document/0x05g-Testing-Network-Communication.md#default-configurations) を参照) が、アプリケーションがそれを送信する方法はまだ複数あります。

- **AndroidManifest.xml**: `<application>` タグの [`android:usesCleartextTraffic`](https://developer.android.com/guide/topics/manifest/application-element#usesCleartextTraffic) 属性を設定します。Network Security Configuration が構成されている場合、このフラグは無視されることに注意してください。
- **Network Security Configuration**: `<base-config>` または `<domain-config>` 要素の [`cleartextTrafficPermitted`](https://developer.android.com/privacy-and-security/security-config#CleartextTrafficPermitted) 属性を `true` に設定します。

## 手順

1. アプリをリバースエンジニアします ([Java コードの逆コンパイル (Decompiling Java Code)](../../../techniques/android/MASTG-TECH-0017.md))。
2. AndroidManifest.xml を取得します。
3. Network Security Configuration を取得します。
4. AndroidManifest.xml から `usesCleartextTraffic` の値を読み取ります。
5. NSC `<base-config>` 要素から `cleartextTrafficPermitted` の値を読み取ります。
6. NSC `<domain-config>` 要素から `cleartextTrafficPermitted` の値を読み取ります。

## 結果

出力にはクリアテキストトラフィックを潜在的に許可する構成のリストを含みます。

## 評価

クリアテキストトラフィックが許可されている場合、そのテストケースは不合格です。これは以下が true である場合に発生する可能性があります。

1. AndroidManifest は `usesCleartextTraffic` を `true` に設定し、NSC がありません。
2. NSC は `<base-config>` の `cleartextTrafficPermitted` を `true` に設定します。
3. NSC は `<domain-config>` の `cleartextTrafficPermitted` を `true` に設定します。

**注:** AndroidManifest が `usesCleartextTraffic` を `true` に設定し、NSC がある場合、空の `<network-security-config>` 要素しかないとしても、テストは不合格ではありません。たとえば、以下のような場合です。

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
</network-security-config>
```
