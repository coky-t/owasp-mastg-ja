---
title: Network Security Configuration での証明書ピン留めの欠如 (Missing Certificate Pinning in Network Security Configuration)
platform: android
id: MASTG-TEST-0242
type: [static, code]
weakness: MASWE-0047
profiles: [L2]
knowledge: [MASTG-KNOW-0014, MASTG-KNOW-0015]
---

## 概要

アプリは [Network Security Configuration を使用して証明書のピン留め](../../../knowledge/android/MASVS-NETWORK/MASTG-KNOW-0015.md#pinning-via-network-security-configuration-api-24) を構成できます。ドメインごとに、一つまたは複数のダイジェストをピン留めできます。

このテストの目的は、アプリが NSC を使用して証明書のピン留めを実装していないかどうかをチェックすることです。ただし、アプリは他のテストでカバーされる他のピン留め手法を使用している可能性があることに注意してください。

## 手順

1. [Android アプリのリバースエンジニアリング (Reverse Engineering Android Apps)](../../../techniques/android/MASTG-TECH-0013.md) を使用して、アプリをリバースエンジニアします。
2. [AndroidManifest から情報の取得 (Obtaining Information from the AndroidManifest)](../../../techniques/android/MASTG-TECH-0117.md) を使用して、AndroidManifest.xml を取得します。
3. [AndroidManifest の解析 (Analyzing the AndroidManifest)](../../../techniques/android/MASTG-TECH-0150.md) を使用して、`<application>` タグに `networkSecurityConfig` が設定されているかどうかをチェックします。
4. [Network Security Configuration の解析 (Analyzing the Network Security Configuration)](../../../techniques/android/MASTG-TECH-0151.md) を使用して、Network Security Configuration ファイルから、ピンセット (`<pin-set>`) がある `<domain-config>` からのすべてのドメインを抽出します。

## 結果

出力には証明書のピン留めを有効にするドメインのリストを含む可能性があります。

## 評価

`networkSecurityConfig` が設定されていないか、関連するドメインが証明書のピン留めを有効にしていない場合、そのテストケースは不合格です。
