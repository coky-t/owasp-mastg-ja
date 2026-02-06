---
title: Network Security Configuration での証明書ピン留めの欠如 (Missing Certificate Pinning in Network Security Configuration)
platform: android
id: MASTG-TEST-0242
type: [static]
weakness: MASWE-0047
profiles: [L2]
knowledge: [MASTG-KNOW-0014, MASTG-KNOW-0015]
---

## 概要

アプリは [Network Security Configuration を使用して証明書のピン留め](../../../knowledge/android/MASVS-NETWORK/MASTG-KNOW-0015.md#pinning-via-network-security-configuration-api-24) を構成できます。ドメインごとに、一つまたは複数のダイジェストをピン留めできます。

このテストの目的は、アプリが NSC を使用して証明書のピン留めを実装していないかどうかをチェックすることです。ただし、アプリは他のテストでカバーされる他のピン留め手法を使用している可能性があることに注意してください。

## 手順

1. アプリをリバースエンジニアします ([Java コードの逆コンパイル (Decompiling Java Code)](../../../techniques/android/MASTG-TECH-0017.md))。
2. AndroidManifest.xml を取得 ([AndroidManifest から情報の取得 (Obtaining Information from the AndroidManifest)](../../../techniques/android/MASTG-TECH-0117.md)) し、`<application>` タグに `networkSecurityConfig` が設定されているかどうかをチェックします。
3. 参照しているネットワークセキュリティ構成ファイルを検査し、`<domain-config>` からピンセット (`<pin-set>`) があるすべてのドメインを抽出します。

## 結果

出力には証明書のピン留めを有効にするドメインのリストを含む可能性があります。

## 評価

`networkSecurityConfig` が設定されていないか、関連するドメインが証明書のピン留めを有効にしていない場合、そのテストケースは不合格です。
