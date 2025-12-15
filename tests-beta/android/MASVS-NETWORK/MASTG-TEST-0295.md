---
title: 更新されていない GMS セキュリティプロバイダ (GMS Security Provider Not Updated)
platform: android
id: MASTG-TEST-0295
type: [static]
weakness: MASWE-0052
profiles: [L2]
best-practices: [MASTG-BEST-0020]
knowledge: [MASTG-KNOW-0011, MASTG-KNOW-0010]
---

## 概要

このテストでは、Android アプリがセキュリティプロバイダ が [SSL/TLS 脆弱性を緩和するために更新されている](https://developer.android.com/privacy-and-security/security-gms-provider) かどうかをチェックします。このプロバイダは Google Play Services API を使用して更新する必要があり、実装では例外を適切に処理する必要があります。

## 手順

1. アプリをリバースエンジニアします ([Java コードの逆コンパイル (Decompiling Java Code)](../../../techniques/android/MASTG-TECH-0017.md))。
2. 静的解析 ([Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md)) を使用して、`ProviderInstaller.installIfNeeded` や `ProviderInstaller.installIfNeededAsync` の使用箇所を探します。

## 結果

出力には、セキュリティプロバイダの更新が実行されるすべての場所と、例外が処理される方法 (`installIfNeeded` の場合)、または `ProviderInstallListener` がエラーを処理する方法 (`installIfNeededAsync` の場合) をリストする可能性があります。

## 評価

アプリがプロバイダを更新しない場合、または例外を適切に処理しない場合、そのテストは不合格です。これらの呼び出しはネットワーク接続が確立される前に行っていることをチェックしてください。
