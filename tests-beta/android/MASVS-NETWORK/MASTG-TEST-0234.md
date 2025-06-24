---
title: SSLSocket でのサーバーホスト名検証の実装の欠如 (Missing Implementation of Server Hostname Verification with SSLSockets)
platform: android
id: MASTG-TEST-0234
type: [static]
weakness: MASWE-0052
profiles: [L1, L2]
---

## 概要

このテストは、Android アプリが [`HostnameVerifier`](https://developer.android.com/reference/javax/net/ssl/HostnameVerifier) なしで [`SSLSocket`](https://developer.android.com/reference/javax/net/ssl/SSLSocket) を使用し、**不正または無効なホスト名** での証明書を提示するサーバーへの接続を許可しているかどうかをチェックします。

デフォルトでは、`SSLSocket` は [ホスト名検証を実行しません](https://developer.android.com/privacy-and-security/security-ssl#WarningsSslSocket)。これを強制するには、アプリが明示的に [`HostnameVerifier.verify()`](https://developer.android.com/reference/javax/net/ssl/HostnameVerifier#verify%28java.lang.String,%20javax.net.ssl.SSLSession%29) を呼び出し、適切なチェックを実装する必要があります。

このような安全でない実装は、攻撃者が有効な (または自己署名された) 証明書で [MITM 攻撃](../../../Document/0x04f-Testing-Network-Communication.md#intercepting-network-traffic-through-mitm) を実行し、アプリのトラフィックを傍受または改竄することを可能にします。

**注:** アプリが完全に安全な Network Security Configuration (NSC) を有している場合でも、`SSLSocket` はその影響を受けないため、接続は成功します。

## 手順

1. アプリをリバースエンジニアします ([Java コードの逆コンパイル (Decompiling Java Code)](../../../techniques/android/MASTG-TECH-0017.md))。
2. アプリに対して静的解析 ([Android での静的解析 (Static Analysis on Android)](../../techniques/android/MASTG-TECH-0014.md)) ツールを実行して、`SSLSocket` と `HostnameVerifier` のすべての使用箇所を探します。

## 結果

出力には `SSLSocket` と `HostnameVerifier` が使用されている場所のリストを含みます。

## 評価

アプリが `HostnameVerifier` なしで `SSLSocket` を使用している場合、そのテストケースは不合格です。

**注:** `HostnameVerifier` が存在する場合、それが安全でない方法で実装されていないことを確認してください。ガイダンスについては [サーバーホスト名検証の正しくない実装 (Incorrect Implementation of Server Hostname Verification)](MASTG-TEST-0283.md) を参照してください。
