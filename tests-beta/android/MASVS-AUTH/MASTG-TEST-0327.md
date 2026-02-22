---
platform: android
title: イベントバウンド型生体認証用の API への参照 (References to APIs for Event-Bound Biometric Authentication)
id: MASTG-TEST-0327
apis: [BiometricPrompt, BiometricPrompt.CryptoObject, authenticate]
type: [static]
weakness: MASWE-0044
profiles: [L2]
knowledge: [MASTG-KNOW-0001, MASTG-KNOW-0043, MASTG-KNOW-0047, MASTG-KNOW-0012]
best-practices: []
---

## 概要

このテストでは、アプリがイベントバウンド型生体認証 ([生体認証 (Biometric Authentication)](../../../knowledge/android/MASVS-AUTH/MASTG-KNOW-0001.md)) を実装して機密リソース (トークン、キーなど) にアクセスしているかどうかをチェックします。認証の成功は、機密操作に暗号的にバインドされてユーザーの存在を必要とするのではなく、コールバック結果にのみ依存します。

Android では、`BiometricPrompt.authenticate()` は [`CryptoObject` あり](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt#authenticate(android.hardware.biometrics.BiometricPrompt.CryptoObject,%20android.os.CancellationSignal,%20java.util.concurrent.Executor,%20android.hardware.biometrics.BiometricPrompt.AuthenticationCallback)) または [`CryptoObject` なし](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt#authenticate(android.os.CancellationSignal,%20java.util.concurrent.Executor,%20android.hardware.biometrics.BiometricPrompt.AuthenticationCallback)) で呼び出すことができます。**`CryptoObject` なしで** 使用する場合、アプリは [`onAuthenticationSucceeded`](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt.AuthenticationCallback#onAuthenticationSucceeded(android.hardware.biometrics.BiometricPrompt.AuthenticationResult)) コールバックを使用して認証が成功したかどうかを判断します (イベントバウンド)。これは、生体検証に成功せずにコールバックを上書きすることでロジックを操作される可能性があります。

一方、`CryptoObject` が使用される場合 (暗号バウンド)、アプリはユーザー認証を必要とする暗号オブジェクト (`Cipher`, `Signature`, `Mac` など) を渡します。これは、認証が単なる一回限りのブール値ではなく、安全なデータ取得パス (アウトオブプロセス) の一部となり、認証のバイパスが大幅に困難になります。

## 手順

1. 静的解析 ([Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md)) ツールを実行して、関連する API のインスタンスを識別します。

## 結果

出力には関連する API が使用されている場所のリストを含む可能性があります。

## 評価

以下の場合、保護する価値のある機密操作ごとに、このテストは不合格です。

- `BiometricPrompt.authenticate` が [`CryptoObject` なし](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt#authenticate(android.os.CancellationSignal,%20java.util.concurrent.Executor,%20android.hardware.biometrics.BiometricPrompt.AuthenticationCallback)) で使用されている。
- 生体認証と組み合わせて `setUserAuthenticationRequired(true)` での鍵生成の呼び出しがない。デフォルトでは、ユーザーが認証されているかどうかに関係なく、鍵の使用が認可されるため。

以下の場合、保護する価値のある機密操作ごとに、このテストは合格です。

- `BiometricPrompt.authenticate` が [`CryptoObject` あり](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt#authenticate(android.hardware.biometrics.BiometricPrompt.CryptoObject,%20android.os.CancellationSignal,%20java.util.concurrent.Executor,%20android.hardware.biometrics.BiometricPrompt.AuthenticationCallback)) で、つまり機密操作に Android KeyStore から適切に構成された暗号鍵を用いて、使用されている。
- `setUserAuthenticationRequired(true)` での鍵生成の呼び出しがあり、鍵は生体認証が成功した後にのみ使用できるようにし、認証を暗号操作にバインドしている。
