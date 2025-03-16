---
platform: android
title: 危険なアプリパーミッション (Dangerous App Permissions)
id: MASTG-TEST-0254
weakness: MASWE-0117
---

## 概要

Android アプリでは、カメラ、位置情報、ストレージなどの情報やシステム機能にアクセスするためにさまざまな方法でパーミッションが取得されます。必要なパーミッションは `AndroidManifest.xml` ファイルの `<uses-permission>` タグで指定されます。

## 手順

アプリで使用しているパーミッションを見つけるのに役立つツールは複数あります。[AndroidManifest から情報の取得 (Obtaining Information from the AndroidManifest)](../../../techniques/android/MASTG-TECH-0117.md) を参照して、記載されているいずれかのツールを使用します。

1. APK から `AndroidManifest.xml` ファイルを抽出します ([AndroidManifest から情報の取得 (Obtaining Information from the AndroidManifest)](../../../techniques/android/MASTG-TECH-0117.md) を参照)。
2. 宣言されているパーミッションのリストを取得します ([アプリパーミッションの取得 (Obtaining App Permissions)](../../../techniques/android/MASTG-TECH-0126.md) を参照)。

## 結果

出力はアプリで宣言されているパーミッションのリストを示します。

## 評価

アプリに危険なパーミッションがある場合、そのテストは不合格です。

宣言されているパーミッションのリストを Android で定義されている [dangerous permissions](https://android.googlesource.com/platform/frameworks/base/%2B/master/core/res/AndroidManifest.xml) のリストと比較します。詳細については [Android ドキュメント](https://developer.android.com/reference/android/Manifest.permission) を参照してください。

**コンテキストの考慮**:

パーミッションの評価の際にはコンテキストが不可欠です。たとえば、カメラを使用して QR コードをスキャンするアプリには `CAMERA` パーミッションを持つ必要があります。しかし、アプリにカメラ機能がない場合、このパーミッションは不要であり、削除すべきです。

また、アプリが使用するパーミッションに代わるプライバシー保護の代替手段があるかどうかも考慮してください。たとえば、`CAMERA` パーミッションを使用する代わりに、アプリは [デバイスの組み込みカメラアプリを使用](https://developer.android.com/privacy-and-security/minimize-permission-requests#take-photo) して、`ACTION_IMAGE_CAPTURE` や `ACTION_VIDEO_CAPTURE` インテントアクションを呼び出して写真やビデオを撮影できます。このアプローチにより、アプリは `CAMERA` パーミッションを直接要求せずにカメラ機能にアクセスできるため、ユーザーのプライバシーを強化します。
