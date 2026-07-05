---
platform: android
title: オーバーレイ攻撃保護への参照 (References to Overlay Attack Protections)
id: MASTG-TEST-0340
apis:
  - onFilterTouchEventForSecurity
  - setFilterTouchesWhenObscured
  - FLAG_WINDOW_IS_OBSCURED
  - FLAG_WINDOW_IS_PARTIALLY_OBSCURED
type:
  - static
  - code
weakness: MASWE-0053
best-practices:
  - MASTG-BEST-0040
profiles:
  - L2
knowledge:
  - MASTG-KNOW-0022
---

# MASTG-TEST-0340 オーバーレイ攻撃保護への参照 (References to Overlay Attack Protections)

### 概要

オーバーレイ攻撃 (タップジャッキングとも呼ばれる) は、悪意のあるアプリが正規アプリのインタフェース上に偽の UI 要素を重ねて、ユーザーに意図しないアクション (パーミッションの付与、クレデンシャルの流出、決済の承認など) を許す可能性があります。アプリが適切な保護を講じていない場合、ユーザーは正規アプリとやり取りしていると思い込み、オーバーレイされた悪意のあるコンテンツとやり取りする可能性があります。

Android はタッチフィルタリングを通じたオーバーレイ攻撃から保護するための複数のメカニズムを提供しています。これらのメカニズムはビューが隠されたことを検出し、それに応じてタッチイベントをフィルタします。しかし、アプリが機密性の高い UI 要素にこれらの保護を使用していない場合、オーバーレイ攻撃に対して脆弱なままとなります。

このテストは、ビューが隠されている場合にやり取りを防止するタッチフィルタリング API と属性への参照を探すことで、アプリがオーバーレイ攻撃保護を実装しているかどうかをチェックします。

これには以下を含みます。

* `setFilterTouchesWhenObscured` メソッド。
* レイアウトファイル内の `android:filterTouchesWhenObscured` 属性。
* `onFilterTouchEventForSecurity` メソッド。
* `FLAG_WINDOW_IS_OBSCURED` や `FLAG_WINDOW_IS_PARTIALLY_OBSCURED` フラグのチェック。
* [`setHideOverlayWindows`](https://developer.android.com/reference/android/view/Window#setHideOverlayWindows\(boolean\)) メソッドと、API レベル 31 以降で必要な `HIDE_OVERLAY_WINDOWS` パーミッション。

### 手順

1. [Android アプリのリバースエンジニアリング (Reverse Engineering Android Apps)](../../../techniques/android/MASTG-TECH-0013.md) を使用して、アプリをリバースエンジニアします。
2. [Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md) を使用して、関連する API を探します。
3. [AndroidManifest から情報の取得 (Obtaining Information from the AndroidManifest)](../../../techniques/android/MASTG-TECH-0117.md) を使用して、AndroidManifest.xml を取得します。
4. [AndroidManifest の解析 (Analyzing the AndroidManifest)](https://github.com/coky-t/owasp-mastg-ja/blob/master/techniques/android/MASTG-TECH-0150.md) を使用して、AndroidManifest.xml ファイルから `targetSdkVersion` を取得します。
5. [アプリパーミッションの取得 (Obtaining App Permissions)](../../../techniques/android/MASTG-TECH-0126.md) を使用して、関連するパーミッションを取得します。

### 結果

出力には以下を含む可能性があります。

* オーバーレイ保護メカニズムが使用されている場所のリスト
* アプリの `targetSdkVersion`
* `HIDE_OVERLAY_WINDOWS` などの関連するパーミッション

### 評価

アプリが機密性の高いユーザー操作 (ログイン、支払い確認、パーミッションリクエスト、セキュリティ設定など) を処理し、それらの機密性の高い UI 要素にオーバーレイ攻撃保護を実装していない場合、そのテストは不合格です。

例:

* アプリは機密性の高い UI 要素に `setFilterTouchesWhenObscured(true)` や `android:filterTouchesWhenObscured="true"` を実装していない。
* アプリはカスタムセキュリティポリシーを実装するために `onFilterTouchEventForSecurity` をオーバーライドしていない。
* アプリは機密性の高い操作のタッチイベントハンドラで `FLAG_WINDOW_IS_OBSCURED` や `FLAG_WINDOW_IS_PARTIALLY_OBSCURED` をチェックしていない。
* アプリは API レベル 31 以降をターゲットとしているが、`setHideOverlayWindows(true)` を使用しておらず、`HIDE_OVERLAY_WINDOWS` パーミッションを宣言していない。
