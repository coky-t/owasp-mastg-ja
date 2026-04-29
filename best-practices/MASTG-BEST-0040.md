---
title: オーバーレイ攻撃を防止する (Preventing Overlay Attacks)
alias: preventing-overlay-attacks
id: MASTG-BEST-0040
platform: android
knowledge: [MASTG-KNOW-0022]
---

アプリは、適切な防御メカニズムを実装することで、機密性の高いユーザー操作をオーバーレイ攻撃から保護する必要があります。オーバーレイ攻撃 ([タップジャッキング](https://developer.android.com/privacy-and-security/risks/tapjacking) を含む) は、悪意のあるアプリが正規のアプリインタフェース上に偽の UI 要素を配置し、ユーザーを意図しないアクションに誘導する際に発生します。

オーバーレイ攻撃から保護するために適切なメカニズムを実装します。以下のアプローチは堅牢性の高いものから低いものへとリストされています。

## 防止メカニズム

これらのメカニズムはオーバーレイの表示を防止したり、オーバーレイが検出された場合にタッチイベントをブロックします。

1. **`HIDE_OVERLAY_WINDOWS` パーミッションと `setHideOverlayWindows(true)` を使用する** (API レベル 31 以降): マニフェストで [`HIDE_OVERLAY_WINDOWS`](https://developer.android.com/reference/android/Manifest.permission#HIDE_OVERLAY_WINDOWS) パーミッションを宣言し、ウィンドウに対して [`setHideOverlayWindows(true)`](https://developer.android.com/reference/android/view/Window#setHideOverlayWindows(boolean)) を呼び出すことで、アクティビティがフォアグラウンドにある間、システム以外のオーバーレイウィンドウを非表示にします。これはタッチイベントをフィルタリングするだけでなく、オーバーレイを完全に防止するために、最も堅牢なソリューションです。

2. **`android:filterTouchesWhenObscured="true"` を設定する、または `setFilterTouchesWhenObscured(true)` を呼び出す**: 機密性の高いビューに対して XML でレイアウト属性 [`android:filterTouchesWhenObscured="true"`](https://developer.android.com/reference/android/view/View#attr_android:filterTouchesWhenObscured) を設定する、または、ログインボタン、支払い確認、パーミッションリクエストなどの機密性の高いビューに対してプログラムで [`setFilterTouchesWhenObscured(true)`](https://developer.android.com/reference/android/view/View#setFilterTouchesWhenObscured(boolean)) を呼び出します。これはそのビューが別の表示ウィンドウによって隠されている場合にタッチイベントをフィルタします。

3. **`onFilterTouchEventForSecurity` をオーバーライドする**: より細かな制御を行い、アプリ固有の要件に基づいてカスタムセキュリティポリシーを実装するには、[`onFilterTouchEventForSecurity`](https://developer.android.com/reference/android/view/View#onFilterTouchEventForSecurity(android.view.MotionEvent)) メソッドをオーバーライドします。

## 検出メカニズム

これらのメカニズムはオーバーレイが存在する際に検出しますが、自動的に阻止するわけではありません。アプリが以下に応じて対応できるようにします。

- タッチイベントハンドラで [`FLAG_WINDOW_IS_OBSCURED`](https://developer.android.com/reference/android/view/MotionEvent#FLAG_WINDOW_IS_OBSCURED) (API レベル 9 以降) や [`FLAG_WINDOW_IS_PARTIALLY_OBSCURED`](https://developer.android.com/reference/android/view/MotionEvent#FLAG_WINDOW_IS_PARTIALLY_OBSCURED) (API レベル 29 以降) などの **モーションイベントフラグをチェック** して、隠れたウィンドウを検出し、適切に対応します。このアプローチは、検出されたオーバーレイの処理方法を決定するためにカスタム実装を必要とすることに注意してください。

これらの保護は、以下のように、ユーザーによる確認が不可欠なセキュリティ上重要な UI 要素に選択的に適用します。

- ログインおよび認証画面
- パーミッションリクエストダイアログ
- 支払い確認ボタン
- 機密データ入力フィールド
- セキュリティ設定変更

## 注意事項と考慮事項

- システムレベルの脆弱性がある古い Android バージョンでは、タッチフィルタリングは完全な解決策ではありません。アプリは可能な限り最新の API レベルをターゲットにすべきです。
- 一部の攻撃、特にシステムレベルの脆弱性を悪用するもの (たとえば、Android 8.0 より前のオーバーレイ)、はアプリレベルでは完全には緩和できません。
- タッチフィルタリングを広範囲に適用しすぎると、オーバーレイが想定される正当なユースケース (たとえば、システムダイアログ、アクセシビリティ機能) に影響を及ぼす可能性があります。
- タッチフィルタリングを有効にしても、依然としてソーシャルエンジニアリングによってユーザーが騙される可能性があります。アプリはこれらの保護に加えて、ユーザー教育と明確な UI 表示を組み合わせるべきです。
- 最大限の保護のために、古い API レベルをターゲットとするアプリは、新しい Android バージョンで導入されたプラットフォームレベルの保護を利用するように、`targetSdkVersion` をアップグレードすることを検討すべきです。
