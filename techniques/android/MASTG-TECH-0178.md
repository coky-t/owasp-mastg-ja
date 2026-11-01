---
title: スクリーンショットの撮影 (Taking Screenshots)
platform: android
---

スクリーンショットは、アプリが特定の時点にスクリーン上に表示しているものを示します。それらは、たとえば、手動検証の際に、証跡としたり、スクリーンがどのデータを表示しているかを確認するのに役立ちます。しかし、それらはピクセルを捕捉するだけであり、ビューがアクセシビリティデータセンシティブとしてマークされているかどうかといった、UI 要素のいずれのプロパティも明らかにしません。それらのプロパティを検査するには、[UI 階層の評価 (Inspecting the UI Hierarchy)](MASTG-TECH-0177.md) を参照してください。

[`FLAG_SECURE`](https://developer.android.com/reference/android/view/WindowManager.LayoutParams#FLAG_SECURE) を使用するウィンドウは、これらの手法で撮影したスクリーンショットでは黒く表示します。

## [adb](../../tools/android/MASTG-TOOL-0004.md) を使用する

`screencap` コマンドを使用してスクリーンをキャプチャし、その PNG 画像を直接コンピュータに書き出します。

```bash
adb exec-out screencap -p > screenshot.png
```

## [Android CLI](../../tools/android/MASTG-TOOL-0155.md) を使用する

`screen capture` コマンドを使用します。

```bash
android screen capture --output=screenshot.png
```

`--annotate` を追加して、スクリーン上で検出された UI 要素の周りにラベル付きのバウンディングボックスを描画します。そのスクリーンを文書化する際、特定の要素を指し示すのに役立ちます。

## [Maestro](../../tools/generic/MASTG-TOOL-0154.md) を使用する

フロー内で `takeScreenshot` コマンドを使用して、たとえば、フローが機密データを扱うスクリーンへ遷移した後など、特定の時点でのスクリーンをキャプチャします。

```yaml
appId: org.owasp.mastestapp
---
- tapOn: "Start"
- takeScreenshot: payment-form
```

これは、複数のスクリーンのスクリーンショットを必要としたり、同じスクリーンを繰り返しキャプチャしたい場合に役立ちます。
