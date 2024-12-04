---
title: アプリの再パッケージ化 (Repackaging Apps)
platform: android
---

脱獄していないデバイスでテストする必要がある場合は、アプリを再パッケージ化して動的テストを可能にする方法を学ぶべきです。

コンピュータを使用して、objection Wiki の記事 ["Patching Android Applications"](https://github.com/sensepost/objection/wiki/Patching-Android-Applications) に示されているすべての手順を実行します。完了したら、以下の objection コマンドを呼び出して APK にパッチを適用できるようになります。

```bash
objection patchapk --source app-release.apk
```

次に、パッチを適用したアプリケーションは adb を使用してインストールする必要があります。

> この再パッケージ化手法はほとんどのユースケースで十分です。より高度な再パッケージ化については、[再パッケージ化と再署名 (Repackaging & Re-Signing)](MASTG-TECH-0039.md) を参照してください。
