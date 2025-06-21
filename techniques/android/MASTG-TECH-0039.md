---
title: 再パッケージ化と再署名 (Repackaging & Re-Signing)
platform: android
---

## 再パッケージ化

以下を行うことで、アプリを簡単に再パッケージ化できます。

```bash
cd UnCrackable-Level1
apktool b
zipalign -v 4 dist/UnCrackable-Level1.apk ../UnCrackable-Repackaged.apk
```

Android Studio ビルドツールのディレクトリがパスにある必要があることに注意してください。`[SDK-Path]/build-tools/[version]` に位置しています。`zipalign` と `apksigner` のツールはこのディレクトリにあります。

## 再署名

[再署名](https://developer.android.com/studio/publish/app-signing) の前に、まずコード署名証明書が必要です。Android Studio で以前にプロジェクトをビルドしたことがある場合、IDE はすでにデバッグキーストアと証明書を `$HOME/.android/debug.keystore` に作成しています。このキーストアのデフォルトパスワードは "android" で、キーの名前は "androiddebugkey" です。

標準の Java ディストリビューションには、キーストアと証明書を管理する `keytool` を含みます。独自の署名証明書と鍵を作成して、デバッグキーストアに追加できます。

```bash
keytool -genkey -v -keystore ~/.android/debug.keystore -alias signkey -keyalg RSA -keysize 2048 -validity 20000
```

証明書が利用可能になったら、それで APK を再署名できます。`apksigner` がパスにあることと、再パッケージ化した APK が配置されているフォルダから実行していることを確認してください。

```bash
apksigner sign --ks  ~/.android/debug.keystore --ks-key-alias signkey UnCrackable-Repackaged.apk
```

注: `apksigner` で JRE 互換性問題が発生する場合、代わりに `jarsigner` を使用できます。この場合、`zipalign` は署名の **後** に呼び出す必要があります。

```bash
jarsigner -verbose -keystore ~/.android/debug.keystore ../UnCrackable-Repackaged.apk signkey
zipalign -v 4 dist/UnCrackable-Level1.apk ../UnCrackable-Repackaged.apk
```

これでアプリを再インストールできます。

```bash
adb install UnCrackable-Repackaged.apk
```
