---
title: ライブラリを IPA 内に手作業で注入する (Injecting Libraries into an IPA Manually)
platform: ios
---

この技法は IPA ファイルに任意のライブラリを注入できます。ライブラリを注入した後、[アプリのインストール (Installing Apps)](MASTG-TECH-0056.md) を使用して、改変した IPA をデバイスにインストールする必要があります。

この技法は、アプリケーションに機能やテスト機能を追加したい場合に適しています。たとえば、IPA ファイルに Frida Gadget を注入して、アプリケーションの動的計装を可能にできます。

例として Frida Gadget (`FridaGadget.dylib`) を使用しますが、この技法を使用して、希望する任意の `.dylib` ライブラリを注入できます。

## ライブラリを入手する

この例では、Frida Gadget というライブラリを対象とします。Frida プロジェクトの [GitHub リリースページ](https://github.com/frida/frida/releases) からダウンロードできます。ターゲットプラットフォームと一致する最新リリースを探し、`frida-gadget-XX.YY.ZZ-ios-universal.dylib.xz` ファイルをダウンロードします。

`xz` ツールを使用してファイルを展開し、`FridaGadget.dylib` として保存します。

```bash
xz -d <frida-gadget-XX.YY.ZZ-ios-universal.dylib.xz> -c > FridaGadget.dylib
```

## IPA にライブラリを追加する

IPA ファイルは ZIP アーカイブですので、任意の ZIP ツールを使用してアーカイブをアンパックできます。

```bash
unzip UnCrackable-Level1.ipa
```

次に、ターゲットライブラリ、この場合では `FridaGadget.dylib`、を `.app/Frameworks` ディレクトリにコピーします (ディレクトリが存在しない場合は作成します)。

```bash
mkdir -p Payload/UnCrackable\ Level\ 1.app/Frameworks
cp FridaGadget.dylib Payload/UnCrackable\ Level\ 1.app/Frameworks/
```

[optool](../../tools/ios/MASTG-TOOL-0059.md) を使用して、バイナリに `load` コマンド (`LC_LOAD_DYLIB`) を追加します。以下のコードは [iOS UnCrackable L1](../../apps/ios/MASTG-APP-0025.md) に対してこれを行う方法を示しています。

```bash
optool install -c load -p "@executable_path/Frameworks/FridaGadget.dylib"  -t Payload/UnCrackable\ Level\ 1.app/UnCrackable\ Level\ 1

Found FAT Header
Found thin header...
Found thin header...
Inserting a LC_LOAD_DYLIB command for architecture: arm
Successfully inserted a LC_LOAD_DYLIB command for arm
Inserting a LC_LOAD_DYLIB command for architecture: arm64
Successfully inserted a LC_LOAD_DYLIB command for arm64
Writing executable to Payload/UnCrackable Level 1.app/UnCrackable Level 1...
```

`load` コマンドを注入した後、IPA を再パッケージする必要があります。

```bash
zip -r patched.ipa Payload
```

App Store から入手した iOS アプリケーションをデバッグするには、`get-task-allow` エンタイトルメントを含む開発プロビジョニングプロファイルで再署名する必要があります。アプリをデバッグ可能にするパッチ適用の完全なワークフローは [パッチ適用 (Patching)](MASTG-TECH-0147.md) を参照してください。
