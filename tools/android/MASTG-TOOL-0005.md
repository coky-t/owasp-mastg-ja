---
title: Android NDK
platform: android
source: https://developer.android.com/ndk/guides/standalone_toolchain
---

Android NDK はネイティブコンパイラとツールチェーンのビルド済みバージョンを含みます。GCC と Clang のコンパイラはどちらも従来からサポートされてきましたが、GCC のアクティブサポートは NDK バージョン 14 で終了しました。デバイスアーキテクチャとホスト OS によって適切なバージョンが決まります。ビルド済みツールチェーンは NDK の `toolchains` ディレクトリにあり、アーキテクチャごとに一つのサブディレクトリがあります。

| アーキテクチャ | ツールチェーン |
| --- | --- |
| ARM-based | arm-linux-androideabi-&lt;gcc-version&gt; |
| x86-based | x86-&lt;gcc-version&gt; |
| MIPS-based | mipsel-linux-android-&lt;gcc-version&gt; |
| ARM64-based | aarch64-linux-android-&lt;gcc-version&gt; |
| X86-64-based | x86_64-&lt;gcc-version&gt; |
| MIPS64-based | mips64el-linux-android-&lt;gcc-version&gt; |

適切なアーキテクチャを選択するだけでなく、ターゲットとするネイティブ API レベルに適した sysroot を指定する必要があります。sysroot はターゲットのシステムヘッダとライブラリを含むディレクトリです。ネイティブ API は Android API レベルによって異なります。Android API レベルごとに利用可能な sysroot ディレクトリは `$NDK/platforms/` にあります。各 API レベルディレクトリにはさまざまな CPU やアーキテクチャを含みます。

ビルドシステムをセットアップする方法の一つは、コンパイラパスと必要なフラグを環境変数としてエクスポートすることです。しかし、作業を簡単にするために、NDK では、必要な設定を組み込んだ一時的なツールチェーンである、いわゆるスタンドアロンツールチェーンを作成できます。

スタンドアロンツールチェーンをセットアップするには、[NDK の最新安定版](https://developer.android.com/ndk/downloads/index.html#stable-downloads "Android NDK Downloads") をダウンロードします。ZIP ファイルを展開して、NDK ルートディレクトリに移動し、以下のコマンドを実行します。

```bash
./build/tools/make_standalone_toolchain.py --arch arm --api 24 --install-dir /tmp/android-7-toolchain
```

これは Android 7.0 (API レベル 24) 用のスタンドアロンツールチェーンを `/tmp/android-7-toolchain` ディレクトリに作成します。利便性のために、ツールチェーンを指す環境変数をエクスポートできます (例ではこれを使用します)。以下のコマンドを実行するか、これを `.bash_profile` やその他のスタートアップスクリプトに追加します。

```bash
export TOOLCHAIN=/tmp/android-7-toolchain
```
