---
title: uber-apk-signer
platform: android
source: https://github.com/patrickfav/uber-apk-signer
---

uber-apk-signer は、デバッグ証明書または提供されたリリース証明書で一つ以上の Android アプリケーションパッケージ (APK) に署名、[zip align](https://developer.android.com/studio/command-line/zipalign.html)、検証するのに役立つツールです。v1、v2、[v3](https://source.android.com/security/apksigning/v3)、[v4](https://source.android.com/security/apksigning/v4) の Android 署名スキームをサポートしています。組み込みのデバッグキーストアで簡単で便利にデバッグ署名します。署名後、自動的に署名と zip アラインメントを検証します。

[最新リリース](https://github.com/patrickfav/uber-apk-signer/releases/latest) から jar をダウンロードして以下を実行します。

```bash
$ java -jar uber-apk-signer.jar --apks </path/to/apks>
```

デモ:

[![asciicast](https://asciinema.org/a/91092.png)](https://asciinema.org/a/91092)

詳細については [GitHub リポジトリ](https://github.com/patrickfav/uber-apk-signer) をご覧ください。
