---
title: blint
platform: android
source: https://github.com/owasp-dep-scan/blint
---

blint は、実行ファイルのセキュリティプロパティと機能をチェックする Binary Linter です。バージョン 2 以降、`blint` はサポートされているバイナリのソフトウェア部品表 (SBOM) を生成できます。これには Android (APK および AAB) を含みますが、iOS (IPA) アプリは含みません。

Android アプリ (APK または AAB) からの SBOM の生成はサポートされていますが、[制限があります](https://github.com/owasp-dep-scan/blint/issues/119)。アプリで使用されるライブラリのメタ情報が削除されるため、Android アプリから作成された SBOM は常に不完全になります。

blint はブラックボックスセキュリティ評価の選択肢になりますが、グレー/ホワイトボックステストでは以下のような他のツールを優先すべきです。

- [dependency-check](../generic/MASTG-TOOL-0131.md)
- [dependency-track](../generic/MASTG-TOOL-0132.md)
- [cdxgen](../generic/MASTG-TOOL-0134.md)
