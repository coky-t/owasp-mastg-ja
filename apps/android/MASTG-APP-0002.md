---
title: Android License Validator
platform: android
source: https://mas.owasp.org/crackmes/Android#android-license-validator
---

Android License Validator はネイティブコードでキーバリデーション機能を実装した crackme であり、Android デバイス用のスタンドアロン ELF 実行可能ファイルとしてパッケージ化されています。ネイティブコードの解析は Java よりも困難なことが多く、これが重要なビジネスロジックがこの方法で記述されることが多い理由です。

このサンプルアプリケーションは現実世界のシナリオを表していないかもしれませんが、シンボリック実行の基本を理解するための貴重な学習ツールとして役に立ちます。これらの洞察は実践的な状況、特に難読化されたネイティブライブラリを含む Android アプリを扱う際、に適用できます。実際、難読化されたコードは、特に難読化解除のプロセスをより困難にするために、ネイティブライブラリに入れられることがよくあります。

> [Bernhard Mueller](https://github.com/muellerberndt "Bernhard Mueller") より
