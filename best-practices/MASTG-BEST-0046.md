---
title: エミュレーションに対する堅牢化 (Hardening Against Emulation)
alias: hardening-against-emulation
id: MASTG-BEST-0046
platform: android
knowledge: [MASTG-KNOW-0031, MASTG-KNOW-0035, MASTG-KNOW-0033, MASTG-KNOW-0030]
---

エミュレートされたデバイスは、ターゲットアプリケーションを、カスタムシステムイメージ、変更されたプラットフォームコンポーネント、アプリが検出しにくい計装を使用する可能性がある制御された環境で実行できます。これは高度なリバースエンジニアリング技法を可能にします。

エミュレートされたデバイスへの対策は、以下のような複数タイプのセキュリティコントロールを適用する多層的なアプローチが一般的です。

- **検出コントロール**: 一般的なデバイスエミュレータのインジケータとプロパティをスキャン ([エミュレータの検出 (Emulator Detection)](../knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0031.md)) して、Google Play Integrity API ([Google Play Integrity API](../knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0035.md)) を使用し、リスクのあるデバイス、エミュレートされている環境、変更されたアプリバイナリ、その他の信頼できないインタラクションを特定します。
- **抑止コントロール**: この検出ロジックを難読化 ([難読化 (Obfuscation)](../knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0033.md)) して、アプリ全体にチェックを分散し、そのタイミングを変化し、これらのチェックをバイパスするのに必要なコストと労力を高めます。
- **リバースエンジニアリングツールに対する堅牢化**: カスタム環境やエミュレートされた環境はしばしばそのようなツールと組み合わせられるため、リバースエンジニアリングツールの検出 ([リバースエンジニアリングツールの検出 (Detection of Reverse Engineering Tools)](../knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0030.md)) を実装します。
