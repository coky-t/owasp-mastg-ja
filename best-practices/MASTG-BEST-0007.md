---
title: AndroidManifest のデバッグフラグを無効にする (Debuggable Flag Disabled in the AndroidManifest)
alias: debuggable-flag-disabled
id: MASTG-BEST-0007
platform: android
knowledge: [MASTG-KNOW-0007]
---

すべてのリリースビルドで AndroidManifest.xml の debuggable フラグが `false` に設定されていることを確認します。

**注:** `debuggable` フラグでデバッグを無効にすることは重要な第一歩ですが、高度な攻撃からアプリを完全に保護するわけではありません。熟練した攻撃者は、バイナリパッチ ([パッチ適用 (Patching)](../techniques/android/MASTG-TECH-0038.md) を参照) でデバッガをアタッチできるようにしたり、[Frida (Android)](../tools/android/MASTG-TOOL-0001.md) などのバイナリ計装ツールを使用して同様の機能を実現するなど、さまざまな方法でデバッグを有効にすることができます。より高いレベルのセキュリティを必要とするアプリでは、追加の防御層としてアンチデバッグ技法の実装を検討してください。詳細なガイダンスについては [デバッガ検出が実装されていない (Debugger Detection Not Implemented)](../weaknesses/MASVS-RESILIENCE/MASWE-0101.md) を参照してください。
