---
masvs_category: MASVS-RESILIENCE
platform: ios
title: エミュレータ検出 (Emulator Detection)
---

エミュレータ検出の目標はエミュレートされたデバイス上でアプリを実行する難易度を上げることです。これにより、リバースエンジニアはエミュレータチェックを無効にするか、物理デバイスを利用することを余儀なくされ、大規模なデバイス解析に必要なアクセスができなくなります。

セキュリティテスト入門の章の [iOS シミュレータ上でのテスト](../../../Document/0x06b-iOS-Security-Testing.md#testing-on-the-ios-simulator "Testing on the iOS Simulator") セクションで説明したように、利用可能なシミュレータは Xcode に同梱されているものだけです。シミュレータバイナリは ARM コードではなく x86 コードにコンパイルされており、実デバイス (ARM アーキテクチャ) 用にコンパイルされたアプリはシミュレータでは動作しないため、幅広い _エミュレーション_ 選択肢が利用できる Android とは対照的に、 iOS アプリに関して _シミュレーション_ 保護はそれほど気にする必要はありませんでした。

しかし、 [Corellium](https://www.corellium.com/) (商用ツール) はそのリリース以来、リアルエミュレーションを可能にし、 [iOS シミュレータとは一線を画しています](https://www.corellium.com/compare/ios-simulator "Corellium vs Apple\'s iOS Simulator") 。それに加えて、SaaS ソリューションであるため、Corellium は資金的な制約のみで大規模なデバイス解析が可能です。

Apple Silicon (ARM) ハードウェアが広く普及しているため、x86 / x64 アーキテクチャの存在を確認する従来のチェックでは不十分なことがあります。潜在的な検出戦略の一つとして一般的に使用されるエミュレーションソリューションで利用可能な機能と制限を特定することがあります。たとえば、Corellium は iCloud、セルラーサービス、カメラ、NFC、Bluetooth、App Store アクセス、GPU ハードウェアエミュレーション ([Metal](https://developer.apple.com/documentation/metal/gpu_devices_and_work_submission/getting_the_default_gpu "Apple Metal Framework")) をサポートしていません。したがって、これらの機能のいずれかを含むチェックを賢く組み合わせることで、エミュレートされた環境の存在を示す指標となる可能性があります。
