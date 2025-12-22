---
masvs_category: MASVS-STORAGE
platform: ios
title: プロセス間通信 (IPC) メカニズム (Inter-Process Communication (IPC) Mechanisms)
---

[プロセス間通信 (IPC)](https://nshipster.com/inter-process-communication/ "IPC on iOS") はプロセスが互いにメッセージやデータを送信することを許可します。互いに通信する必要があるプロセスには、iOS 上で IPC を実装する方法がいくつかあります。

- **[XPC サービス](https://developer.apple.com/library/content/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html "XPC Services")**: XPC は基本的なプロセス間通信を提供する構造化された非同期ライブラリです。これは `launchd` によって管理されます。これは iOS 上の IPC の最も安全で柔軟な実装であり、推奨される手法です。これは、ルート権限昇格がなく、ファイルシステムアクセスとネットワークアクセスを最小限に抑えてサンドボックス化された、可能な限り最も制限された環境で実行します。二つの異なる API が XPC サービスで使用されます。
    - NSXPCConnection API
    - XPC Services API
- **[Mach Port](https://developer.apple.com/documentation/foundation/nsmachport "NSMachPort")**: すべての IPC 通信は最終的に Mach カーネル API に依存します。Mach Port はローカル通信 (デバイス内通信) のみを許可します。ネイティブに実装することも、Core Foundation (CFMachPort) および Foundation (NSMachPort) ラッパーを介して実装することもできます。
- **NSFileCoordinator**: `NSFileCoordinator` クラスを使用し、ローカルファイルシステム上で利用可能なファイルを介してアプリ間でデータを管理したり、さまざまなプロセスにデータを送信できます。[NSFileCoordinator](https://www.atomicbird.com/blog/sharing-with-app-extensions "NSFileCoordinator") メソッドは同期的に実行するため、実行を停止するまでコードはブロックされます。これは非同期ブロックコールバックを待つ必要がないため便利ですが、メソッドが実行中のスレッドをブロックすることも意味します。
