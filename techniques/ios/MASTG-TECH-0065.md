---
title: iOS アプリのリバースエンジニアリング (Reverse Engineering iOS Apps)
platform: ios
---

iOS リバースエンジニアリングは良い面と悪い面が入り混じっています。一方では、Objective-C と Swift でプログラムされたアプリはうまく逆アセンブルできます。Objective-C では、オブジェクトメソッドは「セレクタ」と呼ばれる動的関数ポインタを介して呼び出され、実行時に名前によって解決されます。実行時の名前解決の利点は、これらの名前が最終的なバイナリでそのまま残る必要があるため、逆アセンブリがより読みやすくなることです。残念ながら、これは逆アセンブラでメソッド間の直接的な相互参照が利用できないことも意味し、フローグラフの構築が困難になります。

## 参考情報

- [#miller] - Charlie Miller, Dino Dai Zovi. The iOS Hacker's Handbook. Wiley, 2012 - <https://www.wiley.com/en-us/iOS+Hacker%27s+Handbook-p-9781118204122>
- [#levin] Jonathan Levin. Mac OS X and iOS Internals: To the Apple's Core. Wiley, 2013 - <http://newosxbook.com/MOXiI.pdf>
