---
masvs_v1_id:
- MSTG-STORAGE-9
masvs_v2_id:
- MASVS-PLATFORM-3
platform: ios
title: 自動生成されたスクリーンショットの機密情報についてのテスト (Testing Auto-Generated Screenshots for Sensitive Information)
masvs_v1_levels:
- L2
---

## 概要

## 静的解析

ソースコードがある場合、[`applicationDidEnterBackground`](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/1622997-applicationdidenterbackground) メソッドを検索して、アプリケーションがバックグラウンドになる前に画面をサニタイズしているかどうかを調べます。

以下は、アプリケーションがバックグラウンドになるたびに、デフォルトのバックグラウンド画像 (`overlayImage.png`) を使用して、現在のビューをオーバーライドするサンプル実装です。

Swift:

```swift
private var backgroundImage: UIImageView?

func applicationDidEnterBackground(_ application: UIApplication) {
    let myBanner = UIImageView(image: #imageLiteral(resourceName: "overlayImage"))
    myBanner.frame = UIScreen.main.bounds
    backgroundImage = myBanner
    window?.addSubview(myBanner)
}

func applicationWillEnterForeground(_ application: UIApplication) {
    backgroundImage?.removeFromSuperview()
}
```

Objective-C:

```objectivec
@property (UIImageView *)backgroundImage;

- (void)applicationDidEnterBackground:(UIApplication *)application {
    UIImageView *myBanner = [[UIImageView alloc] initWithImage:@"overlayImage.png"];
    self.backgroundImage = myBanner;
    self.backgroundImage.bounds = UIScreen.mainScreen.bounds;
    [self.window addSubview:myBanner];
}

- (void)applicationWillEnterForeground:(UIApplication *)application {
    [self.backgroundImage removeFromSuperview];
}
```

これはアプリケーションがバックグラウンドになるたびにバックグラウンド画像を `overlayImage.png` に設定します。`overlayImage.png` が常に現在のビューを上書きするため、機密データ漏洩を防止できます。

## 動的解析

_視覚的なアプローチ_ を使用し、iOS デバイス (脱獄済みかどうかに関わらず) を使用して、このテストケースをすばやく検証できます。

1. ユーザー名、電子メールアドレス、アカウントの詳細など、機密情報を表示するアプリケーション画面に移動します。
2. iOS デバイスで **ホーム** ボタンを押して、アプリケーションをバックグラウンドにします。
3. 機密情報を含むビューではなく、デフォルト画像がトップビュー要素として表示されていることを検証します。

必要に応じて、Frida Gadget ([非脱獄デバイスでの動的解析 (Dynamic Analysis on Non-Jailbroken Devices)](../../../techniques/ios/MASTG-TECH-0079.md)) で再パッケージ化した後、脱獄済みデバイスまたは非脱獄デバイスで手順 1 から 3 を実行して証跡を収集することもできます。その後、SSH ([デバイスシェルへのアクセス (Accessing the Device Shell)](../../../techniques/ios/MASTG-TECH-0052.md)) またはその他の手段 ([ホストとデバイス間のデータ転送 (Host-Device Data Transfer)](../../../techniques/ios/MASTG-TECH-0053.md)) を使用して iOS デバイスに接続し、Snapshots ディレクトリに移動します。場所は iOS のバージョンによって異なりますが、通常はアプリの Library ディレクトリにあります。たとえば、iOS 14.5 では Snapshots ディレクトリは以下の場所にあります。

```txt
/var/mobile/Containers/Data/Application/$APP_ID/Library/SplashBoard/Snapshots/sceneID:$APP_NAME-default/
```

そのフォルダのスクリーンショットには機密情報が含まれていてはいけません。
