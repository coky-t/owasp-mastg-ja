---
masvs_v1_id:
- MSTG-ARCH-9
masvs_v2_id:
- MASVS-CODE-2
platform: android
title: 強制更新のテスト (Testing Enforced Updating)
masvs_v1_levels:
- L2
---

## 概要

[強制更新](../../../Document/0x05h-Testing-Platform-Interaction.md#enforced-updating "Enforced Updating") をテストするには、アプリがアプリ内更新をサポートしているかどうかをチェックし、ユーザーが最初に更新せずにアプリを使い続けることができないように、適切に強制されているかどうかを検証する必要があります。

## 静的解析

以下のコードサンプルはアプリ更新の例を示しています。

```java
//Part 1: check for update
// Creates instance of the manager.
AppUpdateManager appUpdateManager = AppUpdateManagerFactory.create(context);

// Returns an intent object that you use to check for an update.
Task<AppUpdateInfo> appUpdateInfo = appUpdateManager.getAppUpdateInfo();

// Checks that the platform will allow the specified type of update.
if (appUpdateInfo.updateAvailability() == UpdateAvailability.UPDATE_AVAILABLE
      // For a flexible update, use AppUpdateType.FLEXIBLE
      && appUpdateInfo.isUpdateTypeAllowed(AppUpdateType.IMMEDIATE)) {



                  //...Part 2: request update
                  appUpdateManager.startUpdateFlowForResult(
                     // Pass the intent that is returned by 'getAppUpdateInfo()'.
                     appUpdateInfo,
                     // Or 'AppUpdateType.FLEXIBLE' for flexible updates.
                     AppUpdateType.IMMEDIATE,
                     // The current activity making the update request.
                     this,
                     // Include a request code to later monitor this update request.
                     MY_REQUEST_CODE);



                     //...Part 3: check if update completed successfully
 @Override
 public void onActivityResult(int requestCode, int resultCode, Intent data) {
   if (myRequestCode == MY_REQUEST_CODE) {
     if (resultCode != RESULT_OK) {
       log("Update flow failed! Result code: " + resultCode);
       // If the update is cancelled or fails,
       // you can request to start the update again in case of forced updates
     }
   }
 }

 //..Part 4:
 // Checks that the update is not stalled during 'onResume()'.
// However, you should execute this check at all entry points into the app.
@Override
protected void onResume() {
  super.onResume();

  appUpdateManager
      .getAppUpdateInfo()
      .addOnSuccessListener(
          appUpdateInfo -> {
            ...
            if (appUpdateInfo.updateAvailability()
                == UpdateAvailability.DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS) {
                // If an in-app update is already running, resume the update.
                manager.startUpdateFlowForResult(
                    appUpdateInfo,
                    IMMEDIATE,
                    this,
                    MY_REQUEST_CODE);
            }
          });
}
}
```

>出典: [https://developer.android.com/guide/app-bundle/in-app-updates](https://developer.android.com/guide/app-bundle/in-app-updates "Support in-app updates")

## 動的解析

適切な更新をテストするには、開発者からのリリースやサードパーティのアプリストアを使用して、セキュリティ脆弱性のある古いバージョンのアプリケーションをダウンロードしてみます。
次に、アプリケーションを更新せずに使用し続けることができるかどうかを検証します。更新プロンプトが表示された場合、そのプロンプトをキャンセルするか、通常のアプリケーションの使用によってプロンプトを回避して、アプリケーションを引き続き使用できるかどうかを検証します。これには、バックエンドが脆弱なバックエンドへの呼び出しを停止するかどうかや、脆弱なアプリバージョン自体がバックエンドによってブロックされているかどうかを検証することを含みます。
最後に、MIMT プロキシを使用してトラフィックを傍受しながらアプリのバージョン番号を変更してみて、バックエンドがどのように応答するか (その変更が記録されるかどうかなど) を観察します。
