---
masvs_v1_id:
- MSTG-PLATFORM-4
masvs_v2_id:
- MASVS-PLATFORM-1
platform: android
title: PendingIntent の脆弱な実装のテスト (Testing for Vulnerable Implementation of PendingIntent)
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## 概要

[Pending Intents](../../../Document/0x05h-Testing-Platform-Interaction.md#pending-intents) をテストする際には、それらが不変であり、アプリがベースインテントを受け取る正確なパッケージ、アクション、コンポーネントを指定していることを確認しなければなりません。

## 静的解析

脆弱な実装を特定するには、静的解析は `PendingIntent` を取得するために使用される API コールを探すことで実行できます。そのような API を以下に示します。

```java
PendingIntent getActivity(Context, int, Intent, int)
PendingIntent getActivity(Context, int, Intent, int, Bundle)
PendingIntent getActivities(Context, int, Intent, int, Bundle)
PendingIntent getActivities(Context, int, Intent, int)
PendingIntent getForegroundService(Context, int, Intent, int)
PendingIntent getService(Context, int, Intent, int)
```

上記の関数のいずれかが見つかったら、[Pending Intents](../../../Document/0x05h-Testing-Platform-Interaction.md#pending-intents) セクションに記載されているセキュリティ上の落とし穴がないか、ベースインテントと `PendingIntent` の実装をチェックします。

たとえば、[A-156959408](https://android.googlesource.com/platform/frameworks/base/+/6ae2bd0e59636254c32896f7f01379d1d704f42d "A-156959408")(CVE-2020-0389) では、ベースインテントが暗黙的であり `PendingIntent` も変更可能であるため、悪用される可能性があります。

```java
private Notification createSaveNotification(Uri uri) {
    Intent viewIntent = new Intent(Intent.ACTION_VIEW)
            .setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_GRANT_READ_URI_PERMISSION)
            .setDataAndType(uri, "video/mp4"); //Implicit Intent

//... skip ...


Notification.Builder builder = new Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_android)
                .setContentTitle(getResources().getString(R.string.screenrecord_name))
                .setContentText(getResources().getString(R.string.screenrecord_save_message))
                .setContentIntent(PendingIntent.getActivity(
                        this,
                        REQUEST_CODE,
                        viewIntent,
                        Intent.FLAG_GRANT_READ_URI_PERMISSION))     // Mutable PendingIntent.
                .addAction(shareAction)
                .addAction(deleteAction)
                .setAutoCancel(true);

```

## 動的解析

Frida を使用して、`PendingIntent` を取得するために使用される API をフックできます。この情報を使用してコールのコード位置を判断し、さらに上記のように静的解析を実行するために使用できます。

以下は `PendingIntent.getActivity` 関数をフックするために使用できるいわゆる Frida スクリプトの例です。

```javascript
var pendingIntent = Java.use('android.app.PendingIntent');

var getActivity_1 = pendingIntent.getActivity.overload("android.content.Context", "int", "android.content.Intent", "int");

getActivity_1.implementation = function(context, requestCode, intent, flags){
    console.log("[*] Calling PendingIntent.getActivity("+intent.getAction()+")");
    console.log("\t[-] Base Intent toString: " + intent.toString());
    console.log("\t[-] Base Intent getExtras: " + intent.getExtras());
    console.log("\t[-] Base Intent getFlags: " + intent.getFlags());
    return this.getActivity(context, requestCode, intent, flags);
}
```

このアプローチは、制御フローを判断することが難しいことがある、大規模なコードベースを持つアプリケーションを扱う場合に役立ちます。
