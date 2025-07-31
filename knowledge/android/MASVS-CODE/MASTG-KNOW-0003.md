---
masvs_category: MASVS-CODE
platform: android
title: アプリ署名 (App Signing)
---

Android ではすべての APK はインストールまたは実行する前に証明書でデジタル署名する必要があります。デジタル署名はアプリケーションの更新で所有者の身元を確認するためにも使用されます。このプロセスによりアプリが不正なコードを含むような改竄や改変を防ぐことができます。

APK に署名すると、公開鍵証明書が APK に添付されます。この証明書は APK を開発者および開発者の秘密鍵に一意に関連付けます。デバッグモードでアプリをビルドすると、Android SDK はデバッグ目的専用に作成されたデバッグ鍵でアプリに署名します。デバッグ鍵で署名されたアプリは配布されることを意図しておらず、Google Play ストアを含むほとんどのアプリストアで受け入れられません。

アプリの [最終リリースビルド](https://developer.android.com/studio/publish/app-signing.html "Android Application Signing") は有効なリリース鍵で署名されている必要があります。Android Studio では、アプリを手動で署名するかリリースビルドタイプに割り当てられた署名構成を作成することで署名できます。

Android 9 (API level 28) 以前では Android 上のすべてのアプリ更新に同じ証明書で署名されている必要があるため、[25年以上の有効期間が推奨されます](https://developer.android.com/studio/publish/app-signing#considerations "Android Signing Considerations") 。Google Play に公開されるアプリは2033年10月22日以降に終了する有効期間を持つ鍵で署名する必要があります。

三つの APK 署名スキームが利用可能です。

- JAR 署名 (v1 スキーム)
- APK 署名スキーム v2 (v2 スキーム)
- APK 署名スキーム v3 (v3 スキーム)

Android 7.0 (API level 24) 以上でサポートされている v2 署名は v1 スキームと比較してセキュリティとパフォーマンスが向上しています。
Android 9 (API level 28) 以上でサポートされている v3 署名により、アプリは APK 更新の一部として署名鍵を変更できます。この機能は新しい鍵と古い鍵の両方を使用できるようにすることで互換性とアプリの継続的な可用性を保証します。執筆時点では [apksigner](../../../tools/android/MASTG-TOOL-0123.md) を介してのみ利用可能であることに注意します。

それぞれの署名スキームに対して、リリースビルドでは常に以前のすべてのスキームも使用して署名される必要があります。
