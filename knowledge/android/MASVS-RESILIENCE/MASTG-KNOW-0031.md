---
masvs_category: MASVS-RESILIENCE
platform: android
title: エミュレータの検出 (Emulator Detection)
---

アンチリバースのコンテキストでは、エミュレータ検出の目的はエミュレートされたデバイス上でアプリを実行する難易度を上げて、リバースエンジニアが好んで使用するツールや技法を阻むことです。この難易度の上昇により、リバースエンジニアはエミュレータチェックを破るか物理デバイスを利用することを余儀なくされ、大規模なデバイス解析に必要なアクセスを妨げます。

問題のデバイスがエミュレートされていることを示すインジケータはいくつかあります。これらの API 呼び出しはすべてフックできますが、これらのインジケータはささやかな防御の第一線を提供します。

インジケータの最初のセットは `build.prop` ファイル内にあります。

```default
API Method          Value           Meaning
Build.ABI           armeabi         possibly emulator
BUILD.ABI2          unknown         possibly emulator
Build.BOARD         unknown         emulator
Build.Brand         generic         emulator
Build.DEVICE        generic         emulator
Build.FINGERPRINT   generic         emulator
Build.Hardware      goldfish        emulator
Build.Host          android-test    possibly emulator
Build.ID            FRF91           emulator
Build.MANUFACTURER  unknown         emulator
Build.MODEL         sdk             emulator
Build.PRODUCT       sdk             emulator
Build.RADIO         unknown         possibly emulator
Build.SERIAL        null            emulator
Build.USER          android-build   emulator
```

ルート化された Android デバイスで `build.prop` ファイルを編集したり、ソースから AOSP をコンパイルするときにファイルを改変できます。いずれの技法でも上記の静的文字列チェックをバイパスできます。

次の静的インジケータのセットはテレフォニーマネージャを利用します。すべての Android エミュレータはこの API がクエリできる固定値があります。

```default
API                                                     Value                   Meaning
TelephonyManager.getDeviceId()                          0's                     emulator
TelephonyManager.getLine1 Number()                      155552155               emulator
TelephonyManager.getNetworkCountryIso()                 us                      possibly emulator
TelephonyManager.getNetworkType()                       3                       possibly emulator
TelephonyManager.getNetworkOperator().substring(0,3)    310                     possibly emulator
TelephonyManager.getNetworkOperator().substring(3)      260                     possibly emulator
TelephonyManager.getPhoneType()                         1                       possibly emulator
TelephonyManager.getSimCountryIso()                     us                      possibly emulator
TelephonyManager.getSimSerial Number()                  89014103211118510720    emulator
TelephonyManager.getSubscriberId()                      310260000000000         emulator
TelephonyManager.getVoiceMailNumber()                   15552175049             emulator
```

Xposed や Frida などのフックフレームワークはこの API をフックして偽のデータを提供する可能性があることを心に留めてください。
