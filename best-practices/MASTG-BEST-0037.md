---
title: 登録変更時に生体鍵を無効にする (Invalidate Biometric Keys on Enrollment Changes)
alias: invalidate-biometric-keys-on-enrollment-changes
id: MASTG-BEST-0037
platform: android
knowledge: [MASTG-KNOW-0001]
---

生体認証に暗号鍵を生成する場合、新しい生体情報が登録された際に鍵が無効化されるようにします。[`setInvalidatedByBiometricEnrollment(true)`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setInvalidatedByBiometricEnrollment(boolean)) を明示的に設定するか、`setUserAuthenticationRequired(true)` が設定されている場合に鍵を無効化するデフォルトの動作に任せます。

`setInvalidatedByBiometricEnrollment(false)` が使用される場合、新しい生体情報が登録された後でも鍵は有効なままとなります。デバイスパスコードを入手した攻撃者は新しい生体情報を登録し、既存の暗号化データにアクセスするために使用したり、機密性の高い操作をトリガーする可能性があります。

登録情報の変更時に鍵を無効化することにより、鍵作成時に登録されていた生体情報のみがアンロックでき、新たに登録された生体情報が以前に保護されているデータにアクセスすることを防止します。

> [!NOTE]
> 新しい生体情報が登録されると、鍵は即時かつ永久に無効になります。アプリは [`KeyPermanentlyInvalidatedException`](https://developer.android.com/reference/android/security/keystore/KeyPermanentlyInvalidatedException) を処理し、新しい鍵を作成して再認証するようにユーザーを誘導する必要があります。
