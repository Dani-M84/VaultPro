[app]
title = VaultPro
package.name = vaultpro
package.domain = com.danim.vaultpro

source.dir = .
source.include_exts = py,png,jpg,kv,atlas,json,ttf

version = 2.0
requirements = python3,kivy,kivymd,pyjnius,cryptography,pyotp

orientation = portrait
fullscreen = 0

android.permissions = USE_BIOMETRIC,USE_FINGERPRINT
android.api = 33
android.minapi = 24
android.ndk = 25b
android.accept_sdk_license = True
android.archs = arm64-v8a

[buildozer]
log_level = 2
warn_on_root = 1
