[app]
title = VaultPro
package.name = vaultpro
package.domain = com.danim.vaultpro
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,json,ttf
version = 2.1
requirements = python3,kivy==2.3.0,kivymd==1.2.0,pyjnius,cryptography,pyotp,openssl,libffi
orientation = portrait
fullscreen = 0
android.permissions = INTERNET
android.api = 33
android.minapi = 24
android.ndk = 25b
android.accept_sdk_license = True
android.archs = arm64-v8a, armeabi-v7a
p4a.bootstrap = sdl2
[buildozer]
log_level = 2
warn_on_root = 1
