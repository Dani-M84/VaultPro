
[app]
title = VaultPro A36
package.name = vaultpro
package.domain = com.danim.vaultpro
source.dir = .
source.include_exts = py
version = 4.0
requirements = python3,kivy==2.3.0,cryptography==41.0.7,pyotp
orientation = portrait
fullscreen = 0
android.permissions = INTERNET
android.api = 33
android.minapi = 24
android.ndk = 25b
android.accept_sdk_license = True
android.archs = arm64-v8a
p4a.bootstrap = sdl2
[buildozer]
log_level = 1
warn_on_root = 1
