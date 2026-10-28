---
name: chuckle-paywall-removal
description: Remove the activation/subscription paywall from the Chuckle (app.jjyy.chuckle) Android client and keep the mod working across releases. Use when asked to strip 付费墙/激活/订阅 from a Chuckle APK, rebuild it after a version bump, or verify the patched build on a device.
---

# Chuckle paywall removal

Target: `app.jjyy.chuckle` (X/Twitter client, Kotlin + Jetpack Compose, obfuscated,
multi-dex, ships Play-signed). Goal: no paywall, no ads gating, premium gates open,
and the app still runs after re-signing.

Two equivalent delivery routes. **Prefer the smali route** for maintenance; keep
the dex-byte route as fallback when apktool cannot round-trip a release.

| Route | How | When |
|---|---|---|
| smali (primary) | `apktool d` → edit `.smali` bodies → `apktool b` | apktool round-trips cleanly |
| dex bytes (fallback) | `locate.py` → `build.py` patches opcodes in place | apktool fails, or you need a 30-byte surgical change |

Both end with: `zipalign -p 4` → `apksigner` with a local key → re-inject the
`{"channel":"app"}` signing-block pair → install with **uninstall** (signature change).

## Non-negotiable knowledge (learned the hard way)

1. **The app ties its theme to its own signature.** `igl`-style check decrypts an
   expected signer hash and compares it to `PackageManager`'s. On mismatch a Koin
   initializer swaps the theme provider (`xfn`) for an empty stub, so every
   `ColorStateList` is null and `RippleDrawable` construction throws
   `IllegalArgumentException: RippleDrawable requires a non-null color`. Re-signing
   alone is why the settings list and the home search bar crash. **Always patch the
   integrity predicate to `true` before blaming the paywall patches.**
2. **apktool needs `state_swiped` declared.** `res/color/m3_list_item_background_color_selector.xml`
   and `m3_segmented_list_item_background_color_selector.xml` reference
   `app:state_swiped`, whose attr entry is missing from `resources.arsc` (dangling id
   0x7f04067a in the shipped build). Without adding
   `<attr name="state_swiped" format="boolean" />` to `res/values/attrs.xml`, `apktool b`
   dies with `failed linking file resources`.
3. **Dex header order**: recompute SHA-1 over bytes 32..end first, then adler32 over
   bytes 12..end (the signature lives inside the checksum range).
4. **Patch length discipline** (dex route): replacements must be equal length or
   shorter + `nop` padding. Shrinking the array silently corrupts `file_size` and ART
   answers `ClassNotFoundException` for unrelated classes.
5. **Register count** (dex route): several two-line getters use only `v0`
   (`registers_size == 1`). Synthesizing an object needs a second register — bump
   `registers_size` at the code_item header (first uint16 at `code_off`).
6. **Opcode traps**: `iput-boolean` is `0x5c` (not `0x5a`, that is `iput-wide`);
   `const-string` is `0x1a`; `invoke-direct` 35c encodes `A` (arg count) in bits 12–15.
7. **Kotlin classes may have no `<init>`**: `lvm` is constructed with
   `invoke-direct {v0}, Ljava/lang/Object;-><init>()V`.
8. **Channel**: `on2` reads the APK Signing Block pair `0x71777777`
   (`{"channel":"app"}`); apksigner wipes it. Re-inject with `inject_channel.py`
   (inserting an ID-value pair does not invalidate v2/v3 because the block itself is
   not signed and the block start offset does not move).
9. **Re-install wipes the X login.** Uninstall deletes `/data/data/app.jjyy.chuckle`
   and the Keystore keys, so every install cycle means logging in again. Batch changes;
   warn the user; or use a spare arm64 device/ARM-host emulator.
10. **No x86 emulator**: the APK ships `lib/arm64-v8a` only. On an x86_64 AVD it dies
    at `UnsatisfiedLinkError`. Use a real arm64 device (or an ARM host emulator).

## Route A — smali (maintenance path)

```bash
# 0. tooling
java -jar tools/apktool.jar d -f -o out/apktool-dec app.apk    # ~20 s
# 1. one-time fix: declare the dangling attr
#    append <attr name="state_swiped" format="boolean" /> to res/values/attrs.xml
# 2. edit bodies (scripts/smali_patch.py does all five idempotently)
python scripts/smali_patch.py out/apktool-dec \
       --unactivated 0x7f140604 --activated 0x7f140601
# 3. rebuild and sign
java -jar tools/apktool.jar b out/apktool-dec -o out/built.apk
zipalign -f -p 4 out/built.apk out/aligned.apk
apksigner sign --ks local.keystore --ks-pass pass:... --out out/signed.apk out/aligned.apk
python scripts/inject_channel.py out/signed.apk out/final.apk
```

`smali_patch.py` rewrites these bodies (names from 1.1.1(154); re-locate via
`locate.py` after a version bump):

| file | method | body |
|---|---|---|
| `smali/q6.smali` | `oO0OO00()Z` | `const/4 v0, 0x0; return v0` — freemium off |
| `smali/q6.smali` | `oO0OOO0()Z` | `const/4 v0, 0x0; return v0` — no forced purchase |
| `smali_classes2/dvj.smali` | `oO0OOo()Z` | `const/4 v0, 0x1; return v0` — entitled |
| `smali_classes4/igl.smali` | `oO0OO00()Z` | `const/4 v0, 0x1; return v0` — integrity ok |
| `smali_classes2/dvj.smali` | `oO0OOo0()Llvm;` | build a record: code `"active"`, `expired=false` |
| `smali_classes2/cvj.smali` | — | `0x7f140604` → `0x7f140601` (未激活 → 已激活 label) |

Rebuild grows the APK (≈85.7 MB vs 80.2 MB) because resources are recompiled; harmless.

## Route B — dex bytes (surgical fallback)

```bash
python scripts/locate.py app.apk --json plan.json     # semantic targets + offsets
python scripts/build.py app.apk plan.json out.apk     # patches, signs, injects channel
```

`locate.py` finds targets by behaviour, not by name:

- freemium getter — `)Z` method reading RemoteConfig key `freemium_enable`
- forced-purchase — `)Z` method calling the class's enum-returning getter + `ordinal`
- prefs holder — class whose code contains `settings_iap`
- record getter / entitlement — `()L<cls>;` getter and the `)Z` caller that invokes it
- record fields — the `String` and `Z` fields read in the entitlement tests
- integrity — `)Z` method referencing `SigningInfo.getApkContentsSigners`
- status ids — `prime_status_activated` / `prime_status_unactivated` from `resources.arsc`

`build.py` asserts the original bytes (`expect`) before every write, so a wrong plan
fails loudly instead of producing a broken dex.

## Verification gates (all must pass before handing a build over)

1. `dexdump -f <each dex>` → no `Failure to verify`.
2. `apksigner verify --verbose` → `Verifies`; `zipalign -c -v 4` → `Verification successful`.
3. Pull the installed APK and compare `classes*.dex` with the local build byte for byte.
4. On device:
   - launch → home timeline renders (this is where the theme/integrity bug shows up);
   - `am start -n app.jjyy.chuckle/.module.setting.AppSettingActivity` → **no crash**;
   - tap 高级版 (row 1, ≈ (192, 888) at 1440×3168) → page shows `高级版：已激活`;
   - scroll the feed, open a post, tap 显示翻译 → result renders with no purchase prompt;
   - `adb logcat -d | grep FATAL` → 0; no `BillingClient`/`ads_mobile_sdk` init.

## Reusable on-device recipes

```bash
adb shell am start -W -n app.jjyy.chuckle/.module.setting.AppSettingActivity
adb shell uiautomator dump /sdcard/u.xml && adb pull /sdcard/u.xml    # then decode UTF-8
adb shell input tap X Y ; adb shell input swipe 700 2300 700 700 250
adb exec-out screencap -p > shot.png
adb logcat -c ; adb logcat -v threadtime -f /sdcard/l.txt &          # background capture
```

`uiautomator dump` output is UTF-8; Windows console is GBK — write to a file and decode
with a small Python helper instead of printing.

## Scope notes

- `PremiumActivity` is `exported=false`; the settings entry is the only way in.
- The subscribe/restore buttons remain visible and inert; hiding them needs a Compose
  layout patch, not a dex patch.
- The synthetic record only affects `dvj`-mediated logic. The page itself reads the
  persisted `si0` record, which is why the label swap exists.
- Do not try to rebuild from JADX Java: Compose/Kotlin/serialization codegen and
  obfuscation make it non-compilable. smali is the readable-rebuildable layer.
