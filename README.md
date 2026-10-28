# Chuckle paywall removal

Patches for **Chuckle** (`app.jjyy.chuckle`, an X/Twitter client, Kotlin + Jetpack
Compose, obfuscated, multi-dex) that remove its activation / subscription paywall and
keep the rebuilt APK usable after re-signing.

Reference build: `1.1.1 (154)`, minSdk 29 / targetSdk 36, `arm64-v8a` only.
Verified on a OnePlus CPH2581 (Android 16 / API 36).

## What gets patched

| # | Target | Change | Effect |
|---|---|---|---|
| 1 | freemium flag getter (`)Z`, reads RemoteConfig `freemium_enable`) | → `false` | every ad path and upgrade surface goes inert |
| 2 | forced-purchase predicate (`)Z`) | → `false` | first-run "must subscribe" dialog never shows |
| 3 | entitlement predicate (`)Z`) | → `true` | premium features pass their subscription check |
| 4 | integrity check (`)Z`, compares the APK signer hash) | → `true` | **required after re-signing** — see below |
| 5 | subscription record getter (`()L…;`) | synthesize `code="active"`, `expired=false` | logic that reads the record sees an active subscription |
| 6 | premium status label constant | `prime_status_unactivated` → `prime_status_activated` | the Premium page renders `已激活` |

Plus one packaging step: re-inject the `{"channel":"app"}` ID-value pair into the APK
Signing Block (apksigner wipes it).

## Why patch 4 exists (the re-sign trap)

The app ties its theme to its own signing certificate:

```
integrity check  →  expected hash decrypted from resources vs PackageManager signer
                 →  on mismatch a Koin initializer replaces the theme provider with an empty stub
                 →  every ColorStateList becomes null
                 →  RippleDrawable construction throws
                    "IllegalArgumentException: RippleDrawable requires a non-null color"
```

Symptom: the settings list and the home search bar crash immediately after login.
This is **not** caused by the paywall patches — it reproduces with an unmodified,
re-signed APK. Patch 4 removes the trap.

## Two routes

### A. smali (recommended, maintainable)

```bash
java -jar apktool.jar d -f -o out/dec app.apk
# one-time per release: append to out/dec/res/values/attrs.xml
#   <attr name="state_swiped" format="boolean" />
#   (the shipped resources.arsc has a dangling attr id for it)
python tools/smali_patch.py out/dec            # rewrites 5 method bodies + 1 constant
java -jar apktool.jar b out/dec -o out/built.apk
zipalign -f -p 4 out/built.apk out/aligned.apk
apksigner sign --ks local.keystore --out out/signed.apk out/aligned.apk
python tools/inject_channel.py out/signed.apk out/final.apk
```

### B. dex bytes (surgical fallback)

```bash
python tools/patch_paywall.py                  # offsets for 1.1.1(154)
python tools/inject_channel.py out/signed.apk out/final.apk
```

`tools/patch_paywall.py` asserts the original bytes at every offset before writing, so a
version mismatch fails loudly instead of producing a broken dex. For a new release,
re-derive the targets first (see `docs/SKILL.md` → semantic locator) instead of trusting
the 1.1.1 offsets.

## Requirements

- JDK 21, Android SDK build-tools (`zipalign`, `apksigner`, `aapt2`, `dexdump`)
- [apktool](https://github.com/iBotPeaches/Apktool) 2.11.x jar for route A
- Python 3.10+; route B helpers use `androguard` + `loguru`
- a local signing key (`keytool -genkeypair`) — **never commit it**

## Verification

```bash
dexdump -f classes.dex | grep -i "failure to verify"   # must be empty, per dex
apksigner verify --verbose final.apk                    # "Verifies"
zipalign -c -v 4 final.apk                              # "Verification successful"
```

On device:

1. launch → home timeline renders (this is where the theme bug shows up);
2. `am start -n app.jjyy.chuckle/.module.setting.AppSettingActivity` → no crash;
3. Settings → 高级版 → shows `高级版：已激活`;
4. scroll the feed, open a post, tap `显示翻译` → works with no purchase prompt;
5. `logcat | grep FATAL` → zero; no `BillingClient` / `ads_mobile_sdk` init.

## Caveats

- **Re-installing wipes the X login.** A different signing key forces
  `pm uninstall` first, which deletes `/data/data/app.jjyy.chuckle` and the Keystore
  keys. Batch changes; every install cycle means logging in again.
- **No x86 emulator**: the APK ships `lib/arm64-v8a` only, so an x86_64 AVD dies at
  `UnsatisfiedLinkError`. Use a real arm64 device or an ARM-host emulator.
- The subscribe / restore buttons remain visible and inert; hiding them needs a Compose
  layout patch, not a dex patch.
- Use only on a device and an app copy you own.

## Layout

```
docs/SKILL.md              workflow, pitfalls, on-device recipes (also installed as an agent skill)
docs/case-1.1.1-154.md     concrete class names, offsets, signing-block facts, failure signatures
tools/patch_paywall.py     route B: all dex patches for 1.1.1(154) + header fix + sign + channel
tools/smali_patch.py       route A: idempotent smali body rewrites
tools/inject_channel.py    APK Signing Block channel pair injection
tools/bisect_patches.py    build single-patch variants to isolate a regression
tools/uidump.py            decode `uiautomator dump` XML to readable text (UTF-8 safe)
tools/dexsmali.py          quick pseudo-smali dump of selected classes
```
