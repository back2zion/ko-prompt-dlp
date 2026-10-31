# AX Filter — 패키징 및 조직 배포 (Enterprise Deployment)

This guide covers building the extension, publishing it, and force-installing it
with a managed (admin-set) configuration across an organization.

Steps that require a **Google / organization account** are marked
**(requires org account)** — they cannot be completed from this repository alone.

---

## 1. Load unpacked (development)

1. Open `chrome://extensions`.
2. Enable **Developer mode** (top right).
3. Click **Load unpacked** and select `axfilter/extension/`.
4. Open the extension's **Options** and set the server URL and agent API key
   (unless these are supplied by a managed policy — see §4).

To exercise the managed policy locally, drop a `managed_schema`-shaped policy
file into the platform's managed-storage location (§4) before loading, or use
Chrome's `chrome://policy` page to confirm the values are applied.

---

## 2. Build the distributable zip

```
cd axfilter/extension
bash build.sh
```

This reads `version` from `manifest.json` and writes
`dist/axfilter-extension-<version>.zip`, containing only the runtime files
(`manifest.json`, `background.js`, `content.js`, `filter-core.js`,
`options.html`, `options.js`, `managed_schema.json`, `README.md`).
`test/`, `node_modules/`, `.git/`, `dist/`, `build.sh`, and this file are
excluded. Pure shell + `zip`, no network.

Verify:

```
unzip -l dist/axfilter-extension-<version>.zip
```

---

## 3. Publish to the Chrome Web Store (manual) **(requires org account)**

The Web Store cannot be published to from this repo; do it manually in the
dashboard.

1. Create or use a **Chrome Web Store developer account**
   (one-time USD 5 registration fee). **(requires org account)**
2. Go to the [Developer Dashboard](https://chrome.google.com/webstore/devconsole).
3. **Add new item** → upload `dist/axfilter-extension-<version>.zip`.
4. Fill in listing details, privacy practices, and screenshots.
5. For organization-only distribution, set **Visibility** to **Private** and
   restrict to your Google Workspace domain (or use **Unlisted** if you will
   force-install by ID). **(requires org account)**
6. Submit for review and publish. Note the **extension ID** shown on the
   dashboard — you need it for force-install below.

> Alternative (no Web Store): self-host the zip as a `.crx` with an
> `update_manifest.xml` and reference it via the `ExtensionInstallForcelist`
> policy using an `;update_url`. The Web Store path is simpler and recommended.

---

## 4. Force-install + managed policy

The extension's `manifest.json` declares `storage.managed_schema`:
`managed_schema.json`. Administrators can preconfigure these keys, which are
**read-only** in the Options page and take precedence over per-user settings:

| Key        | Type    | Meaning                                   |
|------------|---------|-------------------------------------------|
| `apiBase`  | string  | Inspection server URL (no trailing slash) |
| `apiKey`   | string  | Agent `X-API-Key` (optional)              |
| `enabled`  | boolean | Turn inspection on/off                    |
| `failMode` | string  | `block` (fail safe) or `allow`            |

Replace `EXTENSION_ID_PLACEHOLDER` below with the real ID from the Web Store
dashboard (a 32-char `a`–`p` string).

### Google Admin console (Workspace / ChromeOS) **(requires org account)**

Admin console → **Devices → Chrome → Apps & extensions**. Add the extension by
ID, set **Installation policy = Force install**, and paste this into the
extension's **Policy for extensions** (managed configuration) field:

```json
{
  "apiBase": { "Value": "https://axfilter.example.com" },
  "apiKey": { "Value": "AGENT_API_KEY" },
  "enabled": { "Value": true },
  "failMode": { "Value": "block" }
}
```

(The Admin console wraps each value in `{ "Value": ... }`.)

### Windows (Group Policy / registry)

Force-install the extension, then set the managed configuration under the
extension ID. Registry (`.reg`) example:

```
Windows Registry Editor Version 5.00

; Force install from the Web Store
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist]
"1"="EXTENSION_ID_PLACEHOLDER;https://clients2.google.com/service/update2/crx"

; Managed configuration for this extension
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\EXTENSION_ID_PLACEHOLDER\policy]
"apiBase"="https://axfilter.example.com"
"apiKey"="AGENT_API_KEY"
"enabled"=dword:00000001
"failMode"="block"
```

With the ADMX templates you can instead configure
`Google > Google Chrome > Extensions` in `gpedit.msc`.

### macOS (configuration profile / plist)

Deploy a managed-preferences profile for `com.google.Chrome`. The force-install
list and the per-extension managed configuration:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>ExtensionInstallForcelist</key>
  <array>
    <string>EXTENSION_ID_PLACEHOLDER;https://clients2.google.com/service/update2/crx</string>
  </array>
  <key>ExtensionSettings</key>
  <dict>
    <key>EXTENSION_ID_PLACEHOLDER</key>
    <dict>
      <key>installation_mode</key>
      <string>force_installed</string>
      <key>update_url</key>
      <string>https://clients2.google.com/service/update2/crx</string>
    </dict>
  </dict>
</dict>
</plist>
```

Chrome reads the extension's managed configuration from the managed-preferences
domain `EXTENSION_ID_PLACEHOLDER` (e.g. a profile payload for
`EXTENSION_ID_PLACEHOLDER` with keys `apiBase`, `apiKey`, `enabled`,
`failMode`). Deploy it via your MDM (Jamf, Intune, etc.). **(requires org MDM)**

---

## Verifying the policy

On a managed device, open `chrome://policy` and confirm the extension's managed
values appear, then open the extension **Options** — policy-set fields are shown
disabled with a "조직 정책으로 설정됨" note. When no policy is present, the
Options page behaves exactly as before (per-user `chrome.storage.sync`).

> Reminder: a browser extension can be disabled or removed by the user unless
> force-installed. For true organization-wide enforcement, pair this with the
> server-side proxy and MDM policy described in `../deploy/`.
