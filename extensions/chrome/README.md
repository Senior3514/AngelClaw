# AngelClaw AGI Guardian — Browser Extension

Chromium browser extension for secure chat and quick actions with your
AngelClaw AGI Guardian instance.

## Features

- Quick status check — see connection health at a glance
- One-click actions: Scan Now, Shield Check, Open Dashboard
- Chat with AngelClaw directly from your browser popup
- Side panel with full chat UI and page context awareness
- Sends current page URL metadata to AngelClaw for contextual analysis

## Installation (Chrome / Edge / Brave)

1. Open your browser and navigate to `chrome://extensions/`
2. Enable **Developer mode** (toggle in the top-right corner)
3. Click **Load unpacked**
4. Select this directory (`extensions/chrome/`)
5. The AngelClaw icon will appear in your toolbar

## Configuration

1. Click the AngelClaw icon in the toolbar
2. Under **Settings**, enter:
   - **API URL** — your AngelClaw Cloud URL (default: `http://localhost:8500`)
   - **Auth Token** — your JWT token from the AngelClaw login API
3. Click **Save Settings**

### Getting a Token

```bash
curl -s -X POST http://localhost:8500/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"your-password"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])"
```

## Security Notes

- **No secrets are stored in the extension code** — tokens are stored in
  `chrome.storage.local`, which is encrypted by the browser
- **All sensitive logic is server-side** — the extension is a thin client
- **Content Security Policy** restricts script execution to extension code only
- **Page URL metadata** is sent to the server for context — no page content
  is read or transmitted
- The extension requires explicit `activeTab` permission — it cannot access
  tabs without user interaction

## Side Panel

The side panel provides a full chat interface:

1. Right-click the AngelClaw icon > **Open side panel**
2. Or use Chrome's side panel menu (if available)
3. Current page URL is shown as context at the top
4. Chat history persists while the panel is open

## Porting to Firefox

Firefox uses Manifest V2 with some differences:

1. Change `"manifest_version": 3` to `"manifest_version": 2`
2. Replace `"action"` with `"browser_action"`
3. Replace `"host_permissions"` — move URLs into `"permissions"`
4. Remove the `"side_panel"` key (use `sidebar_action` instead)
5. Change `chrome.storage` to `browser.storage` (or use the polyfill)
6. CSP format: `"content_security_policy": "script-src 'self'; object-src 'none'"`

See: https://extensionworkshop.com/documentation/develop/porting-a-google-chrome-extension/

## Porting to Other Browsers

- **Safari** — Use `xcrun safari-web-extension-converter` to convert the
  Chromium extension. Requires Xcode.
- **DuckDuckGo** — DuckDuckGo browser supports Chrome extensions natively on
  desktop. Load the unpacked extension the same way as Chrome.
- **Opera / Vivaldi** — Both support Chrome extensions. Load via their
  respective extension management pages.

## Development

```bash
# Watch for changes (optional — browser reload picks up changes)
cd extensions/chrome
# Make edits, then reload the extension in chrome://extensions/
```

## Icon Placeholders

The `icons/` directory contains a README describing the required icon
specifications. Replace the placeholder with actual PNG icons before
publishing to the Chrome Web Store.
