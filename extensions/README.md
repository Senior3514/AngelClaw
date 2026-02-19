# AngelClaw — Browser Extensions

Browser companions for the AngelClaw AGI Guardian Administrative Console.

## Chromium (Chrome, Edge, Brave, Opera, Arc)

### Side-Load Installation
1. Open `chrome://extensions/` (or equivalent for your browser)
2. Enable **Developer mode**
3. Click **Load unpacked** and select the `extensions/chrome/` directory
4. The AngelClaw icon will appear in your toolbar

### Features
- **Status indicator**: Badge shows alert count (red) or clear (green)
- **Quick actions**: Trigger scans, check shield status, open console
- **Mini chat**: Ask AngelClaw questions directly from the extension
- **Settings**: Configure API URL and auth token

### Enterprise Deployment
Chrome Enterprise policies can push the extension to managed devices:
```json
{
  "ExtensionInstallForcelist": [
    "EXTENSION_ID;https://your-update-server/updates.xml"
  ]
}
```
Pack the extension (`chrome://extensions/` > Pack extension) to get a `.crx` file.

## DuckDuckGo Browser

See [duckduckgo/README.md](duckduckgo/README.md) for DDG-specific instructions.

## Firefox

The Chrome extension requires minor adaptations for Firefox:
- Replace `chrome.storage.local` with `browser.storage.local`
- Replace `chrome.alarms` with `browser.alarms`
- Use `browser.browserAction` instead of `chrome.action`
- Update `manifest.json` to use `"manifest_version": 2` and `"browser_specific_settings"`

## Security
- Auth tokens are stored in `chrome.storage.local` (encrypted at rest by the browser)
- No data is sent to external servers — only to your configured AngelClaw instance
- The extension does NOT require access to page content or browsing history
- No public extension store dependency — side-load only
