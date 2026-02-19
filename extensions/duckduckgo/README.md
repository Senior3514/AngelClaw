# AngelClaw — DuckDuckGo Browser Extension

## DuckDuckGo Desktop Browser (Chromium-based)

DuckDuckGo's desktop browser is Chromium-based and supports loading unpacked extensions.

### Installation
1. Open DuckDuckGo Browser desktop
2. Navigate to `duckduckgo://extensions/` (or Settings > Extensions)
3. Enable **Developer mode**
4. Click **Load unpacked** and select the `extensions/chrome/` directory
5. The AngelClaw icon appears in the toolbar

### Configuration
1. Click the AngelClaw extension icon
2. Enter your AngelClaw API URL (e.g., `https://your-host:8500`)
3. Enter your auth token
4. Click Save

## DuckDuckGo Mobile Browser

DuckDuckGo's mobile browser (iOS/Android) does **not** support browser extensions.

### Alternative: Browser Access
1. Open DuckDuckGo mobile browser
2. Navigate to `https://your-angelclaw-host/ui`
3. Log in with your credentials
4. Bookmark the page for quick access
5. The AngelClaw console is fully responsive and works well on mobile

## Limitations
- DuckDuckGo's extension support may differ slightly from Chrome
- The `side_panel` feature may not be available in DDG
- Extension auto-update is not available for side-loaded extensions
