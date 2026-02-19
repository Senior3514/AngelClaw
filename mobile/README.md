# AngelClaw — Mobile Access Guide

## Accessing AngelClaw on Mobile

AngelClaw's Administrative Console is fully responsive and works on mobile browsers.

### Requirements
- TLS (HTTPS) connection to your AngelClaw Cloud instance
- Valid credentials (username/password or API key)

### Android (Chrome / Brave / Edge)
1. Open Chrome and navigate to `https://your-angelclaw-host/ui`
2. Log in with your credentials
3. **Add to Home Screen**: Tap the three-dot menu > "Add to Home Screen"
4. AngelClaw will appear as an app icon on your home screen

### iOS / iPadOS (Safari)
1. Open Safari and navigate to `https://your-angelclaw-host/ui`
2. Log in with your credentials
3. **Add to Home Screen**: Tap the Share icon > "Add to Home Screen"
4. AngelClaw will appear as an app icon

### DuckDuckGo Browser
1. Navigate to `https://your-angelclaw-host/ui`
2. Log in with your credentials
3. Bookmark the page for quick access
4. Note: DDG mobile does not support PWA "Add to Home Screen" — use the bookmark

### Xiaomi Pad / Samsung Galaxy Tab
- Use Chrome or the default browser
- Follow the Android instructions above
- The console automatically adapts to tablet screen sizes

## Mobile-Optimized Features
- **Dashboard**: Key metrics visible at a glance
- **Chat**: Full AngelClaw AI chat works on mobile
- **Alerts**: View and acknowledge alerts
- **Fleet**: Browse connected agents
- **Navigation**: Collapsible sidebar for small screens

## Limitations on Mobile
- No local Angel Node agent on mobile (use browser-only access)
- WebSocket real-time feed may be interrupted by mobile power saving
- For full admin operations, desktop is recommended

## Security Notes
- Always use HTTPS
- Log out when done on shared devices
- Consider using an API key for automated access instead of password
