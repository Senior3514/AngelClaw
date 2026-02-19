// AngelClaw AGI Guardian — Background Service Worker
chrome.alarms.create('healthCheck', { periodInMinutes: 1 });

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== 'healthCheck') return;
  const { apiUrl, authToken } = await chrome.storage.local.get(['apiUrl', 'authToken']);
  if (!apiUrl) return;
  try {
    const headers = authToken ? { 'Authorization': 'Bearer ' + authToken } : {};
    const r = await fetch(apiUrl + '/health', { headers });
    if (r.ok) {
      const alerts = await fetch(apiUrl + '/api/v1/guardian/alerts/recent?tenantId=dev-tenant&limit=10', { headers }).then(r => r.json()).catch(() => []);
      const count = alerts.length || 0;
      chrome.action.setBadgeText({ text: count > 0 ? String(count) : '' });
      chrome.action.setBadgeBackgroundColor({ color: count > 0 ? '#f87171' : '#4ade80' });
    } else {
      chrome.action.setBadgeText({ text: '!' });
      chrome.action.setBadgeBackgroundColor({ color: '#fbbf24' });
    }
  } catch (e) {
    chrome.action.setBadgeText({ text: '!' });
    chrome.action.setBadgeBackgroundColor({ color: '#f87171' });
  }
});
