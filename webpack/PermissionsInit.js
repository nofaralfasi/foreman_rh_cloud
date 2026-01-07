/**
 * Initialize global permissions object for Scalprum/Chrome API
 * This allows Insights frontend apps (vulnerability-ui) to access
 * user permissions via chrome.auth.getUserPermissions()
 *
 * Permission format follows Chrome API specification:
 * @see https://github.com/RedHatInsights/frontend-components/blob/master/docs/chrome/chrome-api.md#getuserpermissions
 *
 * Example permission structure (for user with view_vulnerability permission):
 * [
 *   { permission: 'inventory:hosts:read', resourceDefinitions: [] },
 *   { permission: 'vulnerability:vulnerability_results:read', resourceDefinitions: [] },
 *   { permission: 'vulnerability:system.opt_out:read', resourceDefinitions: [] },
 *   { permission: 'vulnerability:report_and_export:read', resourceDefinitions: [] },
 *   { permission: 'vulnerability:advanced_report:read', resourceDefinitions: [] }
 * ]
 */
window.__foreman = window.__foreman || {};
window.__foreman.permissions = window.__foreman.permissions || [];

// Read permissions from backend-injected data attribute
const permissionsElement = document.getElementById(
  'foreman-rh-cloud-permissions'
);
if (permissionsElement) {
  try {
    const permissionsData = permissionsElement.getAttribute('data-permissions');
    if (permissionsData) {
      window.__foreman.permissions = JSON.parse(permissionsData);
    }
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error('Failed to parse Foreman RH Cloud permissions data:', e);
  }
}
