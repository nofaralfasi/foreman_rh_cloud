export const modulesConfig = {
  vulnerability: {
    name: 'vulnerability',
    manifestLocation: `${window.location.origin}/assets/apps/vulnerability/fed-mods.json`,
    cdnPath: `${window.location.origin}/assets/apps/vulnerability/`,
  },
  advisor: {
    name: 'advisor',
    manifestLocation: `${window.location.origin}/assets/apps/advisor/fed-mods.json`,
    cdnPath: `${window.location.origin}/assets/apps/advisor/`,
  },
  inventory: {
    name: 'inventory',
    manifestLocation: `${window.location.origin}/assets/apps/inventory/fed-mods.json`,
    cdnPath: `${window.location.origin}/assets/apps/inventory/`,
  },
};

export const mockUser = {
  entitlements: {},
  identity: {
    account_number: 'string',
    org_id: 'FOREMAN',
    internal: {
      org_id: 'string',
      account_id: 'string',
    },
    type: 'string',
    user: {
      username: 'string',
      email: 'string',
      first_name: 'string',
      last_name: 'string',
      is_active: 'boolean',
      is_internal: 'boolean',
      is_org_admin: 'boolean',
      locale: 'string',
    },
  },
};

/**
 * Fetches user permissions from the backend.
 * Implements the Chrome API getUserPermissions interface using ConsoleDot permission format.
 *
 * Permission mapping (Foreman → Insights):
 *
 * view_vulnerability → inventory:hosts:read
 *                      vulnerability:vulnerability_results:read
 *                      vulnerability:system.opt_out:read
 *                      vulnerability:report_and_export:read
 *                      vulnerability:advanced_report:read
 *
 * edit_vulnerability → vulnerability:system.cve.status:write
 *                      vulnerability:cve.business_risk_and_status:write
 *                      vulnerability:system.opt_out:write
 *
 * @see https://github.com/RedHatInsights/frontend-components/blob/master/docs/chrome/chrome-api.md#getuserpermissions
 * @param {string} app - Optional app name to filter permissions (e.g., 'vulnerability', 'inventory')
 * @param {boolean} _bypassCache - Optional flag to bypass cache (not used in Foreman)
 * @returns {Promise<Array<{permission: string, resourceDefinitions: Array}>>} Array of permission objects
 */
const getUserPermissions = async (app, _bypassCache) => {
  // Get all permissions from backend (already in Insights format)
  const allPermissions = window.__foreman?.permissions || [];

  // If app is specified, filter by app prefix
  if (app) {
    const filtered = allPermissions.filter(
      p => p.permission && p.permission.startsWith(`${app}:`)
    );
    return filtered;
  }

  // Return all permissions
  return allPermissions;
};

export const providerOptions = {
  pluginSDKOptions: {
    pluginLoaderOptions: {
      transformPluginManifest: manifest => {
        if (
          manifest.baseURL === 'auto' &&
          modulesConfig[manifest.name]?.cdnPath
        ) {
          const _cdnPath = modulesConfig[manifest.name]?.cdnPath;
          return {
            ...manifest,
            baseURL: _cdnPath,
            loadScripts: manifest.loadScripts.map(
              script => `${_cdnPath}${script}`
            ),
          };
        }
        return manifest;
      },
    },
  },
  api: {
    chrome: {
      isBeta: () => false,
      on: () => {},
      auth: {
        getUser: () => Promise.resolve(mockUser),
        getUserPermissions,
      },
    },
  },
  config: modulesConfig,
};
