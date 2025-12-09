import {
  modulesConfig,
  mockUser,
  providerOptions,
} from '../ScalprumContext';

describe('ScalprumContext', () => {
  describe('modulesConfig', () => {
    it('should have vulnerability module config', () => {
      expect(modulesConfig.vulnerability).toBeDefined();
      expect(modulesConfig.vulnerability.name).toBe('vulnerability');
    });

    it('should have advisor module config', () => {
      expect(modulesConfig.advisor).toBeDefined();
      expect(modulesConfig.advisor.name).toBe('advisor');
    });

    it('should have inventory module config', () => {
      expect(modulesConfig.inventory).toBeDefined();
      expect(modulesConfig.inventory.name).toBe('inventory');
    });
  });

  describe('mockUser', () => {
    it('should have identity with org_id FOREMAN', () => {
      expect(mockUser.identity.org_id).toBe('FOREMAN');
    });
  });

  describe('providerOptions', () => {
    describe('chrome API', () => {
      it('should have isBeta function', () => {
        expect(providerOptions.api.chrome.isBeta).toBeInstanceOf(Function);
        expect(providerOptions.api.chrome.isBeta()).toBe(false);
      });

      it('should have auth.getUser function', () => {
        expect(providerOptions.api.chrome.auth.getUser).toBeInstanceOf(
          Function
        );
      });

      describe('auth.getUserPermissions', () => {
        beforeEach(() => {
          // Reset window.__foreman before each test
          delete window.__foreman;
        });

        it('should be a function under auth', () => {
          expect(
            providerOptions.api.chrome.auth.getUserPermissions
          ).toBeInstanceOf(Function);
        });

        it('should return a Promise', () => {
          const result =
            providerOptions.api.chrome.auth.getUserPermissions();
          expect(result).toBeInstanceOf(Promise);
        });

        it('should return empty array when no permissions set', async () => {
          const permissions =
            await providerOptions.api.chrome.auth.getUserPermissions();
          expect(permissions).toEqual([]);
        });

        it('should return vulnerability permissions when user has view_vulnerability', async () => {
          window.__foreman = {
            permissions: [
              { permission: 'inventory:hosts:read', resourceDefinitions: [] },
              {
                permission: 'vulnerability:vulnerability_results:read',
                resourceDefinitions: [],
              },
              {
                permission: 'vulnerability:system.opt_out:read',
                resourceDefinitions: [],
              },
            ],
          };

          const permissions =
            await providerOptions.api.chrome.auth.getUserPermissions(
              'vulnerability'
            );
          expect(permissions).toHaveLength(2);
          expect(permissions[0].permission).toBe(
            'vulnerability:vulnerability_results:read'
          );
        });

        it('should return inventory permissions when filtering by inventory', async () => {
          window.__foreman = {
            permissions: [
              { permission: 'inventory:hosts:read', resourceDefinitions: [] },
              {
                permission: 'vulnerability:vulnerability_results:read',
                resourceDefinitions: [],
              },
            ],
          };

          const permissions =
            await providerOptions.api.chrome.auth.getUserPermissions(
              'inventory'
            );
          expect(permissions).toHaveLength(1);
          expect(permissions[0].permission).toBe('inventory:hosts:read');
        });

        it('should filter by app prefix when app parameter is provided', async () => {
          window.__foreman = {
            permissions: [
              { permission: 'inventory:hosts:read', resourceDefinitions: [] },
              {
                permission: 'vulnerability:vulnerability_results:read',
                resourceDefinitions: [],
              },
              {
                permission: 'vulnerability:system.cve.status:write',
                resourceDefinitions: [],
              },
            ],
          };

          const vulnerabilityPerms =
            await providerOptions.api.chrome.auth.getUserPermissions(
              'vulnerability'
            );
          expect(vulnerabilityPerms).toHaveLength(2);
          vulnerabilityPerms.forEach(p => {
            expect(p.permission.startsWith('vulnerability:')).toBe(true);
          });

          const inventoryPerms =
            await providerOptions.api.chrome.auth.getUserPermissions(
              'inventory'
            );
          expect(inventoryPerms).toHaveLength(1);
          expect(inventoryPerms[0].permission).toBe('inventory:hosts:read');
        });

        it('should return all permissions when no app filter is provided', async () => {
          window.__foreman = {
            permissions: [
              { permission: 'inventory:hosts:read', resourceDefinitions: [] },
              {
                permission: 'vulnerability:vulnerability_results:read',
                resourceDefinitions: [],
              },
            ],
          };

          const permissions =
            await providerOptions.api.chrome.auth.getUserPermissions();
          expect(permissions).toHaveLength(2);
        });

        it('should return permissions in Chrome API format', async () => {
          window.__foreman = {
            permissions: [
              {
                permission: 'vulnerability:vulnerability_results:read',
                resourceDefinitions: [],
              },
            ],
          };

          const permissions =
            await providerOptions.api.chrome.auth.getUserPermissions(
              'vulnerability'
            );

          expect(permissions[0]).toHaveProperty('permission');
          expect(permissions[0]).toHaveProperty('resourceDefinitions');
          expect(Array.isArray(permissions[0].resourceDefinitions)).toBe(true);
        });
      });
    });
  });
});

