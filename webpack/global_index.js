import { registerColumns } from 'foremanReact/components/HostsIndex/Columns/core';
import { registerReducers } from './ForemanRhCloudReducers';
import { registerFills } from './ForemanRhCloudFills';
import { registerRoutes } from './ForemanRhCloudPages';
import hostsIndexColumnExtensions from './ForemanColumnExtensions/index';
import './PermissionsInit';

registerReducers();
registerFills();
registerRoutes();
registerColumns(hostsIndexColumnExtensions);
