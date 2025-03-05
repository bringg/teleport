/**
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import { AwsRole } from 'shared/services/apps';

import cfg from 'teleport/config';

import { App, AppSubKind, PermissionSet } from './types';

function getLaunchUrl({
  fqdn,
  clusterId,
  publicAddr,
  alwaysUseProxyPublicAddr,
}: {
  fqdn: string;
  clusterId: string;
  alwaysUseProxyPublicAddr: boolean;
  publicAddr: string;
}) {
  if (alwaysUseProxyPublicAddr) {
    return cfg.getAppLauncherRoute({
      fqdn,
    });
  }

  if (publicAddr && clusterId && fqdn) {
    return cfg.getAppLauncherRoute({ fqdn, publicAddr, clusterId });
  }

  return '';
}

export default function makeApp(json: any): App {
  json = json || {};
  const {
    name = '',
    description = '',
    uri = '',
    publicAddr = '',
    alwaysUseProxyPublicAddr = false,
    clusterId = '',
    fqdn = '',
    awsConsole = false,
    samlApp = false,
    friendlyName = '',
    requiresRequest,
    integration = '',
    samlAppPreset,
    subKind,
  } = json;

  const launchUrl = getLaunchUrl({
    fqdn,
    clusterId,
    publicAddr,
    alwaysUseProxyPublicAddr,
  });
  const id = `${clusterId}-${name}-${publicAddr || uri}`;
  const labels = json.labels || [];
  const awsRoles: AwsRole[] = json.awsRoles || [];
  const userGroups = json.userGroups || [];
  const permissionSets: PermissionSet[] = json.permissionSets || [];

  const isTcp = uri && uri.startsWith('tcp://');
  const isCloud = uri && uri.startsWith('cloud://');

  let addrWithProtocol = uri;
  if (publicAddr) {
    if (isCloud) {
      addrWithProtocol = `cloud://${publicAddr}`;
    } else if (isTcp) {
      addrWithProtocol = `tcp://${publicAddr}`;
    } else if (subKind === AppSubKind.AwsIcAccount) {
      /** publicAddr for Identity Center account app is a URL with scheme. */
      addrWithProtocol = publicAddr;
    } else {
      addrWithProtocol = `https://${publicAddr}`;
    }
  }
  if (alwaysUseProxyPublicAddr) {
    addrWithProtocol = `https://${fqdn}`;
  }
  let samlAppSsoUrl = '';
  if (samlApp) {
    samlAppSsoUrl = `${cfg.baseUrl}/enterprise/saml-idp/login/${name}`;
  }

  return {
    kind: 'app',
    subKind,
    id,
    name,
    description,
    alwaysUseProxyPublicAddr,
    uri,
    publicAddr,
    labels,
    clusterId,
    fqdn,
    launchUrl,
    awsRoles,
    awsConsole,
    isCloudOrTcpEndpoint: isTcp || isCloud,
    addrWithProtocol,
    friendlyName,
    userGroups,
    samlApp,
    samlAppPreset,
    samlAppSsoUrl,
    requiresRequest,
    integration,
    permissionSets,
  };
}
