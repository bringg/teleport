// Teleport
// Copyright (C) 2025 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package tbot

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/require"

	headerv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/header/v1"
	workloadidentityv1pb "github.com/gravitational/teleport/api/gen/proto/go/teleport/workloadidentity/v1"
	"github.com/gravitational/teleport/api/types"
	apiutils "github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/lib/tbot/config"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/tool/teleport/testenv"
)

func TestBotWorkloadIdentityX509(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	log := utils.NewSlogLoggerForTests()

	process := testenv.MakeTestServer(t, defaultTestServerOpts(t, log))
	rootClient := testenv.MakeDefaultAuthClient(t, process)

	role, err := types.NewRole("issue-foo", types.RoleSpecV6{
		Allow: types.RoleConditions{
			WorkloadIdentityLabels: map[string]apiutils.Strings{
				"foo": []string{"bar"},
			},
			Rules: []types.Rule{
				{
					Resources: []string{types.KindWorkloadIdentity},
					Verbs:     []string{types.VerbRead, types.VerbList},
				},
			},
		},
	})
	require.NoError(t, err)
	role, err = rootClient.UpsertRole(ctx, role)
	require.NoError(t, err)

	workloadIdentity := &workloadidentityv1pb.WorkloadIdentity{
		Kind:    types.KindWorkloadIdentity,
		Version: types.V1,
		Metadata: &headerv1.Metadata{
			Name: "foo-bar-bizz",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
		Spec: &workloadidentityv1pb.WorkloadIdentitySpec{
			Spiffe: &workloadidentityv1pb.WorkloadIdentitySPIFFE{
				Id: "/valid/{{ user.bot_name }}",
			},
		},
	}
	workloadIdentity, err = rootClient.WorkloadIdentityResourceServiceClient().
		CreateWorkloadIdentity(ctx, &workloadidentityv1pb.CreateWorkloadIdentityRequest{
			WorkloadIdentity: workloadIdentity,
		})
	require.NoError(t, err)

	checkCRL := func(t *testing.T, tmpDir string, bundle *x509bundle.Bundle) {
		crlPEM, err := os.ReadFile(filepath.Join(tmpDir, config.SVIDCRLPemPath))
		require.NoError(t, err)
		crlBytes, _ := pem.Decode(crlPEM)
		crl, err := x509.ParseRevocationList(crlBytes.Bytes)
		require.NoError(t, err)
		require.NoError(t, crl.CheckSignatureFrom(bundle.X509Authorities()[0]))
	}

	t.Run("By Name", func(t *testing.T) {
		tmpDir := t.TempDir()
		onboarding, _ := makeBot(t, rootClient, "by-name", role.GetName())
		botConfig := defaultBotConfig(t, process, onboarding, config.ServiceConfigs{
			&config.WorkloadIdentityX509Service{
				Selector: config.WorkloadIdentitySelector{
					Name: workloadIdentity.GetMetadata().GetName(),
				},
				Destination: &config.DestinationDirectory{
					Path: tmpDir,
				},
			},
		}, defaultBotConfigOpts{
			useAuthServer: true,
			insecure:      true,
		})
		botConfig.Oneshot = true
		b := New(botConfig, log)
		// Run Bot with 10 second timeout to catch hangs.
		ctx, cancel := context.WithTimeout(ctx, time.Second*10)
		defer cancel()
		require.NoError(t, b.Run(ctx))

		svid, err := x509svid.Load(
			path.Join(tmpDir, config.SVIDPEMPath),
			path.Join(tmpDir, config.SVIDKeyPEMPath),
		)
		require.NoError(t, err)
		require.Equal(t, "spiffe://root/valid/by-name", svid.ID.String())

		// Validate the trust bundle was written to disk, and, that our SVID
		// appears valid according to the trust bundle.
		td := spiffeid.RequireTrustDomainFromString("root")
		bundle, err := x509bundle.Load(
			td, filepath.Join(tmpDir, config.SVIDTrustBundlePEMPath),
		)
		require.NoError(t, err)
		_, _, err = x509svid.Verify(svid.Certificates, bundle)
		require.NoError(t, err)

		checkCRL(t, tmpDir, bundle)
	})
	t.Run("By Labels", func(t *testing.T) {
		tmpDir := t.TempDir()
		onboarding, _ := makeBot(t, rootClient, "by-labels", role.GetName())
		botConfig := defaultBotConfig(t, process, onboarding, config.ServiceConfigs{
			&config.WorkloadIdentityX509Service{
				Selector: config.WorkloadIdentitySelector{
					Labels: map[string][]string{
						"foo": {"bar"},
					},
				},
				Destination: &config.DestinationDirectory{
					Path: tmpDir,
				},
			},
		}, defaultBotConfigOpts{
			useAuthServer: true,
			insecure:      true,
		})
		botConfig.Oneshot = true
		b := New(botConfig, log)
		// Run Bot with 10 second timeout to catch hangs.
		ctx, cancel := context.WithTimeout(ctx, time.Second*10)
		defer cancel()
		require.NoError(t, b.Run(ctx))

		svid, err := x509svid.Load(
			path.Join(tmpDir, config.SVIDPEMPath),
			path.Join(tmpDir, config.SVIDKeyPEMPath),
		)
		require.NoError(t, err)
		require.Equal(t, "spiffe://root/valid/by-labels", svid.ID.String())

		// Validate the trust bundle was written to disk, and, that our SVID
		// appears valid according to the trust bundle.
		td := spiffeid.RequireTrustDomainFromString("root")
		bundle, err := x509bundle.Load(
			td, filepath.Join(tmpDir, config.SVIDTrustBundlePEMPath),
		)
		require.NoError(t, err)
		_, _, err = x509svid.Verify(svid.Certificates, bundle)
		require.NoError(t, err)

		checkCRL(t, tmpDir, bundle)
	})
}
