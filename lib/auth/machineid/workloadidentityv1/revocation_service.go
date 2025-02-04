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

package workloadidentityv1

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"log/slog"
	"math/big"
	"time"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/gravitational/teleport"
	workloadidentityv1pb "github.com/gravitational/teleport/api/gen/proto/go/teleport/workloadidentity/v1"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/authz"
	"github.com/gravitational/teleport/lib/tlsca"
)

type workloadIdentityX509RevocationReadWriter interface {
	GetWorkloadIdentityX509Revocation(ctx context.Context, name string) (*workloadidentityv1pb.WorkloadIdentityX509Revocation, error)
	ListWorkloadIdentityX509Revocations(ctx context.Context, pageSize int, token string) ([]*workloadidentityv1pb.WorkloadIdentityX509Revocation, string, error)
	CreateWorkloadIdentityX509Revocation(ctx context.Context, resource *workloadidentityv1pb.WorkloadIdentityX509Revocation) (*workloadidentityv1pb.WorkloadIdentityX509Revocation, error)
	UpdateWorkloadIdentityX509Revocation(ctx context.Context, resource *workloadidentityv1pb.WorkloadIdentityX509Revocation) (*workloadidentityv1pb.WorkloadIdentityX509Revocation, error)
	DeleteWorkloadIdentityX509Revocation(ctx context.Context, name string) error
	UpsertWorkloadIdentityX509Revocation(ctx context.Context, resource *workloadidentityv1pb.WorkloadIdentityX509Revocation) (*workloadidentityv1pb.WorkloadIdentityX509Revocation, error)
}

type certAuthorityGetter interface {
	GetCertAuthority(ctx context.Context, id types.CertAuthID, loadKeys bool) (types.CertAuthority, error)
}

// RevocationServiceConfig holds configuration options for the RevocationService.
type RevocationServiceConfig struct {
	Authorizer authz.Authorizer
	Backend    workloadIdentityX509RevocationReadWriter
	Clock      clockwork.Clock
	Emitter    apievents.Emitter
	Logger     *slog.Logger
	// KeyStorer is used to access the signing keys necessary to sign a CRL.
	KeyStorer KeyStorer
	// CertAuthorityGetter is used to get the certificate authority needed to
	// sign the CRL.
	CertAuthorityGetter certAuthorityGetter
}

// RevocationService is the gRPC service for managing workload identity
// revocations.
// It implements the workloadidentityv1pb.WorkloadIdentityRevocationServiceServer
type RevocationService struct {
	workloadidentityv1pb.UnimplementedWorkloadIdentityRevocationServiceServer

	authorizer          authz.Authorizer
	backend             workloadIdentityX509RevocationReadWriter
	clock               clockwork.Clock
	emitter             apievents.Emitter
	logger              *slog.Logger
	keyStorer           KeyStorer
	certAuthorityGetter certAuthorityGetter
	clusterName         string
}

// NewResourceService returns a new instance of the ResourceService.
func NewRevocationService(cfg *RevocationServiceConfig) (*RevocationService, error) {
	switch {
	case cfg.Backend == nil:
		return nil, trace.BadParameter("backend service is required")
	case cfg.Authorizer == nil:
		return nil, trace.BadParameter("authorizer is required")
	case cfg.Emitter == nil:
		return nil, trace.BadParameter("emitter is required")
	}

	if cfg.Logger == nil {
		cfg.Logger = slog.With(teleport.ComponentKey, "workload_identity_resource.service")
	}
	if cfg.Clock == nil {
		cfg.Clock = clockwork.NewRealClock()
	}
	return &RevocationService{
		authorizer: cfg.Authorizer,
		backend:    cfg.Backend,
		clock:      cfg.Clock,
		emitter:    cfg.Emitter,
		logger:     cfg.Logger,
	}, nil
}

// GetWorkloadIdentity returns a WorkloadIdentity by name.
// Implements teleport.workloadidentity.v1.RevocationService/GetWorkloadIdentityX509Revocation
func (s *RevocationService) GetWorkloadIdentityX509Revocation(
	ctx context.Context, req *workloadidentityv1pb.GetWorkloadIdentityX509RevocationRequest,
) (*workloadidentityv1pb.WorkloadIdentityX509Revocation, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := authCtx.CheckAccessToKind(types.KindWorkloadIdentityX509Revocation, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}

	if req.Name == "" {
		return nil, trace.BadParameter("name: must be non-empty")
	}

	resource, err := s.backend.GetWorkloadIdentityX509Revocation(ctx, req.Name)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return resource, nil
}

// ListWorkloadIdentities returns a list of WorkloadIdentity resources. It
// follows the Google API design guidelines for list pagination.
// Implements teleport.workloadidentity.v1.ResourceService/ListWorkloadIdentities
func (s *RevocationService) ListWorkloadIdentityX509Revocations(
	ctx context.Context, req *workloadidentityv1pb.ListWorkloadIdentityX509RevocationsRequest,
) (*workloadidentityv1pb.ListWorkloadIdentityX509RevocationsResponse, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := authCtx.CheckAccessToKind(types.KindWorkloadIdentityX509Revocation, types.VerbRead, types.VerbList); err != nil {
		return nil, trace.Wrap(err)
	}

	resources, nextToken, err := s.backend.ListWorkloadIdentityX509Revocations(
		ctx,
		int(req.PageSize),
		req.PageToken,
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &workloadidentityv1pb.ListWorkloadIdentityX509RevocationsResponse{
		WorkloadIdentityX509Revocations: resources,
		NextPageToken:                   nextToken,
	}, nil
}

// DeleteWorkloadIdentity deletes a WorkloadIdentity by name.
// Implements teleport.workloadidentity.v1.ResourceService/DeleteWorkloadIdentity
func (s *RevocationService) DeleteWorkloadIdentityX509Revocation(
	ctx context.Context, req *workloadidentityv1pb.DeleteWorkloadIdentityX509RevocationRequest,
) (*emptypb.Empty, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := authCtx.CheckAccessToKind(types.KindWorkloadIdentityX509Revocation, types.VerbDelete); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := authCtx.AuthorizeAdminAction(); err != nil {
		return nil, trace.Wrap(err)
	}

	if req.Name == "" {
		return nil, trace.BadParameter("name: must be non-empty")
	}

	if err := s.backend.DeleteWorkloadIdentityX509Revocation(ctx, req.Name); err != nil {
		return nil, trace.Wrap(err)
	}

	// TODO: Audit event

	return &emptypb.Empty{}, nil
}

// CreateWorkloadIdentity creates a new WorkloadIdentity.
// Implements teleport.workloadidentity.v1.ResourceService/CreateWorkloadIdentity
func (s *RevocationService) CreateWorkloadIdentityX509Revocation(
	ctx context.Context, req *workloadidentityv1pb.CreateWorkloadIdentityX509RevocationRequest,
) (*workloadidentityv1pb.WorkloadIdentityX509Revocation, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := authCtx.CheckAccessToKind(types.KindWorkloadIdentityX509Revocation, types.VerbCreate); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := authCtx.AuthorizeAdminAction(); err != nil {
		return nil, trace.Wrap(err)
	}

	created, err := s.backend.CreateWorkloadIdentityX509Revocation(ctx, req.WorkloadIdentityX509Revocation)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// TODO: Audit log

	return created, nil
}

// UpdateWorkloadIdentity updates an existing WorkloadIdentity.
// Implements teleport.workloadidentity.v1.ResourceService/UpdateWorkloadIdentity
func (s *RevocationService) UpdateWorkloadIdentityX509Revocation(
	ctx context.Context, req *workloadidentityv1pb.UpdateWorkloadIdentityX509RevocationRequest,
) (*workloadidentityv1pb.WorkloadIdentityX509Revocation, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := authCtx.CheckAccessToKind(types.KindWorkloadIdentity, types.VerbUpdate); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := authCtx.AuthorizeAdminAction(); err != nil {
		return nil, trace.Wrap(err)
	}

	created, err := s.backend.UpdateWorkloadIdentityX509Revocation(ctx, req.WorkloadIdentityX509Revocation)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// TODO: Audit log

	return created, nil
}

// UpsertWorkloadIdentity updates or creates an existing WorkloadIdentity.
// Implements teleport.workloadidentity.v1.ResourceService/UpsertWorkloadIdentity
func (s *RevocationService) UpsertWorkloadIdentityX509Revocation(
	ctx context.Context, req *workloadidentityv1pb.UpsertWorkloadIdentityX509RevocationRequest,
) (*workloadidentityv1pb.WorkloadIdentityX509Revocation, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := authCtx.CheckAccessToKind(
		types.KindWorkloadIdentity, types.VerbCreate, types.VerbUpdate,
	); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := authCtx.AuthorizeAdminAction(); err != nil {
		return nil, trace.Wrap(err)
	}

	created, err := s.backend.UpsertWorkloadIdentityX509Revocation(ctx, req.WorkloadIdentityX509Revocation)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// TODO: Audit log

	return created, nil
}

func (s *RevocationService) signCRL(ctx context.Context) ([]byte, error) {
	pageToken := ""
	revocations := []*workloadidentityv1pb.WorkloadIdentityX509Revocation{}
	for {
		res, token, err := s.backend.ListWorkloadIdentityX509Revocations(
			ctx, 0, pageToken,
		)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		revocations = append(revocations, res...)
		if token == "" {
			break
		}
		pageToken = token
	}

	// TODO: fetch
	ca, err := s.certAuthorityGetter.GetCertAuthority(ctx, types.CertAuthID{
		Type:       types.SPIFFECA,
		DomainName: s.clusterName,
	}, true)
	tlsCert, tlsSigner, err := s.keyStorer.GetTLSCertAndSigner(ctx, ca)
	if err != nil {
		return nil, trace.Wrap(err, "getting CA cert and key")
	}
	tlsCA, err := tlsca.FromCertAndSigner(tlsCert, tlsSigner)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	tmpl := &x509.RevocationList{
		// https://www.rfc-editor.org/rfc/rfc5280.html#section-5.1.2.6
		RevokedCertificateEntries: make([]x509.RevocationListEntry, 0, len(revocations)),
		// https://www.rfc-editor.org/rfc/rfc5280.html#section-5.1.2.4
		// This field indicates the issue date of this CRL.  thisUpdate may be
		//  encoded as UTCTime or GeneralizedTime.
		ThisUpdate: time.Now(),
		// https://www.rfc-editor.org/rfc/rfc5280.html#section-5.2.3
		// This is an optional extension we will be omitting for now, at a
		// future date, we may insert a monotonically increasing identifier.
		Number: nil,
	}

	for _, revocation := range revocations {
		serial := new(big.Int)
		_, ok := serial.SetString(revocation.Metadata.Name, 16)
		if !ok {
			// TODO log and skip?
			continue
		}

		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: revocation.Spec.RevokedAt.AsTime(),
		})
	}

	signedCRL, err := x509.CreateRevocationList(
		rand.Reader, tmpl, tlsCA.Cert, tlsCA.Signer,
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return signedCRL, nil
}
