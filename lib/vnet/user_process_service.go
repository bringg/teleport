// Teleport
// Copyright (C) 2024 Gravitational, Inc.
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

package vnet

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"sync"

	"github.com/gravitational/trace"
	"github.com/gravitational/trace/trail"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/gravitational/teleport/api"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/utils/grpc/interceptors"
	vnetv1 "github.com/gravitational/teleport/gen/proto/go/teleport/lib/vnet/v1"
)

type userProcessService struct {
	vnetv1.UnsafeVnetUserProcessServiceServer
	appProvider AppProvider

	mu             sync.Mutex
	appSignerCache map[appKey]crypto.Signer
}

type appKey struct {
	profile, leafCluster, app string
	port                      uint16
}

func newAppKey(protoAppKey *vnetv1.AppKey, port uint16) appKey {
	return appKey{
		profile:     protoAppKey.GetProfile(),
		leafCluster: protoAppKey.GetLeafCluster(),
		app:         protoAppKey.GetName(),
		port:        port,
	}
}

func newUserProcessService(appProvider AppProvider) *userProcessService {
	return &userProcessService{
		appProvider:    appProvider,
		appSignerCache: make(map[appKey]crypto.Signer),
	}
}

func (s *userProcessService) Ping(ctx context.Context, req *vnetv1.PingRequest) (*vnetv1.PingResponse, error) {
	return &vnetv1.PingResponse{}, nil
}

func (s *userProcessService) AuthenticateProcess(ctx context.Context, req *vnetv1.AuthenticateProcessRequest) (*vnetv1.AuthenticateProcessResponse, error) {
	log.DebugContext(ctx, "Received AuthenticateProcess request from admin process")
	if req.Version != api.Version {
		return nil, trace.BadParameter("version mismatch, user process version is %s, admin process version is %s",
			api.Version, req.Version)
	}
	if err := platformAuthenticateProcess(ctx, req); err != nil {
		return nil, trail.ToGRPC(err)
	}
	return &vnetv1.AuthenticateProcessResponse{
		Version: api.Version,
	}, nil
}

func (s *userProcessService) ResolveAppInfo(ctx context.Context, req *vnetv1.ResolveAppInfoRequest) (*vnetv1.ResolveAppInfoResponse, error) {
	appInfo, err := s.appProvider.ResolveAppInfo(ctx, req.GetFqdn())
	if err != nil {
		return nil, trail.ToGRPC(err)
	}
	return &vnetv1.ResolveAppInfoResponse{
		AppInfo: appInfo,
	}, nil
}

func (s *userProcessService) ReissueAppCert(ctx context.Context, req *vnetv1.ReissueAppCertRequest) (*vnetv1.ReissueAppCertResponse, error) {
	if req.AppInfo == nil {
		return nil, trail.ToGRPC(trace.BadParameter("missing AppInfo"))
	}
	cert, err := s.appProvider.ReissueAppCert(ctx, req.GetAppInfo(), uint16(req.GetTargetPort()))
	if err != nil {
		return nil, trail.ToGRPC(trace.Wrap(err, "reissuing app certificate"))
	}
	s.setSignerForApp(req.GetAppInfo().GetAppKey(), uint16(req.GetTargetPort()), cert.PrivateKey.(crypto.Signer))
	return &vnetv1.ReissueAppCertResponse{
		Cert: cert.Certificate[0],
	}, nil
}

func (s *userProcessService) SignForApp(ctx context.Context, req *vnetv1.SignForAppRequest) (*vnetv1.SignForAppResponse, error) {
	log.DebugContext(ctx, "Got SignForApp request",
		"app", req.GetAppKey(),
		"hash", req.GetHash(),
		"digest_len", len(req.GetDigest()),
	)
	var hash crypto.Hash
	switch req.GetHash() {
	case vnetv1.Hash_HASH_NONE:
		hash = crypto.Hash(0)
	case vnetv1.Hash_HASH_SHA256:
		hash = crypto.SHA256
	default:
		return nil, trail.ToGRPC(trace.BadParameter("unsupported hash %v", req.GetHash()))
	}
	appKey := req.GetAppKey()

	signer, ok := s.getSignerForApp(req.GetAppKey(), uint16(req.GetTargetPort()))
	if !ok {
		return nil, trail.ToGRPC(trace.BadParameter("no signer for app %v", appKey))
	}

	signature, err := signer.Sign(rand.Reader, req.GetDigest(), hash)
	if err != nil {
		return nil, trail.ToGRPC(trace.Wrap(err, "signing for app %v", appKey))
	}
	return &vnetv1.SignForAppResponse{
		Signature: signature,
	}, nil
}

func (s *userProcessService) setSignerForApp(appKey *vnetv1.AppKey, targetPort uint16, signer crypto.Signer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appSignerCache[newAppKey(appKey, targetPort)] = signer
}

func (s *userProcessService) getSignerForApp(appKey *vnetv1.AppKey, targetPort uint16) (crypto.Signer, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	signer, ok := s.appSignerCache[newAppKey(appKey, targetPort)]
	return signer, ok
}

type userProcessServiceClient struct {
	clt    vnetv1.VnetUserProcessServiceClient
	closer io.Closer
}

func newUserProcessServiceClient(ctx context.Context, addr string) (*userProcessServiceClient, error) {
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(interceptors.GRPCClientUnaryErrorInterceptor),
		grpc.WithStreamInterceptor(interceptors.GRPCClientStreamErrorInterceptor),
	)
	if err != nil {
		return nil, trace.Wrap(err, "creating user process gRPC client")
	}
	return &userProcessServiceClient{
		clt:    vnetv1.NewVnetUserProcessServiceClient(conn),
		closer: conn,
	}, nil
}

func (c *userProcessServiceClient) Close() error {
	return trace.Wrap(c.closer.Close())
}

func (c *userProcessServiceClient) Ping(ctx context.Context) error {
	if _, err := c.clt.Ping(ctx, &vnetv1.PingRequest{}); err != nil {
		return trail.FromGRPC(err)
	}
	return nil
}

func (c *userProcessServiceClient) AuthenticateProcess(ctx context.Context, pipePath string) error {
	resp, err := c.clt.AuthenticateProcess(ctx, &vnetv1.AuthenticateProcessRequest{
		Version:  api.Version,
		PipePath: pipePath,
	})
	if err != nil {
		return trail.FromGRPC(err)
	}
	if resp.Version != api.Version {
		return trace.BadParameter("version mismatch, user process version is %s, admin process version is %s",
			resp.Version, api.Version)
	}
	return nil
}

func (c *userProcessServiceClient) ResolveAppInfo(ctx context.Context, fqdn string) (*vnetv1.AppInfo, error) {
	resp, err := c.clt.ResolveAppInfo(ctx, &vnetv1.ResolveAppInfoRequest{
		Fqdn: fqdn,
	})
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	return resp.GetAppInfo(), nil
}

func (c *userProcessServiceClient) ReissueAppCert(ctx context.Context, appInfo *vnetv1.AppInfo, targetPort uint16) (tls.Certificate, error) {
	resp, err := c.clt.ReissueAppCert(ctx, &vnetv1.ReissueAppCertRequest{
		AppInfo:    appInfo,
		TargetPort: uint32(targetPort),
	})
	if err != nil {
		return tls.Certificate{}, trail.FromGRPC(err)
	}
	signer, err := c.appCertSigner(resp.GetCert(), appInfo.GetAppKey(), targetPort)
	if err != nil {
		return tls.Certificate{}, trace.Wrap(err)
	}
	tlsCert := tls.Certificate{
		Certificate: [][]byte{resp.GetCert()},
		PrivateKey:  signer,
	}
	return tlsCert, nil
}

func (c *userProcessServiceClient) appCertSigner(cert []byte, appKey *vnetv1.AppKey, targetPort uint16) (*rpcAppCertSigner, error) {
	x509Cert, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, trace.Wrap(err, "parsing x509 certificate")
	}
	return &rpcAppCertSigner{
		c:          c,
		pub:        x509Cert.PublicKey,
		appKey:     appKey,
		targetPort: targetPort,
	}, nil
}

type rpcAppCertSigner struct {
	c          *userProcessServiceClient
	pub        crypto.PublicKey
	appKey     *vnetv1.AppKey
	targetPort uint16
}

func (s *rpcAppCertSigner) Public() crypto.PublicKey {
	return s.pub
}

func (s *rpcAppCertSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	protoHash := vnetv1.Hash_HASH_UNSPECIFIED
	switch opts.HashFunc() {
	case 0:
		protoHash = vnetv1.Hash_HASH_NONE
	case crypto.SHA256:
		protoHash = vnetv1.Hash_HASH_SHA256
	}
	resp, err := s.c.clt.SignForApp(context.TODO(), &vnetv1.SignForAppRequest{
		AppKey:     s.appKey,
		TargetPort: uint32(s.targetPort),
		Digest:     digest,
		Hash:       protoHash,
	})
	if err != nil {
		return nil, trail.FromGRPC(err)
	}
	return resp.GetSignature(), nil
}

func (c *userProcessServiceClient) OnNewConnection(ctx context.Context, appKey *vnetv1.AppKey) error {
	// TODO(nklaassen): implement this.
	return nil
}

func (c *userProcessServiceClient) OnInvalidLocalPort(ctx context.Context, appInfo *vnetv1.AppInfo, routeToApp *proto.RouteToApp) {
	// TODO(nklaassen): implement this.
}
