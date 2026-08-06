// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sweeper

import (
	"context"
	"fmt"
	"log"
	"strings"

	privateca "cloud.google.com/go/security/privateca/apiv1"
	"cloud.google.com/go/security/privateca/apiv1/privatecapb"
	"github.com/GoogleCloudPlatform/gke-workload-identity-ca-rotation/pkg/config"
)

type Sweeper struct {
	caClient *privateca.CertificateAuthorityClient
	cfg      *config.Config
}

func NewSweeper(ctx context.Context, cfg *config.Config) (*Sweeper, error) {
	caClient, err := privateca.NewCertificateAuthorityClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create privateca client: %v", err)
	}

	return &Sweeper{
		caClient: caClient,
		cfg:      cfg,
	}, nil
}

func (s *Sweeper) Close() error {
	return s.caClient.Close()
}

func (s *Sweeper) DeleteCA(ctx context.Context, caName string) error {
	log.Printf("Starting cleanup (deletion) for CA: %s", caName)

	// Delete the CA directly and let the API handle state validation.
	// ignore_active_certificates=true is required as the CA was issuing workload certs.
	opDelete, err := s.caClient.DeleteCertificateAuthority(ctx, &privatecapb.DeleteCertificateAuthorityRequest{
		Name:                     caName,
		IgnoreActiveCertificates: true,
	})
	if err != nil {
		return fmt.Errorf("failed to initiate deletion for CA %s: %v", caName, err)
	}

	_, err = opDelete.Wait(ctx)
	if err != nil {
		if strings.Contains(err.Error(), "Certificate Authority is in state DELETED") {
			log.Printf("Idempotency: CA %s is already DELETED.", caName)
		} else {
			return fmt.Errorf("failed to wait for CA deletion %s: %v", caName, err)
		}
	}

	log.Printf("Successfully deleted CA: %s", caName)
	return nil
}
