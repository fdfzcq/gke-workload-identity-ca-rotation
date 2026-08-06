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
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"cloud.google.com/go/security/privateca/apiv1/privatecapb"
)

type subordinateRotationMap struct {
	OldCAName string `json:"old"`
	NewCAName string `json:"new"`
}

// CleanupRoot handles the final phase of a Root CA rotation (Phase 3).
// It permanently deletes the old Root CA and all of the old Subordinate CAs
// across all regions, effectively ending their 30-day tombstone lifecycle.
func (s *Sweeper) CleanupRoot(ctx context.Context) error {
	subToDeleteJSON := os.Getenv("ROTATION_PAIRS_JSON")
	rootToDelete := os.Getenv("ROOT_TO_DELETE")

	if rootToDelete == "" {
		return fmt.Errorf("missing ROOT_TO_DELETE environment variable")
	}

	log.Printf("Starting final cleanup for old Root chain: %s", rootToDelete)

	// 1. Delete all old subordinate CAs
	var pairs []subordinateRotationMap
	if subToDeleteJSON != "" {
		if err := json.Unmarshal([]byte(subToDeleteJSON), &pairs); err == nil {
			for _, pair := range pairs {
				log.Printf("Deleting old subordinate CA: %s", pair.OldCAName)
				opSub, err := s.caClient.DeleteCertificateAuthority(ctx, &privatecapb.DeleteCertificateAuthorityRequest{
					Name:                     pair.OldCAName,
					IgnoreActiveCertificates: true,
				})
				if err != nil {
					return fmt.Errorf("failed to initiate subordinate deletion %s: %v", pair.OldCAName, err)
				}
				_, err = opSub.Wait(ctx)
				if err != nil {
					if strings.Contains(err.Error(), "Certificate Authority is in state DELETED") {
						log.Printf("Idempotency: CA %s is already DELETED.", pair.OldCAName)
					} else {
						return fmt.Errorf("failed to wait for subordinate deletion %s: %v", pair.OldCAName, err)
					}
				}
			}
		} else {
			return fmt.Errorf("failed to parse ROTATION_PAIRS_JSON: %v", err)
		}
	}

	// 2. Delete central root CA
	log.Printf("Deleting old root CA: %s", rootToDelete)
	opRoot, err := s.caClient.DeleteCertificateAuthority(ctx, &privatecapb.DeleteCertificateAuthorityRequest{
		Name:                     rootToDelete,
		IgnoreActiveCertificates: true,
	})
	if err != nil {
		return fmt.Errorf("failed to initiate root deletion %s: %v", rootToDelete, err)
	}
	_, err = opRoot.Wait(ctx)
	if err != nil {
		if strings.Contains(err.Error(), "Certificate Authority is in state DELETED") {
			log.Printf("Idempotency: CA %s is already DELETED.", rootToDelete)
		} else {
			return fmt.Errorf("failed to wait for root deletion %s: %v", rootToDelete, err)
		}
	}

	log.Printf("Root CA chain cleanup successfully completed.")
	return nil
}
