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

package rotator

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/cloudtasks/apiv2/cloudtaskspb"
	privatecapb "cloud.google.com/go/security/privateca/apiv1/privatecapb"
	"google.golang.org/api/iterator"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ------------------------------------------------------------------------------
// ROOT CA ROTATION
// ------------------------------------------------------------------------------

type SubordinateRotationMap struct {
	OldCAName string `json:"old"`
	NewCAName string `json:"new"`
}

// RotateRootStage initiates a global root CA rotation.
// It creates a new staged Root CA and stages a 1:1 replacement for every active Subordinate CA in the project.
// The current implementation guarantees a 1:1 mapping of project to root CA.
func (r *Rotator) RotateRootStage(ctx context.Context) error {
	log.Printf("Starting Root CA Rotation Phase 1 (STAGE) for project %s", r.cfg.ProjectID)

	// 1. Discover the current Root CA
	rootPoolPath := fmt.Sprintf("projects/%s/locations/%s/caPools/%s", r.cfg.ProjectID, r.cfg.RootCALocation, r.cfg.RootCAPool)
	itRoot := r.caClient.ListCertificateAuthorities(ctx, &privatecapb.ListCertificateAuthoritiesRequest{
		Parent: rootPoolPath,
	})

	var oldRoot *privatecapb.CertificateAuthority
	var stagedRoot *privatecapb.CertificateAuthority

	for {
		ca, err := itRoot.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return err
		}

		if ca.State == privatecapb.CertificateAuthority_ENABLED {
			oldRoot = ca
		} else if ca.State == privatecapb.CertificateAuthority_STAGED {
			stagedRoot = ca
		}
	}

	// The logic flow:
	// 1. Dicover the pool.
	// 2. If pool is empty (no oldRoot, no stagedRoot) -> Bootscrap root CA and exit.
	// 3. If pool is NOT empty, oldRoot MUST be present.
	// 4. Check if stageRoot exists. If yes, resume. If no, create a new one by clone oldRoot.

	// 1. Bootstrapping a new root CA or using the existing one
	if oldRoot == nil && stagedRoot == nil {
		log.Printf("No existing Root CAs found in pool %s. Bootstrapping initial Root CA...", rootPoolPath)

		if r.cfg.RootCASubjectCN == "" {
			return fmt.Errorf("ROOT_CA_SUBJECT_CN environment variable is required to bootstrap a new Root CA")
		}
		if r.cfg.RootCASubjectOrg == "" {
			return fmt.Errorf("ROOT_CA_SUBJECT_ORG environment variable is required to bootstrap a new Root CA")
		}

		newRootID := fmt.Sprintf("root-ca-%d", time.Now().UnixNano()/int64(time.Millisecond))
		log.Printf("Creating initial Root CA: %s", newRootID)

		var algorithm privatecapb.CertificateAuthority_SignHashAlgorithm
		if val, ok := privatecapb.CertificateAuthority_SignHashAlgorithm_value[r.cfg.RootCAAlgorithm]; ok {
			algorithm = privatecapb.CertificateAuthority_SignHashAlgorithm(val)
		} else {
			algorithm = privatecapb.CertificateAuthority_RSA_PKCS1_4096_SHA256
		}

		opRoot, err := r.caClient.CreateCertificateAuthority(ctx, &privatecapb.CreateCertificateAuthorityRequest{
			Parent:                 rootPoolPath,
			CertificateAuthorityId: newRootID,
			CertificateAuthority: &privatecapb.CertificateAuthority{
				Type: privatecapb.CertificateAuthority_SELF_SIGNED,
				Config: &privatecapb.CertificateConfig{
					SubjectConfig: &privatecapb.CertificateConfig_SubjectConfig{
						Subject: &privatecapb.Subject{
							CommonName:   r.cfg.RootCASubjectCN,
							Organization: r.cfg.RootCASubjectOrg,
						},
					},
					X509Config: &privatecapb.X509Parameters{
						CaOptions: &privatecapb.X509Parameters_CaOptions{
							IsCa:                &[]bool{true}[0],
							MaxIssuerPathLength: &[]int32{1}[0],
						},
						KeyUsage: &privatecapb.KeyUsage{
							BaseKeyUsage: &privatecapb.KeyUsage_KeyUsageOptions{
								CertSign: true,
								CrlSign:  true,
							},
						},
					},
				},
				KeySpec: &privatecapb.CertificateAuthority_KeyVersionSpec{
					KeyVersion: &privatecapb.CertificateAuthority_KeyVersionSpec_Algorithm{
						Algorithm: algorithm,
					},
				},
				Lifetime: durationpb.New(10 * 365 * 24 * time.Hour), // 10 years default for Root
			},
		})
		if err != nil {
			return fmt.Errorf("failed to bootstrap root CA: %v", err)
		}
		newRoot, err := opRoot.Wait(ctx)
		if err != nil {
			return fmt.Errorf("failed to wait for bootstrap root CA creation: %v", err)
		}

		log.Printf("Enabling initial Root CA: %s", newRoot.Name)
		opEnable, err := r.caClient.EnableCertificateAuthority(ctx, &privatecapb.EnableCertificateAuthorityRequest{
			Name: newRoot.Name,
		})
		if err != nil {
			return fmt.Errorf("failed to enable initial root CA: %v", err)
		}
		_, err = opEnable.Wait(ctx)
		if err != nil {
			return fmt.Errorf("failed to wait for initial root CA enablement: %v", err)
		}

		log.Printf("Successfully bootstrapped global Root CA pool %s", r.cfg.RootCAPool)
		return nil
	}

	// ARCHITECTURAL RULE: We strictly maintain one active Root CA per project.
	// If we reach this point, the pool is not empty. Therefore, an old enabled Root CA
	// MUST exist for us to clone its configuration and schedule its eventual deletion.
	if oldRoot == nil {
		return fmt.Errorf("no enabled Root CA found in pool %s (cannot proceed with rotation)", rootPoolPath)
	}

	// 2. Create or Resume the new Root CA (STAGED)
	var newRoot *privatecapb.CertificateAuthority
	if stagedRoot != nil {
		log.Printf("Idempotency: Found existing STAGED Root CA: %s. Resuming...", stagedRoot.Name)
		newRoot = stagedRoot
	} else {
		newRootID := fmt.Sprintf("root-ca-%d", time.Now().UnixNano()/int64(time.Millisecond))
		log.Printf("Creating new STAGED Root CA: %s", newRootID)
		opRoot, err := r.caClient.CreateCertificateAuthority(ctx, &privatecapb.CreateCertificateAuthorityRequest{
			Parent:                 rootPoolPath,
			CertificateAuthorityId: newRootID,
			CertificateAuthority: &privatecapb.CertificateAuthority{
				Type:     privatecapb.CertificateAuthority_SELF_SIGNED,
				Config:   oldRoot.Config,
				KeySpec:  oldRoot.KeySpec,
				Lifetime: oldRoot.Lifetime,
				State:    privatecapb.CertificateAuthority_STAGED,
			},
		})
		if err != nil {
			return fmt.Errorf("failed to create new root CA: %v", err)
		}
		newRoot, err = opRoot.Wait(ctx)
		if err != nil {
			return fmt.Errorf("failed to wait for root CA creation: %v", err)
		}
	}

	// 3. Discover all regional DEVOPS pools
	itPools := r.caClient.ListCaPools(ctx, &privatecapb.ListCaPoolsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", r.cfg.ProjectID),
	})

	var rotationPairs []SubordinateRotationMap
	regionalRotationPairs := make(map[string][]SubordinateRotationMap)

	for {
		pool, err := itPools.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to list CA pools: %v", err)
		}
		if pool.Tier != privatecapb.CaPool_DEVOPS {
			continue
		}

		log.Printf("Processing regional pool: %s", pool.Name)

		// Extract region from pool name
		poolParts := strings.Split(pool.Name, "/")
		region := poolParts[3]

		// 4. Find all active and staged CAs in this pool
		itSub := r.caClient.ListCertificateAuthorities(ctx, &privatecapb.ListCertificateAuthoritiesRequest{
			Parent: pool.Name,
		})

		var activeSubs []*privatecapb.CertificateAuthority
		var stagedSubs []*privatecapb.CertificateAuthority

		for {
			sub, err := itSub.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return err
			}

			if sub.State == privatecapb.CertificateAuthority_ENABLED {
				activeSubs = append(activeSubs, sub)
			} else if sub.State == privatecapb.CertificateAuthority_STAGED || sub.State == privatecapb.CertificateAuthority_AWAITING_USER_ACTIVATION {
				stagedSubs = append(stagedSubs, sub)
			}
		}

		var currentRegionalPairs []SubordinateRotationMap

		for _, oldSub := range activeSubs {
			parts := strings.Split(oldSub.Name, "/")
			oldSubID := parts[len(parts)-1]

			// Check if we already staged a replacement for this specific CA
			var existingReplacement *privatecapb.CertificateAuthority
			for _, staged := range stagedSubs {
				if staged.Labels != nil && staged.Labels["replaces"] == oldSubID {
					existingReplacement = staged
					break
				}
			}

			var newSub *privatecapb.CertificateAuthority

			if existingReplacement != nil {
				log.Printf("Idempotency: Found existing staged replacement %s for %s", existingReplacement.Name, oldSub.Name)
				if existingReplacement.State == privatecapb.CertificateAuthority_AWAITING_USER_ACTIVATION {
					log.Printf("Activating stranded AWAITING CA...")
					newSub, err = r.activateSubordinateAgainstRoot(ctx, existingReplacement.Name, rootPoolPath, newRoot.Name)
					if err != nil {
						return err
					}
				} else {
					newSub = existingReplacement
				}
			} else {
				log.Printf("Found active Subordinate CA %s, creating staged replacement...", oldSub.Name)
				newSubID := fmt.Sprintf("sub-ca-%d", time.Now().UnixNano()/int64(time.Millisecond))

				opSub, err := r.caClient.CreateCertificateAuthority(ctx, &privatecapb.CreateCertificateAuthorityRequest{
					Parent:                 pool.Name,
					CertificateAuthorityId: newSubID,
					CertificateAuthority: &privatecapb.CertificateAuthority{
						Type:     privatecapb.CertificateAuthority_SUBORDINATE,
						Config:   oldSub.Config,
						KeySpec:  oldSub.KeySpec,
						Lifetime: oldSub.Lifetime,
						Labels:   map[string]string{"replaces": oldSubID},
					},
				})
				if err != nil {
					return fmt.Errorf("failed to create sub CA: %v", err)
				}
				_, err = opSub.Wait(ctx)
				if err != nil {
					return fmt.Errorf("failed to wait for sub CA creation: %v", err)
				}

				newSubPath := fmt.Sprintf("%s/certificateAuthorities/%s", pool.Name, newSubID)
				newSub, err = r.activateSubordinateAgainstRoot(ctx, newSubPath, rootPoolPath, newRoot.Name)
				if err != nil {
					return err
				}
			}

			pair := SubordinateRotationMap{
				OldCAName: oldSub.Name,
				NewCAName: newSub.Name,
			}
			rotationPairs = append(rotationPairs, pair)
			currentRegionalPairs = append(currentRegionalPairs, pair)
		}

		if len(currentRegionalPairs) > 0 {
			regionalRotationPairs[region] = currentRegionalPairs
		}
	}

	if len(rotationPairs) == 0 {
		return fmt.Errorf("no active subordinate CAs found across any DEVOPS pools")
	}

	// 5. Schedule Orchestration Tasks
	if r.cfg.DisableTaskScheduling {
		log.Printf("Root Rotation Staged. Skipping task scheduling.")
		return nil
	}

	timestamp := time.Now().Unix()

	// T+2h: Enable the New Root
	log.Printf("Scheduling ENABLE_NEW_ROOT task for T+2h")
	enableTaskID := fmt.Sprintf("enable-new-root-%d", timestamp)
	if err := r.scheduleRotationTask(ctx, "ENABLE_NEW_ROOT", map[string]string{"NEW_ROOT": newRoot.Name}, 2*time.Hour, enableTaskID); err != nil {
		return fmt.Errorf("failed to schedule ENABLE_NEW_ROOT: %v", err)
	}

	// T+3h, T+4h, ...: Regional Staggered Flips
	i := 0
	for region, pairs := range regionalRotationPairs {
		delay := 2*time.Hour + time.Duration(i+1)*time.Hour
		pairsJSON, _ := json.Marshal(pairs)

		log.Printf("Scheduling FLIP_SUB_CA_AGAINST_NEW_ROOT task for region %s at T+%.0f min", region, delay.Minutes())
		flipTaskID := fmt.Sprintf("flip-sub-ca-%s-%d", region, timestamp)
		if err := r.scheduleRotationTask(ctx, "FLIP_SUB_CA_AGAINST_NEW_ROOT", map[string]string{
			"ROTATION_PAIRS_JSON": string(pairsJSON),
			"ROTATION_REGION":     region,
		}, delay, flipTaskID); err != nil {
			return fmt.Errorf("failed to schedule regional flip for %s: %v", region, err)
		}
		i++
	}

	// T+Last+1h: Disable Old Root
	finalFlipDelay := 2*time.Hour + time.Duration(len(regionalRotationPairs)+1)*time.Hour
	log.Printf("Scheduling DISABLE_OLD_ROOT task for T+%.0f min", finalFlipDelay.Minutes())
	disableTaskID := fmt.Sprintf("disable-old-root-%d", timestamp)
	if err := r.scheduleRotationTask(ctx, "DISABLE_OLD_ROOT", map[string]string{"OLD_ROOT": oldRoot.Name}, finalFlipDelay, disableTaskID); err != nil {
		return fmt.Errorf("failed to schedule DISABLE_OLD_ROOT: %v", err)
	}

	// T+72h: Final Global Cleanup
	allPairsJSON, _ := json.Marshal(rotationPairs)
	cleanupTaskID := fmt.Sprintf("cleanup-old-root-and-all-subs-%d", timestamp)
	return r.ScheduleRootCleanupTask(ctx, oldRoot.Name, string(allPairsJSON), cleanupTaskID)
}

func (r *Rotator) EnableNewRoot(ctx context.Context) error {
	newRoot := os.Getenv("NEW_ROOT")
	if newRoot == "" {
		return fmt.Errorf("NEW_ROOT environment variable is required")
	}

	log.Printf("Enabling New Root CA: %s", newRoot)
	opRoot, err := r.caClient.EnableCertificateAuthority(ctx, &privatecapb.EnableCertificateAuthorityRequest{
		Name: newRoot,
	})
	if err != nil {
		return fmt.Errorf("failed to enable new root CA: %v", err)
	}

	_, err = opRoot.Wait(ctx)
	if err != nil {
		if strings.Contains(err.Error(), "Certificate Authority is in state ENABLED") {
			log.Printf("Idempotency: New Root CA %s is already ENABLED", newRoot)
		} else {
			return fmt.Errorf("failed to wait for new root CA enablement: %v", err)
		}
	}

	return nil
}

func (r *Rotator) FlipSubCA(ctx context.Context) error {
	pairsJSON := os.Getenv("ROTATION_PAIRS_JSON")
	if pairsJSON == "" {
		return fmt.Errorf("ROTATION_PAIRS_JSON environment variable is required")
	}

	region := os.Getenv("ROTATION_REGION")
	if region == "" {
		return fmt.Errorf("ROTATION_REGION environment variable is required")
	}

	var pairs []SubordinateRotationMap
	if err := json.Unmarshal([]byte(pairsJSON), &pairs); err != nil {
		return fmt.Errorf("failed to parse ROTATION_PAIRS_JSON: %v", err)
	}

	log.Printf("Starting Regional Subordinate Flip for %s for %d pairs", region, len(pairs))

	for i, pair := range pairs {
		log.Printf("Flipping Subordinate pair %d/%d: %s -> %s", i+1, len(pairs), pair.OldCAName, pair.NewCAName)

		// Enable New Subordinate
		opEnable, err := r.caClient.EnableCertificateAuthority(ctx, &privatecapb.EnableCertificateAuthorityRequest{
			Name: pair.NewCAName,
		})
		if err != nil {
			return fmt.Errorf("failed to enable new subordinate CA %s: %v", pair.NewCAName, err)
		} else {
			_, err = opEnable.Wait(ctx)
			if err != nil {
				if strings.Contains(err.Error(), "Certificate Authority is in state ENABLED") {
					log.Printf("Idempotency: New Subordinate CA %s is already ENABLED", pair.NewCAName)
				} else {
					return fmt.Errorf("failed to wait for new subordinate CA enablement: %v", err)
				}
			}
		}

		// Disable Old Subordinate
		opDisable, err := r.caClient.DisableCertificateAuthority(ctx, &privatecapb.DisableCertificateAuthorityRequest{
			Name: pair.OldCAName,
		})
		if err != nil {
			return fmt.Errorf("failed to disable old subordinate CA %s: %v", pair.OldCAName, err)
		} else {
			_, err = opDisable.Wait(ctx)
			if err != nil {
				if strings.Contains(err.Error(), "Certificate Authority is in state DISABLED") {
					log.Printf("Idempotency: Old Subordinate CA %s is already DISABLED", pair.OldCAName)
				} else {
					return fmt.Errorf("failed to wait for old subordinate CA disablement: %v", err)
				}

			}
		}
	}

	return nil
}

func (r *Rotator) DisableOldRoot(ctx context.Context) error {
	oldRoot := os.Getenv("OLD_ROOT")
	if oldRoot == "" {
		return fmt.Errorf("OLD_ROOT environment variable is required")
	}

	log.Printf("Disabling Old Root CA: %s", oldRoot)
	opDisableRoot, err := r.caClient.DisableCertificateAuthority(ctx, &privatecapb.DisableCertificateAuthorityRequest{
		Name: oldRoot,
	})
	if err != nil {
		return fmt.Errorf("failed to disable old root CA: %v", err)
	}

	_, err = opDisableRoot.Wait(ctx)
	if err != nil {
		if strings.Contains(err.Error(), "Certificate Authority is in state DISABLED") {
			log.Printf("Idempotency: Old Root CA %s is already DISABLED", oldRoot)
		} else {
			return fmt.Errorf("failed to wait for old root CA disablement: %v", err)
		}
	}

	return nil
}

func (r *Rotator) activateSubordinateAgainstRoot(ctx context.Context, caName, rootPoolPath, rootCAName string) (*privatecapb.CertificateAuthority, error) {
	log.Printf("Activating CA %s using Root %s", caName, rootCAName)

	csrResp, err := r.caClient.FetchCertificateAuthorityCsr(ctx, &privatecapb.FetchCertificateAuthorityCsrRequest{
		Name: caName,
	})
	if err != nil {
		return nil, err
	}

	// Extract Root ID
	parts := strings.Split(rootCAName, "/")
	rootID := parts[len(parts)-1]

	certID := fmt.Sprintf("cert-%d", time.Now().UnixNano()/int64(time.Millisecond))
	createCertReq := &privatecapb.CreateCertificateRequest{
		Parent:                        rootPoolPath,
		CertificateId:                 certID,
		IssuingCertificateAuthorityId: rootID,
		Certificate: &privatecapb.Certificate{
			CertificateConfig: &privatecapb.Certificate_PemCsr{PemCsr: csrResp.PemCsr},
			Lifetime:          durationpb.New(10 * 365 * 24 * time.Hour),
		},
	}
	certResp, err := r.caClient.CreateCertificate(ctx, createCertReq)
	if err != nil {
		return nil, fmt.Errorf("root signing failed: %v", err)
	}

	opActivate, err := r.caClient.ActivateCertificateAuthority(ctx, &privatecapb.ActivateCertificateAuthorityRequest{
		Name:             caName,
		PemCaCertificate: certResp.PemCertificate,
		SubordinateConfig: &privatecapb.SubordinateConfig{
			SubordinateConfig: &privatecapb.SubordinateConfig_CertificateAuthority{
				CertificateAuthority: rootCAName,
			},
		},
	})
	if err != nil {
		return nil, err
	}

	return opActivate.Wait(ctx)
}

func (r *Rotator) scheduleRotationTask(ctx context.Context, operation string, envOverrides map[string]string, delay time.Duration, taskID string) error {
	queuePath := fmt.Sprintf("projects/%s/locations/%s/queues/%s", r.cfg.ProjectID, r.cfg.QueueLocation, r.cfg.RootQueueID)
	jobURL := fmt.Sprintf("https://run.googleapis.com/v2/projects/%s/locations/%s/jobs/%s:run",
		r.cfg.ProjectID, r.cfg.Location, r.cfg.RotatorJobName)

	var envVars []map[string]string
	envVars = append(envVars, map[string]string{"name": "OPERATION", "value": operation})
	for k, v := range envOverrides {
		envVars = append(envVars, map[string]string{"name": k, "value": v})
	}

	payload := map[string]interface{}{
		"overrides": map[string]interface{}{
			"containerOverrides": []map[string]interface{}{
				{
					"env": envVars,
				},
			},
		},
	}

	body, _ := json.Marshal(payload)

	taskName := ""
	if taskID != "" {
		taskName = fmt.Sprintf("%s/tasks/%s", queuePath, taskID)
	}

	req := &cloudtaskspb.CreateTaskRequest{
		Parent: queuePath,
		Task: &cloudtaskspb.Task{
			Name: taskName,
			MessageType: &cloudtaskspb.Task_HttpRequest{
				HttpRequest: &cloudtaskspb.HttpRequest{
					HttpMethod: cloudtaskspb.HttpMethod_POST,
					Url:        jobURL,
					Body:       body,
					Headers:    map[string]string{"Content-Type": "application/json"},
					AuthorizationHeader: &cloudtaskspb.HttpRequest_OauthToken{
						OauthToken: &cloudtaskspb.OAuthToken{
							ServiceAccountEmail: r.cfg.ServiceAccountEmail,
							Scope:               "https://www.googleapis.com/auth/cloud-platform",
						},
					},
				},
			},
			ScheduleTime: timestamppb.New(time.Now().Add(delay)),
		},
	}

	_, err := r.taskClient.CreateTask(ctx, req)
	return err
}

func (r *Rotator) ScheduleRootCleanupTask(ctx context.Context, oldRoot, pairsJSON, taskID string) error {
	log.Printf("Scheduling Root Cleanup Task in %.0f hours", r.cfg.RootCleanupDelay.Hours())

	queuePath := fmt.Sprintf("projects/%s/locations/%s/queues/%s", r.cfg.ProjectID, r.cfg.QueueLocation, r.cfg.RootQueueID)
	jobURL := fmt.Sprintf("https://run.googleapis.com/v2/projects/%s/locations/%s/jobs/%s:run",
		r.cfg.ProjectID, r.cfg.Location, r.cfg.RootCleanupJobName)

	payload := map[string]interface{}{
		"overrides": map[string]interface{}{
			"containerOverrides": []map[string]interface{}{
				{
					"env": []map[string]string{
						{"name": "OPERATION", "value": "CLEANUP_ROOT"},
						{"name": "ROOT_TO_DELETE", "value": oldRoot},
						{"name": "ROTATION_PAIRS_JSON", "value": pairsJSON},
					},
				},
			},
		},
	}

	body, _ := json.Marshal(payload)

	taskName := ""
	if taskID != "" {
		taskName = fmt.Sprintf("%s/tasks/%s", queuePath, taskID)
	}

	req := &cloudtaskspb.CreateTaskRequest{
		Parent: queuePath,
		Task: &cloudtaskspb.Task{
			Name: taskName,
			MessageType: &cloudtaskspb.Task_HttpRequest{
				HttpRequest: &cloudtaskspb.HttpRequest{
					HttpMethod: cloudtaskspb.HttpMethod_POST,
					Url:        jobURL,
					Body:       body,
					Headers:    map[string]string{"Content-Type": "application/json"},
					AuthorizationHeader: &cloudtaskspb.HttpRequest_OauthToken{
						OauthToken: &cloudtaskspb.OAuthToken{
							ServiceAccountEmail: r.cfg.ServiceAccountEmail,
							Scope:               "https://www.googleapis.com/auth/cloud-platform",
						},
					},
				},
			},
			ScheduleTime: timestamppb.New(time.Now().Add(r.cfg.RootCleanupDelay)),
		},
	}

	_, err := r.taskClient.CreateTask(ctx, req)
	return err
}
