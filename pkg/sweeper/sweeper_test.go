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
	"os"
	"testing"

	"github.com/GoogleCloudPlatform/gke-workload-identity-ca-rotation/pkg/config"
)

func TestIntegration_DeleteCA(t *testing.T) {
	if os.Getenv("RUN_INTEGRATION_TESTS") == "" {
		t.Skip("Skipping integration test. Set RUN_INTEGRATION_TESTS=1 to run.")
	}

	caToDelete := os.Getenv("TEST_CA_TO_DELETE")
	if caToDelete == "" {
		t.Skip("Skipping sweeper integration test. Set TEST_CA_TO_DELETE to a disabled/staged CA name.")
	}

	// Set some defaults if they are missing
	if os.Getenv("PROJECT_ID") == "" {
		os.Setenv("PROJECT_ID", "braided-tracker-464114-g8")
	}
	if os.Getenv("LOCATION") == "" {
		os.Setenv("LOCATION", "us-central1")
	}
	if os.Getenv("POOL_NAME") == "" {
		os.Setenv("POOL_NAME", "subordinate-ca-pool-us-central1")
	}
	if os.Getenv("ROOT_CA_NAME") == "" {
		os.Setenv("ROOT_CA_NAME", "braided-root-ca")
	}
	if os.Getenv("ROOT_CA_POOL") == "" {
		os.Setenv("ROOT_CA_POOL", "root_ca_us")
	}
	if os.Getenv("ROOT_CA_LOCATION") == "" {
		os.Setenv("ROOT_CA_LOCATION", "us-central1")
	}
	if os.Getenv("QUEUE_ID") == "" {
		os.Setenv("QUEUE_ID", "ca-cleanup-queue-v2")
	}
	if os.Getenv("ROOT_QUEUE_ID") == "" {
		os.Setenv("ROOT_QUEUE_ID", "ca-root-cleanup-queue-v2")
	}

	ctx := context.Background()
	cfg, err := config.LoadConfig(ctx)
	if err != nil {
		t.Fatalf("Failed to load configuration: %v", err)
	}

	// Format short IDs into full resource paths for the test
	caToDelete = fmt.Sprintf("projects/%s/locations/%s/caPools/%s/certificateAuthorities/%s",
		cfg.ProjectID, cfg.Location, cfg.CAPoolName, caToDelete)

	s, err := NewSweeper(ctx, cfg)
	if err != nil {
		t.Fatalf("Failed to create Sweeper: %v", err)
	}
	defer s.Close()

	t.Logf("Running integration test to delete CA: %s", caToDelete)

	err = s.DeleteCA(ctx, caToDelete)
	if err != nil {
		t.Fatalf("DeleteCA failed: %v", err)
	}

	t.Log("Successfully completed DeleteCA integration test.")
}

func TestIntegration_CleanupRoot(t *testing.T) {
	if os.Getenv("RUN_INTEGRATION_TESTS") == "" {
		t.Skip("Skipping integration test. Set RUN_INTEGRATION_TESTS=1 to run.")
	}

	// Set some defaults if they are missing
	if os.Getenv("PROJECT_ID") == "" {
		os.Setenv("PROJECT_ID", "braided-tracker-464114-g8")
	}
	if os.Getenv("LOCATION") == "" {
		os.Setenv("LOCATION", "us-central1")
	}
	if os.Getenv("POOL_NAME") == "" {
		os.Setenv("POOL_NAME", "subordinate-ca-pool-us-central1")
	}
	if os.Getenv("ROOT_CA_NAME") == "" {
		os.Setenv("ROOT_CA_NAME", "braided-root-ca")
	}
	if os.Getenv("ROOT_CA_POOL") == "" {
		os.Setenv("ROOT_CA_POOL", "root_ca_us")
	}
	if os.Getenv("ROOT_CA_LOCATION") == "" {
		os.Setenv("ROOT_CA_LOCATION", "us-central1")
	}
	if os.Getenv("QUEUE_ID") == "" {
		os.Setenv("QUEUE_ID", "ca-cleanup-queue-v2")
	}
	if os.Getenv("ROOT_QUEUE_ID") == "" {
		os.Setenv("ROOT_QUEUE_ID", "ca-root-cleanup-queue-v2")
	}
	if os.Getenv("CLEANUP_JOB_NAME") == "" {
		os.Setenv("CLEANUP_JOB_NAME", "ca-cleanup-job")
	}

	// Note: For a real integration test, these variables must point to actual
	// DISABLED CAs in your Google Cloud Project.
	if os.Getenv("ROOT_TO_DELETE") == "" {
		os.Setenv("ROOT_TO_DELETE", "projects/braided-tracker-464114-g8/locations/us-central1/caPools/root_ca_us/certificateAuthorities/braided-root-ca")
	}
	if os.Getenv("ROTATION_PAIRS_JSON") == "" {
		os.Setenv("ROTATION_PAIRS_JSON", `[{"old": "projects/braided-tracker-464114-g8/locations/us-central1/caPools/subordinate-ca-pool-us-central1/certificateAuthorities/sub-ca-1779972709046", "new": "projects/braided-tracker-464114-g8/locations/us-central1/caPools/subordinate-ca-pool-us-central1/certificateAuthorities/sub-ca-root-rot-1779973145751"}]`)
	}

	ctx := context.Background()
	cfg, err := config.LoadConfig(ctx)
	if err != nil {
		t.Fatalf("Failed to load configuration: %v", err)
	}

	s, err := NewSweeper(ctx, cfg)
	if err != nil {
		t.Fatalf("Failed to create Sweeper: %v", err)
	}
	defer s.Close()

	t.Logf("Running integration test for global Root chain cleanup")

	err = s.CleanupRoot(ctx)
	if err != nil {
		t.Fatalf("CleanupRoot failed: %v", err)
	}

	t.Log("Successfully completed CleanupRoot integration test.")
}
