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

package main

import (
	"context"
	"log"
	"os"

	"github.com/GoogleCloudPlatform/gke-workload-identity-ca-rotation/pkg/config"
	"github.com/GoogleCloudPlatform/gke-workload-identity-ca-rotation/pkg/rotator"
	"github.com/GoogleCloudPlatform/gke-workload-identity-ca-rotation/pkg/sweeper"
)

func main() {
	ctx := context.Background()

	// Load configuration from environment variables
	cfg, err := config.LoadConfig(ctx)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Determine which operation to perform based on the environment variable
	operation := os.Getenv("OPERATION")
	if operation == "" {
		log.Fatalf("OPERATION environment variable is required")
	}

	log.Printf("Starting job with OPERATION=%s", operation)

	switch operation {
	case "ROTATE":
		runRotation(ctx, cfg)
	case "CLEANUP":
		runCleanup(ctx, cfg)
	case "ROTATE_ROOT_STAGE":
		runRootRotationStage(ctx, cfg)
	case "ENABLE_NEW_ROOT":
		runEnableNewRoot(ctx, cfg)
	case "FLIP_SUB_CA_AGAINST_NEW_ROOT":
		runFlipSubCA(ctx, cfg)
	case "DISABLE_OLD_ROOT":
		runDisableOldRoot(ctx, cfg)
	case "CLEANUP_ROOT":
		runRootCleanup(ctx, cfg)
	default:
		log.Fatalf("Unknown operation: %s", operation)
	}
}

func runRotation(ctx context.Context, cfg *config.Config) {
	r, err := rotator.NewRotator(ctx, cfg)
	if err != nil {
		log.Fatalf("Failed to initialize rotator: %v", err)
	}
	defer r.Close()

	if err := r.RotateSubordinate(ctx); err != nil {
		log.Fatalf("Rotation failed: %v", err)
	}

	log.Println("Rotation job completed successfully.")
}

func runCleanup(ctx context.Context, cfg *config.Config) {
	caToDelete := os.Getenv("CA_TO_DELETE")
	if caToDelete == "" {
		log.Fatalf("CA_TO_DELETE environment variable is required for CLEANUP operation")
	}

	s, err := sweeper.NewSweeper(ctx, cfg)
	if err != nil {
		log.Fatalf("Failed to initialize sweeper: %v", err)
	}
	defer s.Close()

	if err := s.DeleteCA(ctx, caToDelete); err != nil {
		log.Fatalf("Cleanup failed: %v", err)
	}

	log.Println("Cleanup job completed successfully.")
}

func runRootRotationStage(ctx context.Context, cfg *config.Config) {
	r, err := rotator.NewRotator(ctx, cfg)
	if err != nil {
		log.Fatalf("Failed to initialize rotator: %v", err)
	}
	defer r.Close()

	if err := r.RotateRootStage(ctx); err != nil {
		log.Fatalf("Root rotation staging failed: %v", err)
	}
	log.Println("Root rotation staging completed. Subsequent phases scheduled.")
}

func runEnableNewRoot(ctx context.Context, cfg *config.Config) {
	r, err := rotator.NewRotator(ctx, cfg)
	if err != nil {
		log.Fatalf("Failed to initialize rotator: %v", err)
	}
	defer r.Close()

	if err := r.EnableNewRoot(ctx); err != nil {
		log.Fatalf("Enable root failed: %v", err)
	}
	log.Println("New root CA enabled successfully.")
}

func runFlipSubCA(ctx context.Context, cfg *config.Config) {
	r, err := rotator.NewRotator(ctx, cfg)
	if err != nil {
		log.Fatalf("Failed to initialize rotator: %v", err)
	}
	defer r.Close()

	if err := r.FlipSubCA(ctx); err != nil {
		log.Fatalf("Flip sub CA failed: %v", err)
	}
	log.Println("Subordinate CA flip completed successfully.")
}

func runDisableOldRoot(ctx context.Context, cfg *config.Config) {
	r, err := rotator.NewRotator(ctx, cfg)
	if err != nil {
		log.Fatalf("Failed to initialize rotator: %v", err)
	}
	defer r.Close()

	if err := r.DisableOldRoot(ctx); err != nil {
		log.Fatalf("Disable old root failed: %v", err)
	}
	log.Println("Old root CA disabled successfully.")
}

func runRootCleanup(ctx context.Context, cfg *config.Config) {
	s, err := sweeper.NewSweeper(ctx, cfg)
	if err != nil {
		log.Fatalf("Failed to initialize sweeper: %v", err)
	}
	defer s.Close()

	if err := s.CleanupRoot(ctx); err != nil {
		log.Fatalf("Root cleanup failed: %v", err)
	}
	log.Println("Root cleanup completed successfully.")
}
