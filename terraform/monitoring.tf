# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# ------------------------------------------------------------------------------
# Monitoring & Alerting
# ------------------------------------------------------------------------------

resource "google_monitoring_notification_channel" "email_alert" {
  display_name = "CA Automation Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

resource "google_monitoring_alert_policy" "job_failure_alert" {
  display_name = "CA Automation Job Failure"
  combiner     = "OR"
  notification_channels = [google_monitoring_notification_channel.email_alert.name]
  
  conditions {
    display_name = "Cloud Run Job Execution Failed"
    condition_threshold {
      filter          = "resource.type = \"cloud_run_job\" AND resource.labels.job_name = starts_with(\"ca-\") AND metric.type = \"run.googleapis.com/job/completed_execution_count\" AND metric.labels.result = \"failed\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      
      aggregations {
        alignment_period     = "300s" # 5 minutes
        cross_series_reducer = "REDUCE_SUM"
        per_series_aligner   = "ALIGN_SUM"
      }
    }
  }

  documentation {
    content   = "The CA Automation Cloud Run Job execution FAILED. Check Cloud Logging for the specific error."
    mime_type = "text/markdown"
  }
}


