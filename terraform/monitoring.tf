# Stage 7: monitoring. Log groups, email alerts, alarms, log-based metrics, one dashboard.

locals {
  lb     = aws_lb.app.arn_suffix
  tg     = aws_lb_target_group.app.arn_suffix
  asg    = aws_autoscaling_group.app.name
  rds    = data.aws_db_instance.main.db_instance_identifier
  region = var.aws_region

  verdicts = ["PHISHING", "PROBABLY_PHISHING", "PROBABLY_NOT_PHISHING", "NOT_PHISHING", "BLOCKLIST"]
}

# ---------- Logs (names must match the agent config in user_data.sh.tftpl) ----------
resource "aws_cloudwatch_log_group" "app" {
  name              = "/phishing-detector/app"
  retention_in_days = 14
}

resource "aws_cloudwatch_log_group" "boot" {
  name              = "/phishing-detector/boot"
  retention_in_days = 14
}

resource "aws_cloudwatch_log_group" "access" {
  name              = "/phishing-detector/access"
  retention_in_days = 14
}

# One counter per verdict. Lines look like: ... Analysis message_id=.. verdict=PHISHING score=..
# (none of the five patterns is a substring of another).
resource "aws_cloudwatch_log_metric_filter" "verdict" {
  for_each       = toset(local.verdicts)
  name           = "verdict-${each.key}"
  log_group_name = aws_cloudwatch_log_group.app.name
  pattern        = "\"verdict=${each.key}\""

  metric_transformation {
    name          = "Verdict_${each.key}"
    namespace     = "PhishingDetector"
    value         = "1"
    default_value = 0
  }
}

# Log format is "<time> <LEVEL> <logger>: <message>"; match the level token.
resource "aws_cloudwatch_log_metric_filter" "errors" {
  name           = "app-errors"
  log_group_name = aws_cloudwatch_log_group.app.name
  pattern        = "\" ERROR \""

  metric_transformation {
    name          = "AppErrors"
    namespace     = "PhishingDetector"
    value         = "1"
    default_value = 0
  }
}

# Input the parser refused (see logic/email_parser.py): "Rejected email input: ..." (warning)
# and "eml_parser failed on a N-byte email" (logger.exception, so it also counts in AppErrors).
resource "aws_cloudwatch_log_metric_filter" "rejected" {
  name           = "emails-rejected"
  log_group_name = aws_cloudwatch_log_group.app.name
  pattern        = "?\"Rejected email input\" ?\"eml_parser failed\""

  metric_transformation {
    name          = "EmailsRejected"
    namespace     = "PhishingDetector"
    value         = "1"
    default_value = 0
  }
}

# ---------- ASG events (instance refreshes, launches, terminations) ----------
# Refresh status (Started / Succeeded / Failed / Cancelled) and every instance launch/terminate are
# not CloudWatch metrics, only EventBridge events. Rule -> log group, then metric filters count
# them for the dashboard. The per-minute Pending/Terminating group metrics miss short-lived states.
resource "aws_cloudwatch_log_group" "asg_events" {
  name              = "/aws/events/${var.project_name}-asg-events"
  retention_in_days = 14
}

# Lets EventBridge write to the log group above.
data "aws_iam_policy_document" "events_to_logs" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.asg_events.arn}:*"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com", "delivery.logs.amazonaws.com"]
    }
  }
}

resource "aws_cloudwatch_log_resource_policy" "events_to_logs" {
  policy_name     = "${var.project_name}-events-to-logs"
  policy_document = data.aws_iam_policy_document.events_to_logs.json
}

resource "aws_cloudwatch_event_rule" "asg_events" {
  name        = "${var.project_name}-asg-events"
  description = "Instance refresh, launch and terminate events for the app ASG"
  event_pattern = jsonencode({
    source = ["aws.autoscaling"]
    "detail-type" = [
      { prefix = "EC2 Auto Scaling Instance Refresh" },
      { prefix = "EC2 Instance Launch" },
      { prefix = "EC2 Instance Terminate" },
    ]
    detail = { AutoScalingGroupName = [local.asg] }
  })
}

resource "aws_cloudwatch_event_target" "asg_events_logs" {
  rule = aws_cloudwatch_event_rule.asg_events.name
  arn  = aws_cloudwatch_log_group.asg_events.arn

  depends_on = [aws_cloudwatch_log_resource_policy.events_to_logs]
}

# detail-type is "EC2 Auto Scaling Instance Refresh Failed".
resource "aws_cloudwatch_log_metric_filter" "refresh_failed" {
  name           = "instance-refresh-failed"
  log_group_name = aws_cloudwatch_log_group.asg_events.name
  pattern        = "\"Instance Refresh Failed\""

  metric_transformation {
    name          = "InstanceRefreshFailed"
    namespace     = "PhishingDetector"
    value         = "1"
    default_value = 0
  }
}

# detail-type is "EC2 Instance Terminate Successful": one per replaced/removed instance
# (planned refreshes count too).
resource "aws_cloudwatch_log_metric_filter" "instance_terminated" {
  name           = "instance-terminated"
  log_group_name = aws_cloudwatch_log_group.asg_events.name
  pattern        = "\"Instance Terminate Successful\""

  metric_transformation {
    name          = "InstancesTerminated"
    namespace     = "PhishingDetector"
    value         = "1"
    default_value = 0
  }
}

# detail-type is "EC2 Instance Launch Unsuccessful".
resource "aws_cloudwatch_log_metric_filter" "launch_failed" {
  name           = "instance-launch-failed"
  log_group_name = aws_cloudwatch_log_group.asg_events.name
  pattern        = "\"Instance Launch Unsuccessful\""

  metric_transformation {
    name          = "InstanceLaunchFailed"
    namespace     = "PhishingDetector"
    value         = "1"
    default_value = 0
  }
}

# ---------- Email alerts ----------
# The subscription stays "Pending confirmation" until the link in the AWS email is clicked.
resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ---------- Alarms (all notify the SNS topic) ----------
# A target is failing /health.
resource "aws_cloudwatch_metric_alarm" "unhealthy_hosts" {
  alarm_name          = "${var.project_name}-unhealthy-hosts"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "UnHealthyHostCount"
  dimensions          = { LoadBalancer = local.lb, TargetGroup = local.tg }
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 5
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

# Redundancy lost: the ASG is fixed at 2 instances. No data counts as bad.
resource "aws_cloudwatch_metric_alarm" "healthy_hosts_low" {
  alarm_name          = "${var.project_name}-healthy-hosts-low"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HealthyHostCount"
  dimensions          = { LoadBalancer = local.lb, TargetGroup = local.tg }
  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 5
  comparison_operator = "LessThanThreshold"
  threshold           = 2
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

# The app itself returns errors.
resource "aws_cloudwatch_metric_alarm" "target_5xx" {
  alarm_name          = "${var.project_name}-target-5xx"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HTTPCode_Target_5XX_Count"
  dimensions          = { LoadBalancer = local.lb }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  comparison_operator = "GreaterThanThreshold"
  threshold           = 5
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# The ALB itself fails (for example no healthy targets).
resource "aws_cloudwatch_metric_alarm" "elb_5xx" {
  alarm_name          = "${var.project_name}-elb-5xx"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HTTPCode_ELB_5XX_Count"
  dimensions          = { LoadBalancer = local.lb }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  comparison_operator = "GreaterThanThreshold"
  threshold           = 5
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Slow responses: 95th percentile above 1 second.
resource "aws_cloudwatch_metric_alarm" "response_time_p95" {
  alarm_name          = "${var.project_name}-response-time-p95"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "TargetResponseTime"
  dimensions          = { LoadBalancer = local.lb }
  extended_statistic  = "p95"
  period              = 300
  evaluation_periods  = 1
  comparison_operator = "GreaterThanThreshold"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Instances saturated. EC2 reports every 5 minutes, so 2 x 300s = 10 minutes.
resource "aws_cloudwatch_metric_alarm" "ec2_cpu" {
  alarm_name          = "${var.project_name}-ec2-cpu"
  namespace           = "AWS/EC2"
  metric_name         = "CPUUtilization"
  dimensions          = { AutoScalingGroupName = local.asg }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 2
  comparison_operator = "GreaterThanThreshold"
  threshold           = 70
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Database saturated: 10 x 60s.
resource "aws_cloudwatch_metric_alarm" "rds_cpu" {
  alarm_name          = "${var.project_name}-rds-cpu"
  namespace           = "AWS/RDS"
  metric_name         = "CPUUtilization"
  dimensions          = { DBInstanceIdentifier = local.rds }
  statistic           = "Average"
  period              = 60
  evaluation_periods  = 10
  comparison_operator = "GreaterThanThreshold"
  threshold           = 80
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Database disk filling up: less than 2 GB free (value is in bytes).
resource "aws_cloudwatch_metric_alarm" "rds_storage" {
  alarm_name          = "${var.project_name}-rds-free-storage"
  namespace           = "AWS/RDS"
  metric_name         = "FreeStorageSpace"
  dimensions          = { DBInstanceIdentifier = local.rds }
  statistic           = "Minimum"
  period              = 300
  evaluation_periods  = 1
  comparison_operator = "LessThanThreshold"
  threshold           = 2147483648
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# The app logged more than 5 ERROR lines in 5 minutes.
resource "aws_cloudwatch_metric_alarm" "app_errors" {
  alarm_name          = "${var.project_name}-app-errors"
  namespace           = "PhishingDetector"
  metric_name         = "AppErrors"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  comparison_operator = "GreaterThanThreshold"
  threshold           = 5
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# ---------- Dashboard ----------
locals {
  alarm_arns = [
    aws_cloudwatch_metric_alarm.unhealthy_hosts.arn,
    aws_cloudwatch_metric_alarm.healthy_hosts_low.arn,
    aws_cloudwatch_metric_alarm.target_5xx.arn,
    aws_cloudwatch_metric_alarm.elb_5xx.arn,
    aws_cloudwatch_metric_alarm.response_time_p95.arn,
    aws_cloudwatch_metric_alarm.ec2_cpu.arn,
    aws_cloudwatch_metric_alarm.rds_cpu.arn,
    aws_cloudwatch_metric_alarm.rds_storage.arn,
    aws_cloudwatch_metric_alarm.app_errors.arn,
  ]

  # Metric lines used more than once. Target group metrics need both dimensions.
  m_healthy   = ["AWS/ApplicationELB", "HealthyHostCount", "TargetGroup", local.tg, "LoadBalancer", local.lb]
  m_unhealthy = ["AWS/ApplicationELB", "UnHealthyHostCount", "TargetGroup", local.tg, "LoadBalancer", local.lb]
  m_requests  = ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", local.lb]
  m_target5xx = ["AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", "LoadBalancer", local.lb]
  m_elb5xx    = ["AWS/ApplicationELB", "HTTPCode_ELB_5XX_Count", "LoadBalancer", local.lb]
  m_latency   = ["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", local.lb]

  # One line per instance, found by search so replaced instances show up by themselves.
  # (EC2 metrics cannot be filtered by ASG, so the credit search lists every instance in the region.)
  # CPU comes from the CloudWatch agent (cpu_usage_active), so it can be filtered by ASG.
  search_cpu     = "SEARCH('{CWAgent,AutoScalingGroupName,InstanceId,cpu} AutoScalingGroupName=\"${local.asg}\" MetricName=\"cpu_usage_active\" cpu=\"cpu-total\"', 'Average', 60)"
  search_credits = "SEARCH('{AWS/EC2,InstanceId} MetricName=\"CPUCreditBalance\"', 'Average', 300)"
  search_mem     = "SEARCH('{CWAgent,AutoScalingGroupName,InstanceId} AutoScalingGroupName=\"${local.asg}\" MetricName=\"mem_used_percent\"', 'Average', 60)"
  search_disk    = "SEARCH('{CWAgent,AutoScalingGroupName,InstanceId,device,fstype,path} AutoScalingGroupName=\"${local.asg}\" MetricName=\"disk_used_percent\" path=\"/\"', 'Average', 60)"

  # Absolute positions, matching the layout saved in the console (Monitoring header is at y=13).
  ops_widgets = [
    # --- Health ---
    {
      type = "metric", x = 0, y = 14, width = 6, height = 6
      properties = {
        title = "Target group health", view = "timeSeries", region = local.region, period = 60, stat = "Maximum", liveData = true
        metrics = [
          concat(local.m_healthy, [{ stat = "Minimum", color = "#2ca02c" }]),
          concat(local.m_unhealthy, [{ color = "#d62728" }]),
        ]
      }
    },
    {
      type = "metric", x = 0, y = 20, width = 4, height = 6
      properties = {
        title                = "ASG instances in service", view = "gauge", region = local.region, period = 60, liveData = true
        setPeriodToTimeRange = true, stacked = true
        yAxis                = { left = { min = 0, max = 2 } }
        metrics              = [["AWS/AutoScaling", "GroupInServiceInstances", "AutoScalingGroupName", local.asg, { stat = "Average", color = "#f7b6d2", label = "ASG instances" }]]
      }
    },

    # --- Resources ---
    {
      type = "metric", x = 6, y = 14, width = 6, height = 6
      properties = {
        title   = "EC2 CPU credit balance", view = "timeSeries", region = local.region, liveData = true
        metrics = [[{ expression = local.search_credits, id = "e1" }]]
      }
    },
    {
      type = "metric", x = 12, y = 14, width = 6, height = 6
      properties = {
        title   = "CPU used % (per instance)", view = "timeSeries", region = local.region, liveData = true
        metrics = [[{ expression = local.search_cpu, id = "e1" }]]
      }
    },
    {
      type = "metric", x = 18, y = 14, width = 6, height = 5
      properties = {
        title   = "Disk used % (/)", view = "timeSeries", region = local.region, liveData = true
        metrics = [[{ expression = local.search_disk, id = "e1" }]]
      }
    },
    {
      type = "metric", x = 18, y = 19, width = 6, height = 7
      properties = {
        title   = "Memory used %", view = "timeSeries", region = local.region, liveData = true
        metrics = [[{ expression = local.search_mem, id = "e1" }]]
      }
    },
    {
      type = "metric", x = 4, y = 20, width = 12, height = 6
      properties = {
        title   = "App errors", view = "timeSeries", region = local.region, period = 60
        metrics = [["PhishingDetector", "AppErrors", { stat = "Sum" }]]
      }
    },

    # --- Traffic and success vs failure ---
    {
      type = "metric", x = 0, y = 26, width = 14, height = 6
      properties = {
        title   = "Requests per minute", view = "timeSeries", region = local.region, period = 60
        metrics = [concat(local.m_requests, [{ stat = "Sum" }])]
      }
    },
    {
      type = "metric", x = 14, y = 26, width = 7, height = 6
      properties = {
        title = "Responses by status (stacked)", view = "timeSeries", stacked = true, region = local.region, period = 60
        metrics = [
          ["AWS/ApplicationELB", "HTTPCode_Target_2XX_Count", "LoadBalancer", local.lb, { stat = "Sum", label = "Target 2XX" }],
          ["AWS/ApplicationELB", "HTTPCode_Target_4XX_Count", "LoadBalancer", local.lb, { stat = "Sum", label = "Target 4XX" }],
          concat(local.m_target5xx, [{ stat = "Sum", label = "Target 5XX" }]),
          concat(local.m_elb5xx, [{ stat = "Sum", label = "ELB 5XX" }]),
        ]
      }
    },
    {
      type = "metric", x = 21, y = 26, width = 3, height = 6
      properties = {
        title = "Response time (s)", view = "timeSeries", region = local.region, period = 60, liveData = true
        metrics = [
          concat(local.m_latency, [{ stat = "p50", label = "p50" }]),
          concat(local.m_latency, [{ stat = "p95", label = "p95" }]),
        ]
      }
    },

    # --- Database ---
    {
      type = "metric", x = 0, y = 32, width = 8, height = 6
      properties = {
        title   = "RDS connections", view = "timeSeries", region = local.region, period = 60, stacked = false, liveData = true
        yAxis   = { left = { min = 0 } }
        metrics = [["AWS/RDS", "DatabaseConnections", "DBInstanceIdentifier", local.rds, { stat = "Average", color = "#9467bd" }]]
      }
    },
    {
      type = "metric", x = 8, y = 32, width = 5, height = 6
      properties = {
        title   = "RDS CPU %", view = "timeSeries", region = local.region, period = 60, liveData = true
        yAxis   = { left = { max = 50 } }
        metrics = [["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", local.rds, { stat = "Average", color = "#9467bd" }]]
      }
    },
    {
      type = "metric", x = 13, y = 32, width = 8, height = 6
      properties = {
        title   = "RDS free storage (bytes)", view = "timeSeries", region = local.region, period = 300, stat = "Minimum"
        stacked = false, liveData = true, sparkline = false, setPeriodToTimeRange = false, singleValueFullPrecision = false
        yAxis   = { left = { showUnits = true } }
        metrics = [["AWS/RDS", "FreeStorageSpace", "DBInstanceIdentifier", local.rds, { label = "RDS free storage", color = "#9467bd" }]]
      }
    },
    {
      # Used = allocated storage (GiB -> bytes, from the DB instance) minus free space.
      type = "metric", x = 21, y = 32, width = 3, height = 6
      properties = {
        title = "RDS used storage", view = "singleValue", region = local.region, period = 300, stat = "Average", sparkline = false, liveData = true
        metrics = [
          [{ expression = "${data.aws_db_instance.main.allocated_storage * 1073741824} - m1", label = "used", id = "e1", color = "#9467bd" }],
          ["AWS/RDS", "FreeStorageSpace", "DBInstanceIdentifier", local.rds, { id = "m1", label = "m1", period = 60, color = "#9467bd", visible = false }],
        ]
      }
    },

    # --- Logs ---
    {
      type = "log", x = 0, y = 44, width = 12, height = 10
      properties = {
        title = "Latest 50 app log lines", view = "table", region = local.region
        query = "SOURCE '${aws_cloudwatch_log_group.app.name}' | fields @timestamp, @logStream, @message | sort @timestamp desc | limit 50"
      }
    },
    {
      type = "log", x = 12, y = 44, width = 12, height = 10
      properties = {
        title = "Analyses per instance (5 min)", view = "timeSeries", region = local.region
        query = "SOURCE '${aws_cloudwatch_log_group.app.name}' | filter @message like /Analysis message_id/ | stats count(*) as analyses by bin(5m), @logStream"
      }
    },
    {
      type = "log", x = 0, y = 54, width = 24, height = 6
      properties = {
        title = "Recent 4XX/5XX requests", view = "table", region = local.region
        query = "SOURCE '${aws_cloudwatch_log_group.access.name}' | filter @message like /\" [45]\\d\\d/ | fields @timestamp, @logStream, @message | sort @timestamp desc | limit 20"
      }
    },

    # --- Deployments: instance launches/terminations and refresh events (from the ASG events log) ---
    {
      type = "metric", x = 0, y = 38, width = 12, height = 6
      properties = {
        title = "ASG churn (terminations and failures)", view = "timeSeries", region = local.region, period = 60
        metrics = [
          ["AWS/AutoScaling", "GroupInServiceInstances", "AutoScalingGroupName", local.asg, { stat = "Average", label = "In service" }],
          ["PhishingDetector", "InstancesTerminated", { stat = "Sum", label = "Instances terminated" }],
          ["PhishingDetector", "InstanceLaunchFailed", { stat = "Sum", label = "Launch failed" }],
          ["PhishingDetector", "InstanceRefreshFailed", { stat = "Sum", label = "Refresh failed" }],
        ]
      }
    },
    {
      type = "log", x = 12, y = 38, width = 12, height = 6
      properties = {
        title = "ASG events (launches, terminations, refreshes)", view = "table", region = local.region
        query = "SOURCE '${aws_cloudwatch_log_group.asg_events.name}' | fields @timestamp, `detail-type`, detail.EC2InstanceId, detail.Cause, @message | sort @timestamp desc | limit 20"
      }
    },
  ]
}

# ---------- Business overview (follows the dashboard time range) ----------
locals {
  # Verdict_* metric lines as hidden inputs m1..m5 for metric math, in local.verdicts order:
  # m1 PHISHING, m2 PROBABLY_PHISHING, m3 PROBABLY_NOT_PHISHING, m4 NOT_PHISHING, m5 BLOCKLIST.
  vm_hidden = [for i, v in local.verdicts : ["PhishingDetector", "Verdict_${v}", { id = "m${i + 1}", stat = "Sum", visible = false }]]

  # Sum of all five verdicts, and of PHISHING + PROBABLY_PHISHING + BLOCKLIST.
  expr_analyzed = "SUM([m1,m2,m3,m4,m5])"
  expr_detected = "SUM([m1,m2,m5])"

  overview_widgets = [
    {
      type = "metric", x = 0, y = 1, width = 4, height = 3
      properties = {
        title = "Emails analyzed", view = "singleValue", region = local.region, setPeriodToTimeRange = true
        metrics = concat(
          [[{ expression = local.expr_analyzed, label = "Emails analyzed", id = "e1" }]],
          local.vm_hidden,
        )
      }
    },
    {
      type = "metric", x = 4, y = 1, width = 4, height = 3
      properties = {
        title = "Phishing detected", view = "singleValue", region = local.region, setPeriodToTimeRange = true
        metrics = concat(
          [[{ expression = local.expr_detected, label = "Phishing detected", id = "e1" }]],
          local.vm_hidden,
        )
      }
    },
    {
      type = "metric", x = 4, y = 4, width = 4, height = 3
      properties = {
        title = "Phishing rate %", view = "singleValue", region = local.region, setPeriodToTimeRange = true
        metrics = concat(
          [[{ expression = "IF(${local.expr_analyzed} > 0, 100*${local.expr_detected}/${local.expr_analyzed}, 0)", label = "Phishing rate %", id = "e1" }]],
          local.vm_hidden,
        )
      }
    },
    {
      type = "metric", x = 0, y = 4, width = 4, height = 3
      properties = {
        title   = "Emails rejected", view = "singleValue", region = local.region, setPeriodToTimeRange = true
        metrics = [["PhishingDetector", "EmailsRejected", { stat = "Sum" }]]
      }
    },
    {
      type = "metric", x = 8, y = 1, width = 4, height = 3
      properties = {
        title   = "Healthy hosts (now)", view = "singleValue", region = local.region, period = 60, liveData = true
        metrics = [concat(local.m_healthy, [{ stat = "Minimum" }])]
      }
    },
    {
      type = "metric", x = 8, y = 4, width = 4, height = 3
      properties = {
        title = "Error rate %", view = "singleValue", region = local.region, setPeriodToTimeRange = true
        metrics = [
          [{ expression = "IF(m3 > 0, 100*(FILL(m1,0)+FILL(m2,0))/m3, 0)", label = "Error rate %", id = "e1" }],
          concat(local.m_target5xx, [{ id = "m1", stat = "Sum", visible = false }]),
          concat(local.m_elb5xx, [{ id = "m2", stat = "Sum", visible = false }]),
          concat(local.m_requests, [{ id = "m3", stat = "Sum", visible = false }]),
        ]
      }
    },
    {
      type = "metric", x = 12, y = 1, width = 7, height = 6
      properties = {
        title   = "Verdict mix", view = "pie", region = local.region, setPeriodToTimeRange = true
        metrics = [for v in local.verdicts : ["PhishingDetector", "Verdict_${v}", { stat = "Sum", label = v }]]
      }
    },
    {
      type = "metric", x = 8, y = 7, width = 11, height = 6
      properties = {
        title   = "Verdicts over time", view = "timeSeries", stacked = true, region = local.region, period = 300
        metrics = [for v in local.verdicts : ["PhishingDetector", "Verdict_${v}", { stat = "Sum", label = v }]]
      }
    },
    {
      type = "metric", x = 0, y = 7, width = 8, height = 6
      properties = {
        title   = "Emails rejected over time", view = "timeSeries", region = local.region, period = 300
        metrics = [["PhishingDetector", "EmailsRejected", { stat = "Sum" }]]
      }
    },
    {
      type = "alarm", x = 19, y = 1, width = 5, height = 12
      properties = {
        title  = "Alarms"
        alarms = local.alarm_arns
      }
    },
  ]
}

locals {
  # Every widget has absolute coordinates (matching the layout saved in the console).
  widgets = concat(
    [{ type = "text", x = 0, y = 0, width = 24, height = 1, properties = { markdown = "## Business overview" } }],
    local.overview_widgets,
    [{ type = "text", x = 0, y = 13, width = 24, height = 1, properties = { markdown = "## Monitoring" } }],
    local.ops_widgets,
  )
}

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = var.project_name
  dashboard_body = jsonencode({ start = "-PT3H", widgets = local.widgets })
}

output "dashboard_url" {
  description = "Open this to see the whole system on one page."
  value       = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.main.dashboard_name}"
}
