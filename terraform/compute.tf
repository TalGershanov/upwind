# Latest Amazon Linux 2023 (x86_64), looked up at plan time.
data "aws_ssm_parameter" "al2023_ami" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "aws_launch_template" "app" {
  name_prefix   = "${var.project_name}-"
  image_id      = data.aws_ssm_parameter.al2023_ami.value
  instance_type = var.instance_type
  # No key_name: no SSH, access is through SSM Session Manager.

  iam_instance_profile {
    name = aws_iam_instance_profile.app.name
  }

  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [aws_security_group.app.id]
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 1
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_type           = "gp3"
      volume_size           = 8
      encrypted             = true
      delete_on_termination = true
    }
  }

  user_data = base64encode(templatefile("${path.module}/user_data.sh.tftpl", {
    bucket        = aws_s3_bucket.artifacts.id
    artifact_key  = aws_s3_object.app.key
    region        = var.aws_region
    db_host       = local.db_host
    db_port       = local.db_port
    db_name       = local.db_name
    db_secret_arn = local.db_secret_arn
    app_port      = var.app_port
  }))

  tag_specifications {
    resource_type = "instance"
    tags          = { Name = "${var.project_name}-app" }
  }

  tag_specifications {
    resource_type = "volume"
    tags          = { Name = "${var.project_name}-app" }
  }

  lifecycle {
    create_before_destroy = true
    # The AL2023 AMI id changes every week or two. Without this, any apply would
    # create a new template version and roll both instances with no code change.
    # Code changes still roll them, because they change user_data.
    ignore_changes = [image_id]
  }
}

resource "aws_autoscaling_group" "app" {
  name                = "${var.project_name}-asg"
  min_size            = 2
  max_size            = 2
  desired_capacity    = 2
  vpc_zone_identifier = aws_subnet.private[*].id
  target_group_arns   = [aws_lb_target_group.app.arn]

  # ELB health check: an instance that fails /health is replaced.
  health_check_type         = "ELB"
  health_check_grace_period = 600 # dnf + pip + init_db can take several minutes on a t3.micro

  launch_template {
    id = aws_launch_template.app.id
    # A concrete version number (not "$Latest"), so a new template version is
    # a visible change in the plan and triggers the instance refresh below.
    version = aws_launch_template.app.latest_version
  }

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
    }
  }

  tag {
    key                 = "Name"
    value               = "${var.project_name}-app"
    propagate_at_launch = true
  }
}
