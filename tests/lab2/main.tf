resource "aws_security_group" "rdp" {
  name = "rdp-sg"
  ingress {
    from_port   = 3389
    to_port     = 3389
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "app-logs"
  acl    = "public-read-write"
}

resource "aws_ebs_volume" "clean" {
  size      = 20
  encrypted = true
}
