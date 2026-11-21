resource "aws_ebs_volume" "bad_disk" {
  size = 50
}

resource "aws_ebs_volume" "good_disk" {
  size      = 50
  encrypted = true
}

resource "aws_s3_bucket" "public_one" {
  bucket = "open-bucket"
  acl    = "public-read"
}

resource "aws_s3_bucket" "private_one" {
  bucket = "closed-bucket"
  acl    = "private"
}

resource "aws_db_instance" "bad_db" {
  engine              = "mysql"
  storage_encrypted   = false
  publicly_accessible = true
}
