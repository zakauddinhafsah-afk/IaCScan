resource "aws_iam_policy" "broad" {
  name   = "admin-everything"
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_policy" "least_privilege" {
  name   = "read-one-bucket"
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:GetObject"
      Resource = "arn:aws:s3:::closed-bucket/*"
    }]
  })
}
