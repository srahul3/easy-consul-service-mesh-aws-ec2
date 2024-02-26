provider "aws" {
  region = var.region
}

resource "aws_instance" "example_server" {
  ami           = "ami-04e914639d0cca79a"
  instance_type = "t2.micro"

  tags = {
    Name = "TFCExample"
  }
}
