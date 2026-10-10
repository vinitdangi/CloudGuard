resource "aws_vpc" "cloudguard_lab" {
  cidr_block = "10.50.0.0/16"
}


resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.cloudguard_lab.id
}

resource "aws_subnet" "public_a" {
  vpc_id     = aws_vpc.cloudguard_lab.id
  cidr_block = "10.50.1.0/24"
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.cloudguard_lab.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

}


resource "aws_route_table_association" "public_assoc" {

  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public_rt.id
}





resource "aws_security_group" "aws_sgs" {
  name   = "lab_sg"
  vpc_id = aws_vpc.cloudguard_lab.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {

    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]

  }
}