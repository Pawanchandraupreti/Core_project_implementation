resource "aws_instance" "c2_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  tags = {
    Name = "Simulated-C2-Server"
  }
  
  
  # OPSEC: Randomize server attributes
  user_data = <<-EOF
              #!/bin/bash
              hostnamectl set-hostname $(openssl rand -hex 4)
              EOF
}



