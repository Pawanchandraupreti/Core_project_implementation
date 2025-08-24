resource "aws_instance" "victim" {
  count         = 3
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  
  tags = {
    Name = "Victim-${count.index}"
    Role = "target"
  }
  
  user_data = <<-EOF
              #!/bin/bash
              apt-get update
              apt-get install -y curl net-tools
              EOF
}