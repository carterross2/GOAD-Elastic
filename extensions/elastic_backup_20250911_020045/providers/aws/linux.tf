"elastic" = {
  name               = "elastic"
  linux_sku          = "22_04-lts-gen2"
  linux_version      = "latest"
  ami                = "ami-00c71bd4d220aa22a"
  private_ip_address = "{{ip_range}}.52"
  password           = "sgdvnkjhdshlsd"
  size               = "t3.xlarge"  # 4cpu / 16GB for Elastic Stack
}