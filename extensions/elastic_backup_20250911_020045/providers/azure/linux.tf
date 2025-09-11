"elastic" = {
  name               = "elastic"
  linux_sku          = "22_04-lts-gen2"
  linux_version      = "latest"
  private_ip_address = "{{ip_range}}.52"
  password           = "sgdvnkjhdshlsd"
  size               = "Standard_D4s_v3"  # 4cpu/16GB for Elastic Stack
}