locals {
  ip_map = yamldecode(file("${path.module}/resources/ips.yaml"))

}
