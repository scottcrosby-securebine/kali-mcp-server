variable "KALI_BASE_IMAGE" {
  default = "kalilinux/kali-rolling@sha256:ef7a551400b01dc501ff97f192c5b2b1ec629576dab5032822190cd2684ca4e1"
}

variable "VCS_REF" {
  default = "unknown"
}

variable "BUILD_DATE" {
  default = "unknown"
}

# Default is the local OCI tar (dev path). Override to push, e.g.
#   OUTPUT='type=registry' docker buildx bake --set kali-mcp.tags=ghcr.io/OWNER/kali-mcp-server:vX
# CI publishes through build-push-action (see .github/workflows/container.yml),
# not through this file; this override exists so a local push is possible too.
variable "OUTPUT" {
  default = "type=oci,dest=dist/kali-mcp.oci.tar"
}

group "default" {
  targets = ["kali-mcp"]
}

target "kali-mcp" {
  context = "."
  dockerfile = "Dockerfile"
  platforms = ["linux/amd64", "linux/arm64"]
  output = [OUTPUT]
  args = {
    KALI_BASE_IMAGE = KALI_BASE_IMAGE
    VCS_REF = VCS_REF
    BUILD_DATE = BUILD_DATE
  }
}
