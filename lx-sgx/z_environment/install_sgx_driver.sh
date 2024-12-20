#!/usr/bin/env bash

DCAP_SGX_DRIVER_VERSION="1.41"  # Check the URL: https://download.01.org/intel-sgx/latest/linux-latest/distro/ubuntu{your_version}-server/
OOT_SGX_DRIVER_VERSION="2.11.b6f5b4a" # Check the URL: https://download.01.org/intel-sgx/latest/linux-latest/distro/ubuntu{your_version}-server/

set -eo pipefail

error() {
    echo "Error: $1" >&2
    exit 1
}

if [[ "$EUID" -ne 0 ]]; then
    error "Please run as root."
fi

RELEASE_INFO="$(cat /etc/issue)"
if [[ "$RELEASE_INFO" = *"Ubuntu 18.04"* ]]; then
    OS="Ubuntu-18.04"
    DCAP_SGX_DERIVER_URL="https://download.01.org/intel-sgx/latest/linux-latest/distro/ubuntu18.04-server/sgx_linux_x64_driver_$DCAP_SGX_DRIVER_VERSION.bin"
    OOT_SGX_DERIVER_URL="https://download.01.org/intel-sgx/latest/linux-latest/distro/ubuntu18.04-server/sgx_linux_x64_driver_$OOT_SGX_DRIVER_VERSION.bin"
elif [[ "$RELEASE_INFO" = *"Ubuntu 20.04"* ]]; then
    OS="Ubuntu-20.04"
    DCAP_SGX_DERIVER_URL="https://download.01.org/intel-sgx/latest/linux-latest/distro/ubuntu20.04-server/sgx_linux_x64_driver_$DCAP_SGX_DRIVER_VERSION.bin"
    OOT_SGX_DERIVER_URL="https://download.01.org/intel-sgx/latest/linux-latest/distro/ubuntu20.04-server/sgx_linux_x64_driver_$OOT_SGX_DRIVER_VERSION.bin"
elif [[ "$RELEASE_INFO" = *"Ubuntu 22.04"* ]]; then
    OS="Ubuntu-22.04"
    DCAP_SGX_DERIVER_URL="https://download.01.org/intel-sgx/latest/linux-latest/distro/ubuntu22.04-server/sgx_linux_x64_driver_$DCAP_SGX_DRIVER_VERSION.bin"
    OOT_SGX_DERIVER_URL="https://download.01.org/intel-sgx/latest/linux-latest/distro/ubuntu22.04-server/sgx_linux_x64_driver_$OOT_SGX_DRIVER_VERSION.bin"
elif [[ "$RELEASE_INFO" = *"Ubuntu 24.04"* ]]; then
    OS="Ubuntu-24.04"
    DCAP_SGX_DERIVER_URL="https://download.01.org/intel-sgx/latest/linux-latest/distro/ubuntu22.04-server/sgx_linux_x64_driver_$DCAP_SGX_DRIVER_VERSION.bin"
    OOT_SGX_DERIVER_URL="https://download.01.org/intel-sgx/latest/linux-latest/distro/ubuntu22.04-server/sgx_linux_x64_driver_$OOT_SGX_DRIVER_VERSION.bin"
else
    error "Ubuntu 18.04, 20.04, 22.04, or 24.04 is required."
fi

echo "DCAP SGX Driver Version: $DCAP_SGX_DRIVER_VERSION"
echo "OOT SGX Driver Version: $OOT_SGX_DRIVER_VERSION"
echo "Ubuntu Version: $OS"

apt-get update -y
apt-get install -y dkms

if [[ -x /opt/intel/sgx-aesm-service/cleanup.sh ]]; then
    /opt/intel/sgx-aesm-service/cleanup.sh
fi

# Linux kernel version v5.11 and higher versions have built-in support for the DCAP SGX driver.
# Therefore, you don't need to (and shouldn't try to) manually install the DCAP / OOT drivers.
# Run the following command to check if the matching kernel headers are installed:
# Check if the matching kernel headers are installed
if dpkg-query -s linux-headers-$(uname -r); then
    echo "Matching kernel headers already installed."
else
    echo "Matching kernel headers not found. Installing..."
    sudo apt-get install -y linux-headers-$(uname -r)
fi

# If the kernel version is lower than v5.11, execute the following script to install the SGX driver:
# echo "install $DCAP_SGX_DERIVER_URL..."
# rm -f /tmp/sgx_linux_x64_driver.bin
# curl -fsSL "$DCAP_SGX_DERIVER_URL" -o /tmp/sgx_linux_x64_driver.bin
# chmod +x /tmp/sgx_linux_x64_driver.bin
# mkdir -p /opt/intel
# /tmp/sgx_linux_x64_driver.bin
# rm -f /tmp/sgx_linux_x64_driver.bin

# echo "install $OOT_SGX_DERIVER_URL..."
# rm -f /tmp/sgx_linux_x64_driver.bin
# curl -fsSL "$OOT_SGX_DERIVER_URL" -o /tmp/sgx_linux_x64_driver.bin
# chmod +x /tmp/sgx_linux_x64_driver.bin
# mkdir -p /opt/intel
# /tmp/sgx_linux_x64_driver.bin
# rm -f /tmp/sgx_linux_x64_driver.bin

if [[ -x /opt/intel/sgx-aesm-service/startup.sh ]]; then
    /opt/intel/sgx-aesm-service/startup.sh
fi

echo "Starting SGX service with /opt/intel/sgx-aesm-service/startup.sh"
echo "SGX driver installation was successful"

