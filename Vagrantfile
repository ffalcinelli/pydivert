# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.synced_folder ".", "/pydivert"

  # --- Linux VM (Ubuntu 22.04 with eBPF support) ---
  config.vm.define "linux" do |linux|
    linux.vm.box = "ubuntu/jammy64"
    linux.vm.hostname = "pydivert-linux"
    linux.vm.provider "virtualbox" do |vb|
      vb.memory = "2048"
      vb.cpus = 2
    end
    linux.vm.provision "shell", inline: <<-SHELL
      apt-get update
      apt-get install -y python3-pip python3-venv libbpf-dev clang llvm libelf-dev
      curl -LsSf https://astral.sh/uv/install.sh | UV_INSTALL_DIR=/usr/local/bin sh
      cd /pydivert
      uv sync --extra test --extra linux
    SHELL
  end

  # --- Windows VM (Windows 11 with WinDivert support) ---
  config.vm.define "windows" do |windows|
    windows.vm.box = "gusztavvargadr/windows-11-22h2-enterprise"
    windows.vm.communicator = "winrm"
    windows.vm.synced_folder ".", "C:/pydivert"
    windows.vm.provider "virtualbox" do |vb|
      vb.memory = "4096"
      vb.cpus = 2
      vb.gui = false
      vb.customize ["modifyvm", :id, "--vram", "128"]
      vb.customize ["modifyvm", :id, "--nested-hw-virt", "on"]
    end
    windows.vm.provision "shell", path: "scripts/vagrant-provision.ps1"
  end
end
