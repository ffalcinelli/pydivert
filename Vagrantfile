# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.boot_timeout = 600 # 10 minutes

  # 1. Windows 11 VM
  config.vm.define "windows" do |win|
    win.vm.box = "gusztavvargadr/windows-11-22h2-enterprise"
    win.vm.provider "virtualbox" do |vb|
      vb.memory = "4096"
      vb.cpus = 2
      vb.gui = false
      vb.customize ["modifyvm", :id, "--nested-hw-virt", "on"]
    end
    win.vm.communicator = "winrm"
    win.vm.synced_folder ".", "C:/pydivert"
    win.vm.provision "shell", path: "scripts/vagrant-provision.ps1"
  end

  # 2. Linux (Ubuntu) VM
  config.vm.define "linux" do |linux|
    linux.vm.box = "ubuntu/jammy64"
    linux.vm.provider "virtualbox" do |vb|
      vb.memory = "2048"
      vb.cpus = 2
    end
    linux.vm.synced_folder ".", "/home/vagrant/pydivert"
    linux.vm.provision "shell", path: "scripts/vagrant-provision-linux.sh"
  end

  # 3. FreeBSD VM
  config.vm.define "freebsd" do |freebsd|
    freebsd.vm.box = "freebsd/FreeBSD-14.1-STABLE"
    freebsd.vm.provider "virtualbox" do |vb|
      vb.memory = "2048"
      vb.cpus = 2
    end
    # Synchronize current directory for FreeBSD using rsync
    freebsd.vm.synced_folder ".", "/vagrant", type: "rsync"
    freebsd.vm.provision "shell", path: "scripts/vagrant-provision-freebsd.sh"
  end

  # 4. macOS (Best Effort)
  config.vm.define "macos" do |macos|
    macos.vm.box = "andrew-heck/macos-monterey"
    macos.vm.provider "virtualbox" do |vb|
      vb.memory = "4096"
      vb.cpus = 2
    end
    macos.vm.synced_folder ".", "/Users/vagrant/pydivert"
    macos.vm.provision "shell", path: "scripts/vagrant-provision-macos.sh"
  end
end
