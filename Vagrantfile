# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  # 1. Windows 11 VM
  config.vm.define "windows" do |win|
    win.vm.box = "gusztavvargadr/windows-11-22h2-enterprise"
    win.vm.provider "virtualbox" do |vb|
      vb.name = "pydivert-win11"
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
    linux.vm.box = "ubuntu/24.04"
    linux.vm.provider "virtualbox" do |vb|
      vb.name = "pydivert-linux"
      vb.memory = "2048"
      vb.cpus = 2
    end
    linux.vm.synced_folder ".", "/home/vagrant/pydivert"
    linux.vm.provision "shell", inline: <<-SHELL
      apt-get update
      apt-get install -y python3-pip python3-venv libnetfilter-queue-dev
      curl -LsSf https://astral.sh/uv/install.sh | sh
      echo 'export PATH="$HOME/.local/bin:$PATH"' >> /home/vagrant/.bashrc
    SHELL
  end

  # 3. FreeBSD VM
  config.vm.define "freebsd" do |freebsd|
    freebsd.vm.box = "freebsd/FreeBSD-14.1-STABLE"
    freebsd.vm.provider "virtualbox" do |vb|
      vb.name = "pydivert-freebsd"
      vb.memory = "2048"
      vb.cpus = 2
    end
    # Synchronize current directory for FreeBSD (it uses /vagrant by default, but let's be explicit)
    freebsd.vm.synced_folder ".", "/vagrant", type: "nfs"
    freebsd.vm.provision "shell", inline: <<-SHELL
      pkg update
      pkg install -y python311 py311-pip curl
      curl -LsSf https://astral.sh/uv/install.sh | sh
      echo 'export PATH="$HOME/.local/bin:$PATH"' >> /home/vagrant/.bash_profile
    SHELL
  end
end
