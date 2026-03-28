# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile for PyDivert local testing on Windows 11 using VirtualBox.
# Requirements: 
#   - Vagrant (https://www.vagrantup.com/)
#   - VirtualBox (https://www.virtualbox.org/)

Vagrant.configure("2") do |config|
  # Box for Windows 11 22H2 Enterprise
  config.vm.box = "gusztavvargadr/windows-11-22h2-enterprise"

  config.vm.provider "virtualbox" do |vb|
    vb.name = "pydivert-win11"
    vb.memory = "4096"
    vb.cpus = 2
    vb.gui = false # Set to true to see the GUI
    vb.customize ["modifyvm", :id, "--vram", "128"]
    vb.customize ["modifyvm", :id, "--nested-hw-virt", "on"]
  end

  # WinRM is used for Windows communication
  config.vm.communicator = "winrm"

  # Synchronize the current directory to C:/pydivert in the guest VM
  config.vm.synced_folder ".", "C:/pydivert"

  # Run the provisioning script to install uv and dependencies
  config.vm.provision "shell", path: "scripts/vagrant-provision.ps1"

  config.vm.post_up_message = <<-MESSAGE
    -----------------------------------------------------------------------
    Windows 11 VM for PyDivert is up and running!
    
    To run tests within the VM:
      vagrant powershell -c '$env:UV_PROJECT_ENVIRONMENT="C:/pydivert_venv"; cd C:/pydivert; uv run pytest'

    To get an interactive PowerShell session:
      vagrant powershell
    -----------------------------------------------------------------------
  MESSAGE
end
