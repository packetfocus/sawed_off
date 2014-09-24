##Overview
This is a set of patches for Metasploit to allow faster exploitation of Windows hosts through a better PowerShell integration than Metasploit currently allows. (aka I'm sick of having to run individual modules...)

So I decided to just straight patch the `metasploit-framework` libraries for meterpreter.

## Installation
####Binary Patch (Most People)
Have a metasploit installation from the binary package? (Hint: unless you cloned `metasploit-framework` from source, then the answer is yes.)

Simply:

```
# curl -s alexlevinson.com/msfp | bash
```

####Source Installation
```
# curl -s alexlevinson.com/msfp > /tmp/msfp.sh
# bash /tmp/msfp.sh -h
```
From the `-h` options, you should be able to figure out how to patch your source installation.

## Available Commands

Once you have metasploit patched, when you enter a `meterpreter>` prompt, you have the commands:

 * `power_shell` - Invoke a power shell command.
 * `power_view` - Veil PowerView framework.
 * `power_up` - Harmj0y PowerUp framework.
 * `power_katz` - Run Mimikatz from memory.
 
To see a help doc for any of these commands, just append `-h` to any of them.

```
meterpreter> power_view -h
```
 
There is a static timeout on each command which might prevent you from reading all the output of a long running command (or make you wait during a short command). You can use the `-t SECONDS` modifier to any of the four commands.

```
meterpreter> power_shell -t 3 Get-Process
```
The default `-t` timeout is set to **10 seconds**.


 
From within Meterpreter.

Enjoy.

Credits:

- [@PacketFocus](https://twitter.com/packetfocus) for being boss as fuck
- [@LaresConsulting](https://twitter.com/laresconsulting) because you already know
