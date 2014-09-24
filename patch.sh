# -------------------------------------------------------------------------------------------------
# Default Options
BRANCH="master"
MSF_ROOT="/opt/metasploit/apps/pro/msf3"
REV=$(curl -s 'https://api.github.com/repos/packetfocus/sawed_off/commits' | head -n 3 | tail -n 1 | sed 's/\s//g; s/"//g; s/://g; s/,//g; s/^sha//; s/.\{33\}$//;')
# -------------------------------------------------------------------------------------------------
# Option Parser
for i in "$@"
do
  case $i in
    -b=*|--branch=*)
      BRANCH=$(echo $i | sed 's/[-a-zA-Z0-9]*=//')
      ;;
    -p=*|--prefix=*)
      MSF_ROOT=$(echo $i | sed 's/[-a-zA-Z0-9]*=//' | sed 's/\/$//;')
      ;;
    -h|--help)
      echo "OPTIONS:"
      echo "b/--branch BRANCH   -> Branch to patch from.   (Default = master)"
      echo "p/--prefix DIR      -> Location of Metasploit. (Default = /opt/metasploit/apps/pro/msf3)"
      exit 0
      ;;
    *)
      echo "[!] Unknown option: $i"
      echo "[!] For help, use the -h/--help flags."
      ;;
  esac
done
# -------------------------------------------------------------------------------------------------
# Banner & GFX
echo "######################################################################"
echo "###################    \$awed Off Patcher    ##########################"
echo "######################################################################"
echo "#                                    - Alex Levinson                  "
echo "#                                    - Joshua Perrymon                "
echo "#                                                                     "
echo "#                                    - Revision: $REV             "
echo "#---------------------------------------------------------------------"
echo "[*]  Sawed Off Branch: $BRANCH"
echo "[*] Metasploit Prefix: $MSF_ROOT"
echo "#---------------------------------------------------------------------"
# -------------------------------------------------------------------------------------------------
# Variable Setting
INC_CLASS="${MSF_ROOT%%/}/lib/rex/post/meterpreter/ui/console/command_dispatcher/priv.rb"
CLASS_FILE="${MSF_ROOT%%/}/lib/rex/post/meterpreter/ui/console/command_dispatcher/priv/power_shell.rb"
INC_CLASS_REM="https://raw.githubusercontent.com/packetfocus/sawed_off/$BRANCH/priv.rb"
CLASS_FILE_REM="https://raw.githubusercontent.com/packetfocus/sawed_off/$BRANCH/power_shell.rb"
# -------------------------------------------------------------------------------------------------
# Test for metasploit install
if [ ! -f $INC_CLASS ]; then
  echo "[!] Required metasploit libraries were not found. Please check your -p/--prefix option."
  exit 1
fi
# -------------------------------------------------------------------------------------------------
# Pull patches
if patch_one=$(curl -w '%{size_download}' -s -o $INC_CLASS $INC_CLASS_REM); then
  echo "[*] (1/2) Patches applied. ($patch_one Bytes)"
else
  echo "[!] Patch 1 of 2 failed to download. Check your -b/--branch option."
  exit 1
fi
if patch_two=$(curl -w '%{size_download}' -s -o $CLASS_FILE $CLASS_FILE_REM); then
  echo "[*] (2/2) Patches applied. ($patch_two Bytes)"
else
  echo "[!] Patch 2 of 2 failed to download. Check your -b/--branch option."
  exit 1
fi
# -------------------------------------------------------------------------------------------------
echo "#---------------------------------------------------------------------"
echo "[*] Your Metasploit installation has been successfully patched."
# -------------------------------------------------------------------------------------------------
