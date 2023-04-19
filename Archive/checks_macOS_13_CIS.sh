#!/bin/bash

# Variables
HOSTNAME=$(hostname)
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_FILE="${HOSTNAME}_${TIMESTAMP}.txt"
TOTAL_CHECKS=118
SECONDS=0
TIMER_PID=


# Create an output file avoiding temptation to include word "swell" in the filename ;)
touch $OUTPUT_FILE
rm -f /tmp/check_cis_complete

# Print ASCII art on screen
clear
cat << "EOF"
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |        CIS Benchmark Checker          |
 |-+-+-+-\          ~          /+-+-+-+-+|
 |              MacOS 13                 |      
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                                                                 
                                                                                             
EOF

# Pause to display ASCII art for 2 seconds. 
sleep 3

# Clear the screen before showing the dashboard view
clear

# Colors for output
GREEN=$(tput setaf 2)
RED=$(tput setaf 1)
YELLOW=$(tput setaf 3)
CYAN=$(tput setaf 6)
RESET=$(tput sgr0)


# Helper functions
# Define helper functions for checks to print and store the check results (pass, fail, and not_applicable)

# pass: Prints and stores a "PASS" result for a check
pass() {
  echo -e "${GREEN}PASS${RESET}\t$1\t$2"
  echo -e "PASS\t$1\t$2" >> $OUTPUT_FILE
  ((PASSED++))
}

# fail: Prints and stores a "FAIL" result for a check
fail() {
  echo -e "${RED}FAIL${RESET}\t$1\t$2"
  echo -e "FAIL\t$1\t$2" >> $OUTPUT_FILE
  ((FAILED++))
}

# not_applicable: Prints and stores a "Not Applicable" result for a check
not_applicable() {
  echo -e "${YELLOW}N/A${RESET}\t$1\t$2"
  echo -e "N/A\t$1\t$2" >> $OUTPUT_FILE
  ((NOT_APPLICABLE++))
}

# Update header information

update_header() {
  (
    while [ ! -f /tmp/check_cis_complete ]; do
      local progress=$((PASSED + FAILED + NOT_APPLICABLE))
      local percentage=$(awk "BEGIN { pc=100*${progress}/${TOTAL_CHECKS}; i=int(pc); print (pc-i<0.5)?i:i+1 }")

      tput cup 0 0
      echo -e "User: $(whoami) | Date: $(date '+%Y-%m-%d %H:%M:%S') | Hostname: $HOSTNAME"
      echo -e "${CYAN}Progress:${RESET} [${GREEN}${PASSED}${RESET}/${RED}${FAILED}${RESET}/${YELLOW}${NOT_APPLICABLE}${RESET}] ${CYAN}${percentage}%${RESET}"
      echo "-----------------------------------------------------------------------------------"

      sleep 1
    done
  ) &
  TIMER_PID=$!
  disown
}

#####################################################################
##
##  Begin CIS MacOS 13 Checks
##  
#####################################################################

############################## C-1.1 ################################
## this one took some research, because grep was always returning status of 1 because the command was successful..
## So, I decided to write the output to a tmp file, grep through that, then clean it up once finding recorded.
check_1_1() {
  local check_id="1.1"
  local title="Ensure All Apple-provided Software Is Current"
  local check_command="sudo softwareupdate -l"
  local temp_file=$(mktemp)

  eval $check_command > "$temp_file" 2>&1
  grep -i 'No new software available.' "$temp_file" >/dev/null 2>&1
  local exit_status=$?

  if [ $exit_status -eq 0 ]; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi

  rm -f "$temp_file"
}

############################## C-1.2 ################################
check_1_2() {
  local check_id="1.2"
  local title="Verify that autoupdate is enabled"
  local check_command='defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled'

  if eval $check_command >/dev/null 2>&1 && [ "$(eval $check_command)" -eq 1 ]; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-1.3 ################################
check_1_3() {
  local check_id="1.3"
  local title="Ensure Download New Updates When Available Is Enabled"
  local check_command='defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload'

  if eval $check_command >/dev/null 2>&1 && [ "$(eval $check_command)" -eq 1 ]; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-1.4 ################################
check_1_4() {
  local check_id="1.4"
  local title="Ensure Install of macOS Updates Is Enabled"
  local check_command='defaults read /Library/Preferences/com.apple.commerce AutoUpdateRestartRequired'

  if eval $check_command >/dev/null 2>&1 && [ "$(eval $check_command)" -eq 1 ]; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-1.5 ################################
check_1_5() {
  local check_id="1.5"
  local title="Ensure Install Application Updates from the App Store Is Enabled"
  local check_command='defaults read /Library/Preferences/com.apple.commerce AutoUpdate'

  if eval $check_command >/dev/null 2>&1 && [ "$(eval $check_command)" -eq 1 ]; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-1.6 ################################
check_1_6() {
  local check_id="1.6"
  local title="Ensure Install Security Updates and System Files Is Enabled"
  local pref1_command="defaults read /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall"
  local pref2_command="defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall"

  if [ "$(eval $pref1_command)" -eq 1 ] && [ "$(eval $pref2_command)" -eq 1 ]; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-1.7 ################################
check_1_7() {
  local check_id="1.7"
  local title="Ensure Software Update Deferment Is Less Than or Equal to 30 Days"
  local deferment_command="defaults read /Library/Preferences/com.apple.SoftwareUpdate ConfigDataDefermentInterval"

  if [ "$(eval $deferment_command 2>/dev/null)" -le 30 ]; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-2.1.1.1 (MANUAL) ############################
check_2_1_1_1() {
  local check_id="2.1.1.1"
  local title="Audit iCloud Keychain"
  local users=$(dscl . -list /Users | grep -vE '^_|daemon|nobody')
  local check_failed=false

  for user in $users; do
    local keychain_sync_status=$(sudo -u $user defaults read ~/Library/Preferences/MobileMeAccounts 2>/dev/null | awk '/KEYCHAIN_SYNC/ {getline; print $3}')
    if [ "$keychain_sync_status" = "1;" ]; then
      check_failed=true
    fi
  done

  if [ "$check_failed" = true ]; then
    fail "$check_id" "$title"
  else
    pass "$check_id" "$title"
  fi
}

############################## C-2.1.1.2 (MANUAL) ############################
check_2_1_1_2() {
  local check_id="2.1.1.2"
  local title="Audit iCloud Drive"
  local users=$(dscl . -list /Users | grep -vE '^_|daemon|nobody')
  local check_failed=false

  for user in $users; do
    local icloud_drive_status=$(sudo -u $user defaults read ~/Library/Preferences/MobileMeAccounts 2>/dev/null | awk '/MOBILE_DOCUMENTS/ {getline; print $3}')
    if [ "$icloud_drive_status" = "1;" ]; then
      check_failed=true
    fi
  done

  if [ "$check_failed" = true ]; then
    fail "$check_id" "$title"
  else
    pass "$check_id" "$title"
  fi
}
############################## C-2.1.1.3 ####################################
check_2_1_1_3() {
  local check_id="2.1.1.3"
  local title="Ensure iCloud Drive Document and Desktop Sync Is Disabled"
  local users=$(dscl . -list /Users | grep -vE '^_|daemon|nobody')
  local check_failed=false

  for user in $users; do
    local documents_status=$(sudo -u $user ls -l "/Users/$user/Library/Mobile Documents/com~apple~CloudDocs/Documents/" 2>/dev/null | grep -c '^total')
    local desktop_status=$(sudo -u $user ls -l "/Users/$user/Library/Mobile Documents/com~apple~CloudDocs/Desktop/" 2>/dev/null | grep -c '^total')

    if [ "$documents_status" -gt 0 ] || [ "$desktop_status" -gt 0 ]; then
      check_failed=true
    fi
  done

  if [ "$check_failed" = true ]; then
    fail "$check_id" "$title"
  else
    pass "$check_id" "$title"
  fi
}
############################## C-2.1.2 (MANUAL) ############################
check_2_1_2() {
  local check_id="2.1.2"
  local title="Audit App Store Password Settings"
  local users=$(dscl . -list /Users | grep -vE '^_|daemon|nobody')
  local check_failed=false

  for user in $users; do
    local free_downloads=$(sudo -u $user defaults read com.apple.commerce.plist AutoDownload-AllowFree 2>/dev/null)
    local purchases=$(sudo -u $user defaults read com.apple.commerce.plist AutoDownload-AllowPurchases 2>/dev/null)

    if [ -z "$free_downloads" ] || [ -z "$purchases" ]; then
      check_failed=true
    else
      # Replace <FREE_DOWNLOADS_REQUIREMENT> and <PURCHASES_REQUIREMENT> with your organization's requirements (0 or 1)
      if [ "$free_downloads" -ne 1 ] || [ "$purchases" -ne 0 ]; then
        check_failed=true
      fi
    fi
  done

  if [ "$check_failed" = true ]; then
    fail "$check_id" "$title"
  else
    pass "$check_id" "$title"
  fi
}
############################## C-2.2.1 ############################
check_2_2_1() {
  local check_id="2.2.1"
  local title="Ensure Firewall Is Enabled"
  local check_command="sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate | grep 'Firewall is enabled.'"

  eval $check_command >/dev/null 2>&1
  local exit_status=$?

  if [ $exit_status -eq 0 ]; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-2.2.2 (MANUAL) ############################

check_2_2_2() {
  local check_id="2.2.2"
  local title="Ensure Firewall Stealth Mode Is Enabled"
  local check_command="sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode | grep 'Stealth mode enabled.'"

  eval $check_command >/dev/null 2>&1
  local exit_status=$?

  if [ $exit_status -eq 0 ]; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-2.3.1.1 ################################
check_2_3_1_1() {
  local check_id="2.3.1.1"
  local title="Ensure AirDrop Is Disabled"
  local users=$(dscl . -list /Users | grep -vE '^_|daemon|nobody')
  local check_failed=false

  for user in $users; do
    local airdrop_status=$(sudo -u $user defaults read com.apple.NetworkBrowser DisableAirDrop 2>/dev/null)

    if [ "$airdrop_status" != "1" ]; then
      check_failed=true
    fi
  done

  if [ "$check_failed" = true ]; then
    fail "$check_id" "$title"
  else
    pass "$check_id" "$title"
  fi
}
############################## C-2.3.1.2 ################################
check_2_3_1_2() {
  local check_id="2.3.1.2"
  local title="Ensure AirPlay Receiver Is Disabled"
  local check_command="sudo defaults read /Library/Preferences/com.apple.RemoteManagement.plist DisableAirPlayReceiver"

  local airplay_status=$(eval $check_command 2>/dev/null)

  if [ "$airplay_status" = "1" ]; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-2.3.2.1 ################################
check_2_3_2_1() {
  local check_id="2.3.2.1"
  local title="Ensure Set Time and Date Automatically Is Enabled"
  local check_command="sudo systemsetup -getusingnetworktime | grep 'Network Time: On'"

  eval $check_command >/dev/null 2>&1
  local exit_status=$?

  if [ $exit_status -eq 0 ]; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-2.3.2.2 ################################
check_2_3_2_2() {
  local check_id="2.3.2.2"
  local title="Ensure Time Is Set Within Appropriate Limits"
  local time_server=$(sudo systemsetup -getnetworktimeserver | awk -F': ' '{print $2}')
  local time_offset=$(sudo sntp "$time_server" 2>/dev/null | awk '{print $9}')
  local check_command="[ $time_offset ] && [ ${time_offset%.*} -ge -270 ] && [ ${time_offset%.*} -le 270 ]"

  eval $check_command
  local exit_status=$?

  if [ $exit_status -eq 0 ]; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-2.3.3.1 ################################
check_2_3_3_1() {
  local check_id="2.3.3.1"
  local title="Ensure DVD or CD Sharing Is Disabled"
  local check_command="sudo systemsetup -getsharing | grep -E 'Remote Disc: Off'"

  eval $check_command >/dev/null 2>&1
  local exit_status=$?

  if [ $exit_status -eq 0 ]; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-2.3.3.2 ################################
check_2_3_3_2() {
  local check_id="2.3.3.2"
  local title="Ensure Screen Sharing Is Disabled"
  local check_command="sudo launchctl list | grep -E 'com.apple.screensharing(-agent)?'"

  eval $check_command >/dev/null 2>&1
  local exit_status=$?

  if [ $exit_status -ne 0 ]; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-2.3.3.3 ################################
check_2_3_3_3() {
  local check_id="2.3.3.3"
  local title="Ensure File Sharing Is Disabled"
  local check_command="sudo launchctl list | grep -c 'com.apple.smbd'"

  if [[ $(eval $check_command) -eq 0 ]]; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-2.3.3.4 ################################
check_2_3_3_4() {
  local check_id="2.3.3.4"
  local title="Ensure Printer Sharing Is Disabled"
  local check_command="sudo cupsctl | grep -c '_share_printers=0'"

  if [[ $(eval $check_command) -gt 0 ]]; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-2.3.3.5 ################################
check_2_3_3_5() {
  local check_id="2.3.3.5"
  local title="Ensure Remote Login Is Disabled"
  local check_command="sudo systemsetup -getremotelogin | grep 'Remote Login: Off'"

  if eval $check_command >/dev/null 2>&1; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-2.3.3.6 ################################
check_2_3_3_6() {
  local check_id="2.3.3.6"
  local title="Ensure Remote Management Is Disabled"
  local check_command="sudo ps -ef | grep -v grep | grep -c 'ARDAgent'"

  if [[ $(eval $check_command) -eq 0 ]]; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-2.3.3.7 ################################
check_2_3_3_7() {
  local check_id="2.3.3.7"
  local title="Ensure Remote Apple Events Is Disabled"
  local check_command="sudo systemsetup -getremoteappleevents | grep 'Remote Apple Events: Off'"

  if eval $check_command >/dev/null 2>&1; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-2.3.3.8 ################################
check_2_3_3_8() {
  local check_id="2.3.3.8"
  local title="Ensure Internet Sharing Is Disabled"
  local check_command="sudo defaults read /Library/Preferences/SystemConfiguration/com.apple.nat 2>/dev/null | grep -c 'Enabled = 1;'"

  if [[ $(eval $check_command) -eq 0 ]]; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-2.3.3.9 ################################
check_2_3_3_9() {
  local check_id="2.3.3.9"
  local title="Ensure Content Caching Is Disabled"
  local check_command="sudo osascript -l JavaScript << EOS
  function run() {
    let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.AssetCache').objectForKey('Activated'))
    let pref2 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowContentCaching'))
    if ((pref1 == 0) || (pref2 == 0)) {
      return('true')
    } else {
      return('false')
    }
  }
  EOS"

  if [[ $(eval $check_command) == "true" ]]; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-2.3.3.10 ################################
check_2_3_3_10() {
  local check_id="2.3.3.10"
  local title="Ensure Media Sharing Is Disabled"
  local users=$(dscl . -list /Users | grep -vE '^_|daemon|nobody')
  local check_failed=false

  for user in $users; do
    local check_command="sudo -u $user defaults read com.apple.amp.mediasharingd home-sharing-enabled 2>/dev/null"
    if [[ $(eval $check_command) -ne 0 ]]; then
      check_failed=true
    fi
  done

  if [ "$check_failed" = true ]; then
    fail "$check_id" "$title"
  else
    pass "$check_id" "$title"
  fi
}
############################## C-2.3.3.11 ################################
check_2_3_3_11() {
  local check_id="2.3.3.11"
  local title="Ensure Bluetooth Sharing Is Disabled"
  local users=$(dscl . -list /Users | grep -vE '^_|daemon|nobody')
  local check_failed=false

  for user in $users; do
    local check_command="sudo -u $user defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled 2>/dev/null"
    if [[ $(eval $check_command) -ne 0 ]]; then
      check_failed=true
    fi
  done

  if [ "$check_failed" = true ]; then
    fail "$check_id" "$title"
  else
    pass "$check_id" "$title"
  fi
}
############################## C-2.3.3.12 ################################
## THIS CHECK IS MANUAL, PLEASE VERIFY

check_2_3_3_12() {
  local check_id="2.3.3.12"
  local title="Ensure Computer Name Does Not Contain PII or Protected Organizational Information"
  local computer_name="$(scutil --get ComputerName)"
  local users=$(dscl . -list /Users | grep -vE '^_|daemon|nobody')
  local check_failed=false

  for user in $users; do
    if [[ $computer_name == $user ]]; then
      check_failed=true
      break
    fi
  done

  if [ "$check_failed" = true ]; then
    fail "$check_id" "$title"
  else
    pass "$check_id" "$title"
  fi
}
############################## C-2.3.4.1 ################################
check_2_3_4_1() {
  local check_id="2.3.4.1"
  local title="Ensure Backup Automatically is Enabled If Time Machine Is Enabled"
  local check_command="sudo osascript -l JavaScript << EOS
  function run() {
    let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.TimeMachine')
      .objectForKey('AutoBackup'))
    if ( pref1 == null ) {
      return('Preference Not Set')
    } else if ( pref1 == 1 ) {
      return('true')
    } else {
      return('false')
    }
  }
  EOS"
  local result="$(eval $check_command)"

  if [[ "$result" == "Preference Not Set" ]] || [[ "$result" == "true" ]]; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-2.3.4.2 ################################
check_2_3_4_2() {
  local check_id="2.3.4.2"
  local title="Ensure Time Machine Volumes Are Encrypted If Time Machine Is Enabled"
  local check_command="sudo defaults read /Library/Preferences/com.apple.TimeMachine.plist | grep -c NotEncrypted"

  if eval $check_command >/dev/null 2>&1; then
    fail "$check_id" "$title"
  else
    pass "$check_id" "$title"
  fi
}
############################## C-2.4.1 ################################
check_2_4_1() {
  local check_id="2.4.1"
  local title="Ensure Show Wi-Fi status in Menu Bar Is Enabled"
  local users=$(dscl . list /Users | grep -vE "_|daemon|nobody|root|Guest|uucp")

  local failed=0
  for user in $users; do
    local check_command="sudo -u $user defaults -currentHost read com.apple.controlcenter.plist WiFi"
    if ! eval $check_command >/dev/null 2>&1; then
      failed=1
      break
    fi
  done

  if [[ $failed -eq 0 ]]; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-2.4.2 ################################
check_2_4_2() {
  local check_id="2.4.2"
  local title="Ensure Show Bluetooth Status in Menu Bar Is Enabled"
  local users=$(dscl . list /Users | grep -vE "_|daemon|nobody|root|Guest|uucp")

  local failed=0
  for user in $users; do
    local check_command="sudo -u $user defaults -currentHost read com.apple.controlcenter.plist Bluetooth"
    if ! eval $check_command >/dev/null 2>&1; then
      failed=1
      break
    fi
  done

  if [[ $failed -eq 0 ]]; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-2.5.1 ################################
check_2_5_1() {
  local check_id="2.5.1"
  local title="Audit Siri Settings (ensure disabled)"
  local users=$(dscl . list /Users | grep -vE "_|daemon|nobody|root|Guest|uucp")

  local failed=0
  for user in $users; do
    local check_command="sudo -u $user defaults read com.apple.assistant.support.plist 'Assistant Enabled'"
    if eval $check_command >/dev/null 2>&1; then
      failed=1
      break
    fi
  done

  if [[ $failed -eq 0 ]]; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}

############################## C-2.6.1.1 ################################
check_2_6_1_1() {
  local check_id="2.6.1.1"
  local title="Ensure Location Services Is Enabled"
  local check_command="sudo launchctl list | grep -c com.apple.locationd"

  local result="$(eval $check_command)"

  if [[ "$result" -eq 1 ]]; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-2.6.1.2 ################################
check_2_6_1_2() {
  local check_id="2.6.1.2"
  local title="Ensure Location Services Is in the Menu Bar"
  local check_command="sudo defaults read /Library/Preferences/com.apple.locationmenu.plist ShowSystemServices"

  if eval $check_command >/dev/null 2>&1; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-2.6.1.3 ################################
check_2_6_1_3() {
  local check_id="2.6.1.3"
  local title="Audit Location Services Access (no one should be allowed)"
  local check_command="sudo defaults read /var/db/locationd/clients.plist"

  local result="$(eval $check_command)"

  if [[ -z "$result" ]]; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-2.6.2 ################################
check_2_6_2() {
  local check_id="2.6.2"
  local title="Ensure Sending Diagnostic and Usage Data to Apple Is Disabled"
  local users=$(dscl . list /Users | grep -vE "_|daemon|nobody|root|Guest|uucp")
  local check_command1="sudo defaults read /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist AutoSubmit"
  local check_command2="sudo defaults read /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist ThirdPartyDataSubmit"
  local check_command3="sudo -u $users defaults read /Users/$users/Library/Preferences/com.apple.assistant.support 'Siri Data Sharing Opt-In Status'"

  if ! eval $check_command1 >/dev/null 2>&1 && ! eval $check_command2 >/dev/null 2>&1 && ! eval $check_command3 >/dev/null 2>&1; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-2.6.3 ################################
check_2_6_3() {
  local check_id="2.6.3"
  local title="Ensure Limit Ad Tracking Is Enabled"
  local users=$(dscl . list /Users | grep -vE "_|daemon|nobody|root|Guest|uucp")
  local check_command="sudo -u $users defaults read /Users/$users/Library/Preferences/com.apple.AdLib.plist allowApplePersonalizedAdvertising"

  if eval $check_command >/dev/null 2>&1; then
    fail "$check_id" "$title"
  else
    pass "$check_id" "$title"
  fi
}
############################## C-2.6.4 ################################
check_2_6_4() {
  local check_id="2.6.4"
  local title="Ensure Gatekeeper Is Enabled"
  local check_command="sudo /usr/sbin/spctl --status"

  if eval $check_command | grep -q 'assessments enabled'; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-2.6.5 ################################
check_2_6_5() {
  local check_id="2.6.5"
  local title="Ensure FileVault Is Enabled and cannot be disabled"
  local check_command1="sudo /usr/bin/fdesetup status"
  local check_command2="sudo /usr/bin/osascript -l JavaScript << EOS $.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\ .objectForKey('dontAllowFDEDisable').js EOS"

  if eval $check_command1 | grep -q 'FileVault is On' && eval $check_command2 | grep -q '1'; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-2.6.6 ################################
check_2_6_6() {
  local check_id="2.6.6"
  local title="Verify Lockdown Mode enabled"

  local users=$(dscl . list /Users | grep -v '^_')
  local lockdown_mode_enabled=true

  for user in $users; do
    local check_command="sudo -u $user defaults read .GlobalPreferences.plist LDMGlobalEnabled 2>/dev/null"
    local result=$(eval $check_command)

    if [ "$result" != "1" ]; then
      lockdown_mode_enabled=false
      break
    fi
  done

  if $lockdown_mode_enabled; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-2.6.7 ################################
check_2_6_7() {
  local check_id="2.6.7"
  local title="Ensure an Administrator Password Is Required to Access System-Wide Preferences"
  local check_command="sudo /usr/bin/security authorizationdb read system.preferences 2> /dev/null | grep -A1 shared | grep false"

  if eval $check_command >/dev/null 2>&1; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-2.7.1 ################################
check_2_7_1() {
  local check_id="2.7.1"
  local title="Ensure Screen Saver Corners Are Secure"

  for user in $(get_users); do
    for corner in tl bl tr br; do
      local check_command="sudo -u $user defaults read com.apple.dock wvous-${corner}-corner"
      if ! eval $check_command | grep -q '6'; then
        pass "$check_id" "$title"
      else
        fail "$check_id" "$title"
        break
      fi
    done
  done
}
############################## C-2.8.1 ################################
check_2_8_1() {
  local check_id="2.8.1"
  local title="Audit Universal Control Settings"

  for user in $(get_users); do
    local check_command1="sudo -u $user defaults -currentHost read com.apple.universalcontrol Disable"
    local check_command2="sudo -u $user defaults -currentHost read com.apple.universalcontrol DisableMagicEdges"

    if ! eval $check_command1 | grep -q '1' && ! eval $check_command2 | grep -q '1'; then
      pass "$check_id" "$title"
    else
      fail "$check_id" "$title"
    fi
  done
}
############################## C-2.9.1 ################################
check_2_9_1() {
  local check_id="2.9.1"
  local title="Ensure Power Nap Is Disabled for Intel Macs"
  local check_command="sudo /usr/bin/pmset -g custom | /usr/bin/grep -c 'powernap 1'"

  if eval $check_command | grep -q '0'; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-2.9.2 ################################
check_2_9_2() {
  local check_id="2.9.2"
  local title="Ensure Wake for Network Access Is Disabled"
  local check_command="sudo /usr/bin/pmset -g custom | /usr/bin/grep -e womp"

  if eval $check_command | grep -q 'womp\s*0'; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}
############################## C-2.9.3 ################################
check_2_9_3() {
  local check_id="2.9.3"
  local title="Ensure the OS is not Activate When Resuming from Sleep"
  local check_command_processor="/usr/sbin/sysctl -n machdep.cpu.brand_string"
  local processor_type=$(eval $check_command_processor)
  
  if echo "$processor_type" | grep -q "Intel"; then
    local check_command_hardware="sudo /usr/sbin/system_profiler SPHardwareDataType | /usr/bin/grep -e MacBook"
    if eval $check_command_hardware; then
      local check_command_standby="sudo /usr/bin/pmset -b -g | /usr/bin/grep -e standby"
      local check_command_destroyfvkey="sudo /usr/bin/pmset -b -g | /usr/bin/grep DestroyFVKeyOnStandby"
      local check_command_hibernatemode="sudo /usr/bin/pmset -b -g | /usr/bin/grep hibernatemode"

      if eval $check_command_standby | grep -q -e "standbydelaylow\s*\d{1,3}" -e "standbydelayhigh\s*\d{1,3}" -e "highstandbythreshold\s*90" \
      && eval $check_command_destroyfvkey | grep -q "DestroyFVKeyOnStandby 1" \
      && eval $check_command_hibernatemode | grep -q "hibernatemode 25"; then
        pass "$check_id" "$title"
      else
        fail "$check_id" "$title"
      fi
    fi
  elif echo "$processor_type" | grep -q "Apple"; then
    local check_command_hardware="sudo /usr/sbin/system_profiler SPHardwareDataType | /usr/bin/grep -e MacBook"
    if eval $check_command_hardware; then
      local check_command_standby="sudo /usr/bin/pmset -b -g | /usr/bin/grep -e standby"
      local check_command_destroyfvkey="sudo /usr/bin/pmset -b -g | /usr/bin/grep DestroyFVKeyOnStandby"
      local check_command_hibernatemode="sudo /usr/bin/pmset -b -g | /usr/bin/grep hibernatemode"

      if eval $check_command_standby | grep -q -e "standby\s*\d{1,3}" \
      && eval $check_command_destroyfvkey | grep -q "DestroyFVKeyOnStandby 1" \
      && eval $check_command_hibernatemode | grep -q "hibernatemode 25"; then
        pass "$check_id" "$title"
      else
        fail "$check_id" "$title"
      fi
    fi
  else
    echo "Unknown processor type. Skipping the check."
  fi
}
############################## C-2.10.1 ################################
check_2_10_1() {
  local check_id="2.10.1"
  local title="Ensure an Inactivity Interval of 20 Minutes Or Less for the Screen Saver Is Enabled"

  local users=$(dscl . list /Users | grep -v '^_')
  local inactivity_interval_ok=true

  for user in $users; do
    local check_command="sudo -u $user osascript -l JavaScript << EOS function run() { let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver').objectForKey('idleTime')) if ( pref1 <= 1200 ) { return('true') } else { return('false') } } EOS"

    if [ "$(eval $check_command)" != "true" ]; then
      inactivity_interval_ok=false
      break
    fi
  done

  if $inactivity_interval_ok; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}

############################## C-2.10.2 ################################
check_2_10_2() {
  local check_id="2.10.2"
  local title="Ensure a Password is Required to Wake the Computer From Sleep or Screen Saver Is Enabled"

  local check_command="sudo osascript -l JavaScript << EOS function run() { let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver').objectForKey('askForPassword')) let pref2 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver').objectForKey('askForPasswordDelay')) if ( pref1 == 1 && pref2 <= 5 ) { return('true') } else { return('false') } } EOS"

  if [ "$(eval $check_command)" == "true" ]; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}

############################## C-2.10.3 ################################
check_2_10_3() {
  local check_id="2.10.3"
  local title="Ensure a Custom Message for the Login Screen Is Enabled"

  local check_command="sudo osascript -l JavaScript << EOS $.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow').objectForKey('LoginwindowText').js EOS"

  if [ -n "$(eval $check_command)" ]; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}

############################## C-2.10.4 ################################
check_2_10_4() {
  local check_id="2.10.4"
  local title="Ensure Login Window Displays as Name and Password Is Enabled"

  local check_command="sudo osascript -l JavaScript << EOS $.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow').objectForKey('SHOWFULLNAME').js EOS"

  if [ "$(eval $check_command)" == "1" ]; then
    pass "$check_id" "$title"
  else
    fail "$check_id" "$title"
  fi
}

############################## C-2.10.5 ################################
check_2_10_5() {
  local check_id="2.10.5"
  local title="Ensure Show Password Hints Is Disabled"

  local check_command="sudo osascript -l JavaScript << EOS $.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow').objectForKey('RetriesUntilHint').js EOS"

    if [ "$(eval $check_command)" == "0" ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}
############################## C-2.11.1 ################################
check_2_11_1() {
    local check_id="2.11.1"
    local title="Ensure Users' Accounts Do Not Have a Password Hint"
    local hints_exist=false

    local user_hint_output=$(sudo dscl . -list /Users hint)
    while read -r line; do
        if [[ $line =~ [[:space:]] ]]; then
            hints_exist=true
            break
        fi
    done <<< "$user_hint_output"

    if [ "$hints_exist" = false ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}
############################## C-2.11.2 ################################
check_2_11_2() {
    local check_id="2.11.2"
    local title="Ensure Touch ID is enabled"

    local touch_id_output=$(sudo bioutil -r)
    local touch_id_unlock=$(echo "$touch_id_output" | grep "Touch ID for unlock:" | awk '{print $NF}')

    if [ "$touch_id_unlock" = "1" ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}
############################## C-2.12.1 ################################
check_2_12_1() {
    local check_id="2.12.1"
    local title="Ensure Guest Account Is Disabled"

    local guest_account_disabled=$(sudo defaults read com.apple.MCX DisableGuestAccount)
    local guest_enabled=$(sudo defaults read com.apple.loginwindow GuestEnabled)
    if [ "$guest_account_disabled" -eq 1 ] || [ "$guest_enabled" -eq 0 ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}
############################## C-2.12.2 ################################
check_2_12_2() {
    local check_id="2.12.2"
    local title="Ensure Guest Access to Shared Folders Is Disabled"

    local smb_guest_access_status=$(sudo sysadminctl -smbGuestAccess status)
    if [ "$smb_guest_access_status" = "smb guest access disabled" ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}
############################## C-2.12.3 ################################
check_2_12_3() {
    local check_id="2.12.3"
    local title="Ensure Automatic Login Is Disabled"

    local auto_login_disabled=$(sudo defaults read com.apple.loginwindow com.apple.login.mcx.DisableAutoLoginClient)
    local auto_login_user=$(sudo defaults read com.apple.loginwindow autoLoginUser 2>/dev/null)
    if [ "$auto_login_disabled" -eq 1 ] || [ -z "$auto_login_user" ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}
############################## C-2.14.1 ################################
check_2_14_1() {
    local check_id="2.14.1"
    local title="Audit Notification & Focus Settings: Ensure No Notifications Show on the Lock Screen"

    local users=$(dscl . -list /Users | grep -vE '^(daemon|nobody|root|_.*|com.apple.*)$')
    local failed_users=""

    for username in $users; do
        local user_id=$(id -u "$username")
        
        # Skip non-regular users
        if [ "$user_id" -lt 500 ]; then
            continue
        fi

        local show_on_lock_screen=$(sudo -u "$username" defaults read com.apple.notificationcenterui showInNotificationCenter 2>/dev/null)
        if [ "$show_on_lock_screen" -ne 0 ]; then
            failed_users+="$username "
        fi
    done

    if [ -z "$failed_users" ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title" "Users with notifications on lock screen: $failed_users"
    fi
}
############################## C-3.1 ################################
check_3_1() {
    local check_id="3.1"
    local title="Ensure Security Auditing Is Enabled"

    if sudo launchctl list | grep -qi auditd; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}
############################## C-3.2 ################################
check_3_2() {
    local check_id="3.2"
    local title="Ensure Security Auditing Flags For User-Attributable Events Are Configured Per Local Organizational Requirements"

    local required_flags="-fm ad -ex aa -fr lo -fw"
    local audit_flags=$(sudo grep -e "^flags:" /etc/security/audit_control | awk -F: '{print $2}')
    local missing_flags=""

    for flag in $required_flags; do
        if [[ ! $audit_flags =~ $flag ]]; then
            missing_flags+="$flag "
        fi
    done

    if [ -z "$missing_flags" ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title" "Missing flags: $missing_flags"
    fi
}
############################## C-3.3 ################################
check_3_3() {
    local check_id="3.3"
    local title="Ensure install.log Is Retained for 365 or More Days and No Maximum Size"

    local ttl=$(sudo grep -i ttl /etc/asl/com.apple.install | awk -F= '{print $2}')
    local all_max=$(sudo grep -i all_max= /etc/asl/com.apple.install)

    if [ "$ttl" -ge 365 ] && [ -z "$all_max" ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}
############################## C-3.4 ################################
check_3_4() {
    local check_id="3.4"
    local title="Ensure Security Auditing Retention Is Enabled"

    local expire_after=$(sudo grep -e "^expire-after" /etc/security/audit_control | awk -F: '{print $2}')

    if [[ $expire_after == *60d* ]] || [[ $expire_after == *5G* ]]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}
############################## C-3.5 ################################
check_3_5() {
    local check_id="3.5"
    local title="Ensure Access to Audit Records Is Controlled"

    local audit_dir=$(sudo grep '^dir' /etc/security/audit_control | awk -F: '{print $2}')
    local user_permissions=$(sudo ls -n "$audit_dir" | awk '{s+=$3} END {print s}')
    local group_permissions=$(sudo ls -n "$audit_dir" | awk '{s+=$4} END {print s}')
    local wrong_permissions_count=$(sudo ls -l "$audit_dir" | awk '!/-r--r-----|current|total/{print $1}' | wc -l | tr -d ' ')

    if [ "$user_permissions" -eq 0 ] && [ "$group_permissions" -eq 0 ] && [ "$wrong_permissions_count" -eq 0 ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}
############################## C-3.6 ################################
check_3_6() {
    local check_id="3.6"
    local title="Ensure Firewall Logging Is Enabled and Configured"

    local firewall_logging=$(sudo defaults read /Library/Preferences/com.apple.alf loggingenabled)
    local logging_option=$(sudo defaults read /Library/Preferences/com.apple.alf loggingoption)

    if [ "$firewall_logging" -eq 1 ] && [ "$logging_option" -eq 2 ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}

############################## C-3.7 ################################
check_3_7() {
    local check_id="3.7"
    local title="Audit Software Inventory"

    # You need to define a custom baseline or system-required software list for this check
    echo "Please define a custom baseline or system-required software list for this check."
}

############################## C-4.1 ################################
check_4_1() {
    local check_id="4.1"
    local title="Ensure Bonjour Advertising Services Is Disabled"

    local bonjour_setting=$(sudo defaults read /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements)

    if [ "$bonjour_setting" -eq 1 ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}

############################## C-4.2 ################################
check_4_2() {
    local check_id="4.2"
    local title="Ensure HTTP Server Is Disabled"

    local httpd_count=$(sudo launchctl list | grep -c "org.apache.httpd")

    if [ "$httpd_count" -eq 0 ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}

############################## C-4.3 ################################
check_4_3() {
    local check_id="4.3"
    local title="Ensure NFS Server Is Disabled"

    local nfsd_count=$(sudo launchctl list | grep -c com.apple.nfsd)

    if [ "$nfsd_count" -eq 0 ] && [ ! -f /etc/exports ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}

############################## C-5.1.1 ################################
check_5_1_1() {
    local check_id="5.1.1"
    local title="Ensure Home Folders Are Secure"

    local insecure_home_folders=$(sudo ls -l /Users/ | grep -v Shared | awk '!/drwx------|drwx--x--x/ {print $1}' | wc -l | tr -d ' ')

    if [ "$insecure_home_folders" -eq 0 ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}

############################## C-5.1.2 ################################
check_5_1_2() {
    local check_id="5.1.2"
    local title="Ensure System Integrity Protection Status (SIP) Is Enabled"

    local sip_status=$(sudo csrutil status | grep -c "enabled")

    if [ "$sip_status" -eq 1 ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}############################## C-5.1.3 ################################
check_5_1_3() {
    local check_id="5.1.3"
    local title="Ensure Apple Mobile File Integrity (AMFI) Is Enabled"

    local amfi_setting=$(sudo nvram -p | grep -c "amfi_get_out_of_my_way=1")

    if [ "$amfi_setting" -eq 0 ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}

############################## C-5.1.4 ################################
check_5_1_4() {
    local check_id="5.1.4"
    local title="Ensure Sealed System Volume (SSV) Is Enabled"

    local ssv_status=$(sudo csrutil authenticated-root status | grep -c "enabled")

    if [ "$ssv_status" -eq 1 ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}

############################## C-5.1.5 ################################
check_5_1_5() {
    local check_id="5.1.5"
    local title="Ensure Appropriate Permissions Are Enabled for System Wide Applications"

    local insecure_apps=$(sudo find /Applications -iname "*.app" -type d -perm -2 -ls | wc -l | xargs)

    if [ "$insecure_apps" -eq 0 ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}

############################## C-5.1.6 ################################
check_5_1_6() {
    local check_id="5.1.6"
    local title="Ensure No World Writable Files Exist in the System Folder"

    local world_writable_files=$(sudo find /System/Volumes/Data/System -type d -perm -2 -ls | grep -v "Drop Box" | wc -l | xargs)

    if [ "$world_writable_files" -eq 0 ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}

############################## C-5.1.7 ################################
check_5_1_7() {
    local check_id="5.1.7"
    local title="Ensure No World Writable Files Exist in the Library Folder"

    local world_writable_dirs=$(sudo find /System/Volumes/Data/Library -type d -perm -2 -ls | grep -v Caches | grep -v /Preferences/Audio/Data | wc -l | xargs)

    if [ "$world_writable_dirs" -eq 0 ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}

############################## C-5.2.1 ################################
check_5_2_1() {
    local check_id="5.2.1"
    local title="Ensure Password Account Lockout Threshold Is Configured"

    local lockout_threshold=$(sudo pwpolicy -getaccountpolicies 2> /dev/null | tail +2 | xmllint --xpath '//dict/key[text()="policyAttributeMaximumFailedAuthentications"]/following-sibling::integer[1]/text()' -)

    if [ "$lockout_threshold" -le 5 ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}

############################## C-5.2.2 ################################
check_5_2_2() {
    local check_id="5.2.2"
    local title="Ensure Password Minimum Length Is Configured"

    local min_length=$(sudo pwpolicy -getaccountpolicies | grep -e "policyAttributePassword matches" | cut -b 46-53 | cut -d',' -f1 | cut -d'{' -f2)

    if [ "$min_length" -ge 15 ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}
############################## C-5.2.3 ################################
check_5_2_3() {
    local check_id="5.2.3"
    local title="Ensure Complex Password Must Contain Alphabetic Characters Is Configured"

    local output=$(sudo pwpolicy -getaccountpolicies | grep -e "Contain at least one number and one alphabetic character." | cut -b 13-68)
    local minimum_letters=$(sudo pwpolicy -getaccountpolicies | grep -A1 minimumLetters | tail -1 | cut -d'>' -f2 | cut -d '<' -f1)

    if [ "$output" = "Contain at least one number and one alphabetic character" ] || { [ -n "$minimum_letters" ] && [ "$minimum_letters" -ge 1 ]; }; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}

############################## C-5.2.4 ################################
check_5_2_4() {
    local check_id="5.2.4"
    local title="Ensure Complex Password Must Contain Numeric Character Is Configured"

    local output=$(sudo pwpolicy -getaccountpolicies | grep -e "Contain at least one number and one alphabetic character." | cut -b 13-68)
    local minimum_numeric_characters=$(sudo pwpolicy -getaccountpolicies | grep -A1 minimumNumericCharacters | tail -1 | cut -d'>' -f2 | cut -d '<' -f1)

    if [ "$output" = "Contain at least one number and one alphabetic character" ] || { [ -n "$minimum_numeric_characters" ] && [ "$minimum_numeric_characters" -ge 1 ]; }; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}

############################## C-5.2.5 ################################
check_5_2_5() {
    local check_id="5.2.5"
    local title="Ensure Complex Password Must Contain Special Character Is Configured"

    local output=$(sudo pwpolicy -getaccountpolicies | grep -e "policyAttributePassword matches '(.*[^a-zA-Z0-9].*){1,}'" | cut -b 12-67)
    local minimum_symbols=$(sudo pwpolicy -getaccountpolicies | grep -A1 minimumSymbols | tail -1 | cut -d'>' -f2 | cut -d '<' -f1)

    if [ "$output" = "policyAttributePassword matches '(.*[^a-zA-Z0-9].*){1,}'" ] || { [ -n "$minimum_symbols" ] && [ "$minimum_symbols" -ge 1 ]; }; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}

############################## C-5.2.6 ################################
check_5_2_6() {
    local check_id="5.2.6"
    local title="Ensure Complex Password Must Contain Uppercase and Lowercase Characters Is Configured"

    local minimum_mixed_case_characters=$(sudo pwpolicy -getaccountpolicies | grep -A1 minimumMixedCaseCharacters | tail -1 | cut -d'>' -f2 | cut -d '<' -f1)

    if [ -n "$minimum_mixed_case_characters" ] && [ "$minimum_mixed_case_characters" -ge 1 ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}

############################## C-5.2.7 ################################
check_5_2_7() {
    local check_id="5.2.7"
    local title="Ensure Password Age Is Configured"

    local expires_every_n_days=$(sudo pwpolicy -getaccountpolicies | grep -A1 policyAttributeExpiresEveryNDays | tail -1 | cut -d'>' -f2 | cut -d '<' -f1)
    local days_until_expiration=$(sudo pwpolicy -getaccountpolicies | grep -A1 policyAttributeDaysUntilExpiration | tail -1 | cut -d'>' -f2 | cut -d '<' -f1)

    if { [ -n "$expires_every_n_days" ] && [ "$expires_every_n_days" -le 365 ]; } || { [ -n "$days_until_expiration" ] && [ "$days_until_expiration" -le 365 ]; }; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}

############################## C-5.2.8 ################################
check_5_2_8() {
    local check_id="5.2.8"
    local title="Ensure Password History Is Configured"

    local password_history_depth=$(sudo pwpolicy -getaccountpolicies | grep -A1 policyAttributePasswordHistoryDepth | tail -1 | cut -d'>' -f2 | cut -d '<' -f1)

    if [ -n "$password_history_depth" ] && [ "$password_history_depth" -ge 15 ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}
############################## C-5.3.1 ################################
check_5_3_1() {
    local check_id="5.3.1"
    local title="Ensure all user storage APFS volumes are encrypted"

    local encrypted_volumes=$(sudo diskutil ap list | grep -c "FileVault: Yes")

    if [ "$encrypted_volumes" -gt 0 ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}

############################## C-5.3.2 ################################
check_5_3_2() {
    local check_id="5.3.2"
    local title="Ensure all user storage CoreStorage volumes are encrypted"

    local encrypted_corestorage_volumes=$(sudo diskutil cs list | grep -c "Encryption Status:       Unlocked")

    if [ "$encrypted_corestorage_volumes" -eq 0 ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}

############################## C-5.4 ################################
check_5_4() {
    local check_id="5.4"
    local title="Ensure the Sudo Timeout Period Is Set to Zero"

    local sudo_timeout=$(sudo sudo -V | grep -c "Authentication timestamp timeout: 0.0 minutes")
    local sudo_folder_owner_group=$(sudo stat /etc/sudoers.d | awk '{print $5, $6}')

    if [ "$sudo_timeout" -eq 1 ] && [ "$sudo_folder_owner_group" = "root wheel" ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}

############################## C-5.5 ################################
check_5_5() {
    local check_id="5.5"
    local title="Ensure a Separate Timestamp Is Enabled for Each User/tty Combo"

    local separate_timestamp=$(sudo sudo -V | grep -c "Type of authentication timestamp record: tty")

    if [ "$separate_timestamp" -eq 1 ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}

############################## C-5.6 ################################
check_5_6() {
    local check_id="5.6"
    local title="Ensure the 'root' Account Is Disabled"

    local root_account_status=$(sudo dscl . -read /Users/root AuthenticationAuthority)

    if [[ "$root_account_status" == *"Disabled"* ]]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}

############################## C-5.7 ################################
check_5_7() {
    local check_id="5.7"
    local title="Ensure an Administrator Account Cannot Login to Another User's Active and Locked Session"

    local admin_login=$(sudo security authorizationdb read system.login.screensaver 2>&1 | grep -c 'use-login-window-ui')

    if [ "$admin_login" -eq 1 ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}

############################## C-5.8 ################################
check_5_8() {
    local check_id="5.8"
    local title="Ensure a Login Window Banner Exists"

    local banner_exists=$(sudo ls /Library/Security/ | grep -c 'PolicyBanner')
    local banner_permissions=$(sudo stat -f %A /Library/Security/PolicyBanner.* 2>/dev/null | grep
    local banner_permissions=$(sudo stat -f %A /Library/Security/PolicyBanner.* 2>/dev/null | grep -E '^6[0-7][0-7][0-7]$' | wc -l)

    if [ "$banner_exists" -ge 1 ] && [ "$banner_permissions" -ge 1 ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}

############################## C-5.9 ################################
check_5_9() {
    local check_id="5.9"
    local title="Ensure Legacy EFI Is Valid and Updating"

    local processor=$(sudo sysctl -n machdep.cpu.brand_string)
    local t2_chip=$(sudo system_profiler SPiBridgeDataType | grep "T2")
    local efi_firmware=$(sudo /usr/libexec/firmwarecheckers/eficheck/eficheck --integrity-check | grep -c "Primary allowlist version match found")
    local efi_check_daemon=$(sudo launchctl list | grep -c com.apple.driver.eficheck)

    if [[ "$processor" == *"Apple"* ]] || [[ -n "$t2_chip" ]] || { [ "$efi_firmware" -eq 1 ] && [ "$efi_check_daemon" -eq 1 ]; }; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}

############################## C-5.10 ################################
check_5_10() {
    local check_id="5.10"
    local title="Ensure the Guest Home Folder Does Not Exist"

    local guest_home_folder=$(sudo ls /Users/ | grep -c Guest)

    if [ "$guest_home_folder" -eq 0 ]; then
        pass "$check_id" "$title"
    else
        fail "$check_id" "$title"
    fi
}
############################## C-6.1.1 ################################
check_6_1_1() {
    local check_id="6.1.1"
    local title="Ensure Show All Filename Extensions Setting is Enabled"
    local usernames=$(get_usernames)

    for username in $usernames; do
        local extensions_enabled=$(sudo -u "$username" defaults read "/Users/$username/Library/Preferences/.GlobalPreferences.plist" AppleShowAllExtensions 2>/dev/null)
        if [ "$extensions_enabled" == "1" ]; then
            pass "$check_id" "$title ($username)"
        else
            fail "$check_id" "$title ($username)"
        fi
    done
}

############################## C-6.2.1 ################################
check_6_2_1() {
    local check_id="6.2.1"
    local title="Ensure Protect Mail Activity in Mail Is Enabled"
    local usernames=$(get_usernames)

    for username in $usernames; do
        local user_home=$(eval echo ~$username)
        local db_path="${user_home}/Library/Containers/com.apple.mail/Data/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.ApplicationRecentDocuments/com.apple.mail.sfl2"
        local query="SELECT kMDItemDisplayName, kMDItemPath FROM sfl_list;"
        local result=$(sudo -u "$username" sqlite3 "$db_path" "$query" 2>/dev/null | grep -i "Mail Privacy Protection")

        if [[ -n "$result" ]]; then
            pass "$check_id" "$title ($username)"
        else
            fail "$check_id" "$title ($username)"
        fi
    done
}

############################## C-6.3.1 ################################
check_6_3_1() {
    local check_id="6.3.1"
    local title="Ensure Automatic Opening of Safe Files in Safari Is Disabled"
    local usernames=$(get_usernames)

    for username in $usernames; do
        local auto_open_safe_downloads=$(sudo -u "$username" defaults read "/Users/$username/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari" AutoOpenSafeDownloads 2>/dev/null)
        if [ "$auto_open_safe_downloads" == "0" ]; then
            pass "$check_id" "$title ($username)"
        else
            fail "$check_id" "$title ($username)"
        fi
    done
}

############################## C-6.3.2 ################################
check_6_3_2() {
    local check_id="6.3.2"
    local title="Audit History and Remove History Items"
    local usernames=$(get_usernames)

    for username in $usernames; do
        local history_age_limit=$(sudo -u "$username" defaults read "/Users/$username/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari" HistoryAgeInDaysLimit 2>/dev/null)
        if [ "$history_age_limit" == "14" ]; then
            pass "$check_id" "$title ($username)"
        else
            fail "$check_id" "$title ($username)"
        fi
    done
}

############################## C-6.3.3 ################################
check_6_3_3() {
    local check_id="6.3.3"
    local title="Ensure Warn When Visiting A Fraudulent Website in Safari Is Enabled"
    local usernames=$(get_usernames)

    for username in $usernames; do
        local warn_fraudulent_websites=$(sudo -u "$username" defaults read "/Users/$username/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari" WarnAboutFraudulentWebsites 2>/dev/null)
        if [ "$warn_fraudulent_websites" == "1" ]; then
            pass "$check_id" "$title ($username)"
        else
            fail "$check_id" "$title ($username)"
        fi
    done
}

############################## C-6.3.4 ################################
check_6_3_4() {
    local check_id="6.3.4"
    local title="Ensure Prevent Cross-site Tracking in Safari Is Enabled"
    local usernames=$(get_usernames)

    for username in $usernames; do
        local block_storage_policy=$(sudo -u "$username" defaults read "/Users/$username/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari" BlockStoragePolicy 2>/dev/null)
        local webkit_preferences_storage_blocking_policy=$(sudo -u "$username" defaults read "/Users/$username/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari" WebKitPreferences.storageBlockingPolicy 2>/dev/null)
        local webkit_storage_blocking_policy=$(sudo -u "$username" defaults read "/Users/$username/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari" WebKitStorageBlockingPolicy 2>/dev/null)

        if [ "$block_storage_policy" == "2" ] && [ "$webkit_preferences_storage_blocking_policy" == "1" ] && [ "$webkit_storage_blocking_policy" == "1" ]; then
            pass "$check_id" "$title ($username)"
        else
            fail "$check_id" "$title ($username)"
        fi
    done
}

############################## C-6.3.5 ################################
check_6_3_5() {
    local check_id="6.3.5"
    local title="Audit Hide IP Address in Safari Setting"
    local usernames=$(get_usernames)

    for username in $usernames; do
        local hide_ip_address=$(sudo -u "$username" defaults read "/Users/$username/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari" WBSPrivacyProxyAvailabilityTraffic 2>/dev/null)
        if [ "$hide_ip_address" == "3300" ]; then
            pass "$check_id" "$title ($username)"
        else
            fail "$check_id" "$title ($username)"
        fi
    done
}

############################## C-6.3.6 ################################
check_6_3_6() {
    local check_id="6.3.6"
    local title="Ensure Advertising Privacy Protection in Safari Is Enabled"
    local usernames=$(get_usernames)

    for username in $usernames; do
        local ad_privacy_protection=$(sudo -u "$username" defaults read "/Users/$username/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari" WebKitPreferences.privateClickMeasurementEnabled 2>/dev/null)
        if [ "$ad_privacy_protection" == "1" ]; then
            pass "$check_id" "$title ($username)"
        else
            fail "$check_id" "$title ($username)"
        fi
    done
}

############################## C-6.3.7 ################################
check_6_3_7() {
    local check_id="6.3.7"
    local title="Ensure Show Full Website Address in Safari Is Enabled"
    local usernames=$(get_usernames)

    for username in $usernames; do
        local show_full_url=$(sudo -u "$username" defaults read "/Users/$username/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari" ShowFullURLInSmartSearchField 2>/dev/null)
        if [ "$show_full_url" == "1" ]; then
            pass "$check_id" "$title ($username)"
        else
            fail "$check_id" "$title ($username)"
        fi
    done
}
############################## C-6.4.1 ################################
check_6_4_1() {
    local check_id="6.4.1"
    local title="Ensure Secure Keyboard Entry Terminal.app Is Enabled"
    local usernames=$(get_usernames)

    for username in $usernames; do
        local secure_keyboard_entry=$(sudo -u "$username" defaults read -app Terminal SecureKeyboardEntry 2>/dev/null)
        if [ "$secure_keyboard_entry" == "1" ]; then
            pass "$check_id" "$title ($username)"
        else
            fail "$check_id" "$title ($username)"
        fi
    done
}

###### RUN CHECKS ######
# List of check functions
CHECK_FUNCTIONS=(
  check_1_1
  check_1_2
  check_1_3
  check_1_4
  check_1_5
  check_1_6
  check_1_7
  check_2_1_1_1
  check_2_1_1_2
  check_2_1_1_3
  check_2_1_2
  check_2_2_1
  check_2_2_2
  check_2_3_1_1
  check_2_3_1_2
  check_2_3_2_1
  check_2_3_2_2
  check_2_3_3_1
  check_2_3_3_2

  # Add more check functions here
)

# Initialize variables to count Passed, Failed, and Not Applicable checks
PASSED=0
FAILED=0
NOT_APPLICABLE=0
SECONDS=0

tput sc
update_header
tput rc

# Run checks
for check_function in "${CHECK_FUNCTIONS[@]}"; do
  $check_function
  update_header
done

touch /tmp/check_cis_complete
echo "Complete"
clear

# Display "Completed" message and wait for user to press Ctrl-C
while true; do
  tput sc
  tput cup $(($(tput lines) - 1)) 0
  echo -ne "${CYAN}Completed. Press Ctrl-C to exit.${RESET}"
  sleep 0.5
  echo -ne "\033[2K"
  tput rc
  sleep 0.5
done