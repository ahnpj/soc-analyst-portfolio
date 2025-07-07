# 🛡️ Playbook: Unauthorized USB Device Detection

## Overview  
Investigate alerts triggered by unknown USB devices connecting to endpoints.

## Detection  
- Endpoint security alerts (EDR logs)  
- Endpoint logs showing USB device connections  
- User reports or helpdesk tickets

## Response Steps  
1. **Verify device legitimacy**  
   - Identify device type and user  
2. **Check for policy violations**  
   - Review company USB use policies  
3. **Scan endpoint for malware**  
   - Run AV and EDR scans on affected device  
4. **Contain if suspicious**  
   - Disable USB port or block device via endpoint controls  
5. **Notify user and management**  
   - Educate about USB security risks  
6. **Document and report**  
   - Log incident and actions taken

## Tools & References  
- Endpoint logs (Windows Event ID 6416)  
- EDR solutions with device control  
- Company security policies  
