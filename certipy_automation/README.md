# Testing
Tested thoroughly on HackTheBox machines Certified, Authority, and EscapeTwo. Worked without fail on all three.

# Password Authentication Example
Do NOT need --target flag (only used with Kerberos authentication)
<br><br>

### Command
python3 certipy_automation.py \                                                                                                                                                         
  -u \<user\> \                                                                                                                                                                         
  -p \<pass\> -d \<DOMAIN\> \                                                                                                                                                         
  --dc-ip \<IP\>
  
<img width="1724" height="433" alt="image" src="https://github.com/user-attachments/assets/7eb9dcc5-9eec-435c-b3af-011a3daf1b18" />


<br><br>
Certipy Output Part 1:
<img width="912" height="364" alt="image" src="https://github.com/user-attachments/assets/2a01d407-c1d4-4a9e-aa41-598db79a3c8e" />

<br><br>
Certipy Output Part 2:
<img width="1363" height="343" alt="image" src="https://github.com/user-attachments/assets/d20556cd-fd16-4200-9f5a-e6618483c76c" />

<br><br>
### Parsed Output (from JSON)
// from a different box when testing but output is the same across all
<img width="1002" height="227" alt="image" src="https://github.com/user-attachments/assets/92218c81-a7c3-46e6-8c92-b13c5344931a" />



<br><br><br>
# Kerberos Authentication Example
Do NEED --target flag

<br>

### Command:
python3 certipy_automation.py \                                                     
  -u \<user\> \
  -k -d \<DOMAIN\> \
  --dc-ip \<IP\> --target \<target\> # Example: dc01.certified.htb
  
<img width="1957" height="435" alt="image" src="https://github.com/user-attachments/assets/7196c5a0-f321-4a04-a42e-dfb382d8939c" />


<br><br>
Certipy Output Part 1:
<img width="912" height="364" alt="image" src="https://github.com/user-attachments/assets/fa0f5c54-033f-4717-9c57-46de83652e08" />

<br><br>
Certipy Output Part 2:
<img width="1397" height="322" alt="image" src="https://github.com/user-attachments/assets/434deb3c-1d48-4feb-b81f-663526b89246" />

<br><br>
### Parsed Output (from JSON)
// from a different box when testing but output is the same across all
<img width="1002" height="227" alt="image" src="https://github.com/user-attachments/assets/7a318223-8699-4fd8-b15c-3369ad4a77c3" />


