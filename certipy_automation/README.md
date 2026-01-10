## Password Authentication Example
Do NOT need --target flag (only used with Kerberos authentication)
<br>
<img width="791" height="103" alt="image" src="https://github.com/user-attachments/assets/104c8f6b-e6ac-4439-98b6-1c443331f451" />
<br><br><br>
python3 certipy_automation.py \                                                                                                                                                         
  -u \<user\> \                                                                                                                                                                          
  -p \<pass\> -d \<DOMAIN\> \                                                                                                                                                         
  --dc-ip \<IP\>
  
<img width="1557" height="339" alt="image" src="https://github.com/user-attachments/assets/91541a28-a4f9-44ff-9699-7307ea6ffdaf" />
<br>
Certipy Output Part 1:
<img width="912" height="364" alt="image" src="https://github.com/user-attachments/assets/2a01d407-c1d4-4a9e-aa41-598db79a3c8e" />

<br>
Certipy Output Part 2:
<img width="1363" height="343" alt="image" src="https://github.com/user-attachments/assets/d20556cd-fd16-4200-9f5a-e6618483c76c" />

<br>
INSERT JSON PARSE OUTPUT


<br><br><br>
## Kerberos Authentication Example
Do NEED --target flag
<br>
<img width="791" height="103" alt="image" src="https://github.com/user-attachments/assets/104c8f6b-e6ac-4439-98b6-1c443331f451" />

<br><br><br>
python3 certipy_automation.py \                                             
  -u \<user\> \
  -k -d \<DOMAIN\> \
  --dc-ip \<IP\> --target <target> // EXAMPLE: dc01.certified.htb
  
<img width="1786" height="343" alt="image" src="https://github.com/user-attachments/assets/7592c563-ebae-443d-a06b-f4a58d76c399" />

<br>
Certipy Output Part 1:
<img width="912" height="364" alt="image" src="https://github.com/user-attachments/assets/fa0f5c54-033f-4717-9c57-46de83652e08" />

<br>
Certipy Output Part 2:
<img width="1397" height="322" alt="image" src="https://github.com/user-attachments/assets/434deb3c-1d48-4feb-b81f-663526b89246" />

<br>
INSERT JSON PARSE OUTPUT
