

1.The system has a hard-coded JWT key.👇

<img width="1620" height="997" alt="image" src="https://github.com/user-attachments/assets/c1dca6f0-68dd-49b8-b0e7-11cd3058beb4" />

2.The system contains hard-coded database usernames and passwords.👇

<img width="1701" height="997" alt="image" src="https://github.com/user-attachments/assets/bb347576-ff62-465a-879b-ccf6103df051" />


3.The system will use the phone number as the default password.👇

<img width="2159" height="1257" alt="image" src="https://github.com/user-attachments/assets/767a84a8-1c83-4753-b092-a76dfa71bfb5" />


4.The system has hard-coded administrator account passwords.👇

<img width="1891" height="1257" alt="image" src="https://github.com/user-attachments/assets/134dcbeb-3a10-4d5c-b243-513e64fc19a4" />


5.It's not HttpOnly, meaning that if an XSS vulnerability occurs on the front end, the token can be stolen directly. This can also trigger a CSRF vulnerability.👇

<img width="1964" height="1211" alt="image" src="https://github.com/user-attachments/assets/8be7fe21-17ed-4d5f-a9db-5aa41ea9562b" />
