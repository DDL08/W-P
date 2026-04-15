
1.Manually controlled. Add a work order; the attachment upload function allows you to upload HTML pages containing XSS vulnerabilities, creating an XSS vulnerability. 👇

<img width="2171" height="948" alt="image" src="https://github.com/user-attachments/assets/be739649-11b6-4219-9f55-cef5c3983b5c" />

<img width="2551" height="1494" alt="image" src="https://github.com/user-attachments/assets/345dc3d1-456a-4ab2-a6fa-19d75e4c7a1c" />

<img width="1586" height="892" alt="image" src="https://github.com/user-attachments/assets/cdd65070-42cd-4a52-949c-1344b3ce6de2" />

<img width="2538" height="1064" alt="image" src="https://github.com/user-attachments/assets/3b34b55a-3931-4b8a-9e48-1ff626863f6b" />


2.

<img width="2560" height="1528" alt="image" src="https://github.com/user-attachments/assets/06e5510b-a1f8-46ac-b5c7-d731eebf5db3" />

<img width="2560" height="1528" alt="image" src="https://github.com/user-attachments/assets/e98f41a6-91e1-421f-89de-fc6dc4cd2652" />

Here, the SQL string in `next_node.handler` is replaced with a plain string before `cursor.execute(handler)` is called directly. No parameters are used.
The `handler` itself comes from a model field.



Triggering Conditions
It is called when the workflow starts:
workflow/views.py:80+

<img width="2560" height="1528" alt="image" src="https://github.com/user-attachments/assets/4400feca-e6e3-4dd2-bb32-d1b74db8770f" />


3.SECRET_KEY is hardcoded in the repository, leading to information leakage.👇

mis/settings.py:22
<img width="2388" height="1119" alt="image" src="https://github.com/user-attachments/assets/629911d5-8e1e-4cd5-b4f4-158c93d21556" />

mis/production.py:22
<img width="1762" height="948" alt="image" src="https://github.com/user-attachments/assets/615ff148-d953-4902-8301-f5049c93e2d5" />


4.Production database account passwords are written in plaintext in the repository.👇
mis/production.py:88-95
<img width="1675" height="1041" alt="image" src="https://github.com/user-attachments/assets/7c3a613a-e68c-4e71-acad-2479018ca3f4" />


5.Basic Data -> Workflow -> Add Project; The attachment upload function allows you to upload an HTML page containing an XSS vulnerability, thereby creating an XSS vulnerability. 👇

<img width="1586" height="892" alt="image" src="https://github.com/user-attachments/assets/57052e95-fefe-4f18-8fc0-cea015ea7aff" />

<img width="1586" height="892" alt="image" src="https://github.com/user-attachments/assets/4d83d87f-5272-4061-a045-6003ba9591c8" />

<img width="2550" height="1471" alt="image" src="https://github.com/user-attachments/assets/2f399fca-c146-4fc1-9552-254c3681574a" />

Technical/Drawings:
<img width="2124" height="1020" alt="image" src="https://github.com/user-attachments/assets/ab25c429-a5a7-4c59-9b61-4c79e0791f4d" />

Quotation:
<img width="2264" height="1050" alt="image" src="https://github.com/user-attachments/assets/76e48b1d-2ad4-4e8a-83f1-43f02d8343db" />

Business/Tender Documents:
<img width="2398" height="1077" alt="image" src="https://github.com/user-attachments/assets/420cd86e-4e52-40d4-b2e4-e5bcfa414b4a" />
