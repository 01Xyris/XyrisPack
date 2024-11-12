XyrisPack is a small proof-of-concept packer written in MASM 

![image](https://github.com/user-attachments/assets/05290976-0b22-4f07-babb-90ff1608f49f)

┌─────────────────────────────────┐
│ Builder Process                 │
├─────────────────────────────────┤
│ 1. Takes original payload       │
│ 2. Generates random section     │
│ 3. Creates random XOR key       │
│ 4. Encrypts payload             │
│ 5. Adds new section to stub     │
└─────────────────────────────────┘

┌─────────────────────────────────┐
│ Stub Execution Flow             │
├─────────────────────────────────┤
│ 1. Unhooks NTDLL                │
│ 2. Locates encrypted section    │
│ 3. Decrypts payload             │
│ 4. Performs process hollowing   │
└─────────────────────────────────┘
