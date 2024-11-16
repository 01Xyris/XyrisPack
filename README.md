XyrisPack is a small proof-of-concept packer written in MASM 

![image](https://github.com/user-attachments/assets/e8fc2db7-f7bc-46e8-9eb7-3ab6994f4104)


WaterEffect: [https://github.com/Xyl2k/MASM32-graphical-effects](https://github.com/Xyl2k/MASM32-graphical-effects/tree/master/WaveASM%20WaterEffect%20by%20LuoYunBin%20recode%20by%20Xylitol)
```
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
```
