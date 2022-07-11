# Patriot
![Patriot_missile_launch_b](https://user-images.githubusercontent.com/56411054/178175726-bc2c843c-103e-4366-8221-45d64a033e00.jpg)

Small research project for detecting various kinds of in-memory stealth techniques. 

Download the latest release [here](https://github.com/joe-desimone/patriot/releases/tag/v0.3).

The current version supports the following detections:
- Suspicious CONTEXT structures pointing to VirtualProtect functions. (Targets [research](https://suspicious.actor/2022/05/05/mdsec-nighthawk-study.html) by Austin Hudson [Foliage](https://github.com/y11en/FOLIAGE/tree/master/source) and [Ekko](https://github.com/Cracked5pider/Ekko) by Cracked5pider).
- Validation of MZ/PE headers in memory to detect process hollowing variants.
- Unbacked executable regions running at high integrity.
- Modified code used in module stomping/overwriting.
- Various other anomalies.

![image](https://user-images.githubusercontent.com/56411054/178175830-4289dd66-39d8-46c4-bd1d-f31f25baf8fa.png)

