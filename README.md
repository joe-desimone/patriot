# Patriot
Small research project for detecting various kinds of in-memory stealth techniques. 

For the v0.1 release, we detect [Ekko](https://github.com/Cracked5pider/Ekko) by searching memory for timers which point to NtContinue.

Future improvements should include optimizations to reduce scan time, enumerate thread pool timers, apc's, and check for things like RtlRestoreContext as well.

Hat tip to [Austin Hudson](https://twitter.com/ilove2pwn_) for his excellent [research](https://suspicious.actor/2022/05/05/mdsec-nighthawk-study.html) on the topic

![image](https://user-images.githubusercontent.com/56411054/174499879-ea784efa-ba08-454e-9028-3781547c32f5.png)

# Release
Download the [latest](https://github.com/joe-desimone/patriot/releases/tag/v0.1)
