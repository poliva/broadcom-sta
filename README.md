broadcom-sta
============

Sources for my customized broadcom-sta ubuntu package, supporting CFG80211.

For more information, read "[Why Broadcom 802.11 Linux STA driver sucks, and how to fix it](http://pof.eslack.org/2012/05/23/why-broadcom-80211-linux-sta-driver-sucks-and-how-to-fix-it/)".

Ubuntu packages are available in [poliva/pof ppa](https://launchpad.net/~poliva/+archive/pof):

     sudo add-apt-repository ppa:poliva/pof
     sudo apt-get update
     sudo apt-get install broadcom-sta-dkms
     
You might want to remove the old wl module first, if you have it installed:

     sudo apt-get purge bcmwl-kernel-source