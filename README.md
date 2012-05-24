broadcom-sta
============

Sources for my customized broadcom-sta ubuntu package, supporting CFG80211.

Ubuntu packages are available in [poliva/pof ppa](https://launchpad.net/~poliva/+archive/pof):

     sudo add-apt-repository ppa:poliva/pof
     sudo apt-get update
     sudo apt-get install broadcom-sta-dkms
     
You might want to remove the old wl module first, if you have it installed:

     sudo apt-get purge bcmwl-kernel-source