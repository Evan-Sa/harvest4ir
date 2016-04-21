# Harvest4IR #
Harvest4IR is a useful batch script to collect data from Windows computers for live response.
This tool is for non commercial use only.

Please, if any other artefact seems to be really interesting for live forensic, let me know. I will add it in the script.
Before this, refere to the [TODO](https://code.google.com/p/harvest4ir/wiki/todo) section of the wiki.

## Collected data ##

_Note that, each launched commands are listed in the file "actions.log"._

The script is splitted in two categories:
  * Volatile data
  * Non volatile data

### Volatile data ###
Just after the folder's creation, the RAM is collected. This is to prevent the alteration of it.
Then, here are the collected data :
  * Process information
  * DLLs
  * Unsigned DLLs
  * Handles
  * Network information
  * Logged in information
  * Remote open files

### Non volatile datas ###
  * Collecting prefetch files
  * Listing of partitions
  * MFT files listing (FLS)
  * Densitycount of each partitions
  * md5sum of each files from densityscout
  * System hives collection
  * Users hives collections
  * Events collections
  * Autorun artefacts

## Compression ##

When processing is over, a RAR ciphered archive is created (with the .cab extension) with the password indicated in the script.

# Tools #

It is using a collection of opensource tools listed below.


**Sysinternal**

autorunsc.exe

handle.exe

psfile.exe

procdump.exe

pslist.exe

psloggedon.exe

tcpvcon.exe

Listdlls.exe


**Unix tools**

cut.exe

grep.exe

md5sum.exe

mkdir.exe


**Windows Built-in**

cmd32.exe

cmd64.exe

robocopy.exe

tasklist32.exe

tasklist64.exe

wmic32.exe

wmic64.exe


**Sleuthkit**

fls.exe


**Misc**

densityscout.exe

rawcopy32.exe

rawcopy64.exe

winpmem-1.4.1.zip



**rar**

Rar.exe