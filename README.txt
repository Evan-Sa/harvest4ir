 _   _                           _     ___ ___________ 
| | | |                         | |   /   |_   _| ___ \
| |_| | __ _ _ ____   _____  ___| |_ / /| | | | | |_/ /
|  _  |/ _` | '__\ \ / / _ \/ __| __/ /_| | | | |    / 
| | | | (_| | |   \ V /  __/\__ \ |_\___  |_| |_| |\ \ 
\_| |_/\__,_|_|    \_/ \___||___/\__|   |_/\___/\_| \_|
                                                       
                                                       
Please note that it is not for a comercial use. 
________________________________________________________________________________________________________________________

IMPORTANT :
For a legacy compatibility, the lenght of the script file must have, at least 8 characters.

________________________________________________________________________________________________________________________
How it works...

Only embedded tools are used even cmd.exe. That to be sure of what tools are launched.

 - Put the varibale "%tools%" before each tool you wanted to launch. the variable contain : "your_tools_folder"/CMD%arch%.exe /C "your_tools_folder/"
 - When you add a new tool in the "tools" folder, you have to put the architecture 32 or 64 just before ".exe" with the variable %arch%.

Logging actions.

The %_line% variable store the command. It is used to pass a parameter to the function :log_actions
This function will log the command in actions.log and check if an error occurred and put it in errors.log
Each command need two more line (every time !!) first, store the command in the var _line and after the command launch, call the function log_actions

________________________________________________________________________________________________________________________

Juste after the case folder creation, the mem dump will process.
Not that, some AV detect winpmem as a malware. Be sure the client will allow this tool.

When the collect is over, a cyphered archive is created. The password is : harvester4ir
This archive is created with the extension .cab but it is a rar file.