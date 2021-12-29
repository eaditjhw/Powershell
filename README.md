# Powershell
A collection of my useful Windows Powershell Scripts

FriendlyCertRename.ps - contains the code - takes no aruments and updates all certificates in Cert:\LocalMachine\my where FriendlyName is NULL with CN-TemplateName
 The effective user needs to have Update writes to the Certificate Store - will report an error in updating the file if this is detected                 
