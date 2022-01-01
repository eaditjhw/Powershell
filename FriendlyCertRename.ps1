Param(
    [Switch]$Force = $false
    )
#
# So this is where the Magic happens - Taking the certificate object and updatinbg the Friendly Name
# 
function Update-FriendlyName {
 [CmdletBinding()]
 [OutputType([bool])]
 param(
	[Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
	[Security.Cryptography.X509Certificates.X509Certificate2]$cert
 )
	# Transform the certificate object to expose extended properties including the Template name (if it exists; non MS PKI certs wont have one)
	if (($cert | Transform-Certificate) -eq 1) {
		Write-Host "WARN : We did not manage to extract the extended properties for certificate:" $cert.Thumbprint
		Return $False
	}
	else {
		# Create the Friendly Name for the certificate using the Common Name and Template name joined by a '-'
		$cert.FriendlyName=-join(($cert.Subject -replace "(CN=)(.*?)",'$2'),"-",($cert.Template -replace "(?ms)(Template=)(.*)\((.*$)",'$2'))
		Return $True
	} 
}
#
# Transform_Certificate (credit Vadims Podans of PKI Solutions Inc)
# Takes certificate data from Get-ChildItem and expands the extended properties to obtain the Template that was used to create the certificate request (if it exists - MS PKI certs only)
# Returns the object with properties populated - for full list of properties see X509Certificate2.Properties file
#
function Transform-Certificate {
 [CmdletBinding()]
 param(
	[Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
	[Security.Cryptography.X509Certificates.X509Certificate2]$cert
 )
	process {
		$temp = $cert.Extensions | ?{$_.Oid.Value -eq "1.3.6.1.4.1.311.20.2"}
 		if (!$temp) {
			$temp = $cert.Extensions | ?{$_.Oid.Value -eq "1.3.6.1.4.1.311.21.7"}
 		}
		if ($temp) {
        		$cert | Add-Member -Name Template -MemberType NoteProperty -Value $temp.Format(1) -PassThru
		}
		else {
			return 1
		}
 	}
}
#
# Nifty little test to check if we are in an elevated shell
# Returns true if we are, false if we aren't
#
function Test-Administrator  
{  
    [OutputType([bool])]
    param()
    process {
        [Security.Principal.WindowsPrincipal]$user = [Security.Principal.WindowsIdentity]::GetCurrent();
        return $user.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator);
    }
}

#
# Must be executed in elevated shell - exit if we are not
#
if(-not (Test-Administrator)) {
	Write-Error "FATAL: This script must be executed as with ELEVATED PRIVILEDGES.";
	exit 1;
}
#
# Get all certs with a blank Friendly Name and populate it with a concatenation of CN and Cert Template 
#
if ($Force.ispresent) {
	Write-Host "INFO : Force Mode"
}
else {
	$wshell = New-Object -ComObject Wscript.Shell
	$answer = $wshell.Popup("About to update Friendly Name for all Certificates in Machine Store. Do you want to continue?",0,"Alert",64+4)
	if($answer -eq 7) {exit 0}
}
Get-ChildItem Cert:\LocalMachine\my | where FriendlyName -eq "" | ForEach-Object {
	$Thumbprint=$_.Thumbprint
	Write-Host "INFO : Updating Friendly Name for the following certificate:" $Thumbprint
	If (Update-FriendlyName($_)) {
		Write-Host "INFO : Success! Here's the new Friendly Name: " $_.FriendlyName.Trim()
	}
	else {
		Write-Host "WARN : Did not update this certificate: $Thumbprint"
	}
}
exit 0
