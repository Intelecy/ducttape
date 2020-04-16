# ducttape

This tool allows Advanced Installer to sign binaries using HSM protected keys from Azure Key Vault, all while running in
an Azure DevOps Pipeline.

Microsoft's `signtool.exe` only works with local, file-based keys, or certificates installed in the local key store. But
we need to use keys installed in Azure's Key Vault. If the keys are stored in an HSM-backed vault, then we can't export
the keys to the local system for use by `signtool.exe`. @vcsjones's
[AzureSignTool](https://github.com/vcsjones/AzureSignTool) is a sort of replacement for `signtool.exe` in that it uses
the Key Vault API to sign the hashes rather than a local certificate.

Advanced Installer allows you to configure an alternate to Microsoft's `signtool.exe`. Ideally we would simply replace
`signtool.exe` with `azsigntool.exe` and go on our merry way (as merry as one can be while doing Windows development),
but `azsigntool.exe` requires quite a few additional parameters. Since Advanced Installer's invocation of the sign tool
is limited to a few hardcoded parameters, there isn't an easy way tell `azsigntool.exe` how it should work.

`ducttape.exe` "bridges" the various bits in a "messy but it works" way. `ducttape.exe` reads CLI parameters from its
invocation by Advanced Installer, and adds in parameters read from environmental variables. Once it has all the required
parameters it invokes `azsigntool.exe`. It also logs everything to `$TEMP/ducttape/` to assist in debugging a
miss-configured pipeline. 

Licensed under MIT

https://intelecy.com

## Requirements

Windows 10 or Windows Server 2016+ is required.

## Limitations

Not all CLI argument combinations tested or supported.

## Example `pipeline.yml` fragment:

```yaml
variables:
  vm_image_windows: windows-2019
  adv_installer_version: "16.9"
  az_sign_tool_version: "2.0.17"
  ducttape_version: "v0.0.5"

stages:
  - stage: build
    jobs:
      - job: build_binaries
        steps:
          # build steps

      - job: build_windows_installer
        dependsOn: build_binaries
        pool:
          vmImage: $(vm_image_windows)
        steps:
          # fetch file from a previous job
          - task: DownloadPipelineArtifact@2
            inputs:
              patterns: "**/*.exe"
              path: installer
          
          # flatten and get into expected layout
          - task: CopyFiles@2
            inputs:
              sourceFolder: installer/binaries
              targetFolder: installer
              flattenFolders: true
              contents: "**/*.exe"

          # installer Advanced Installer
          - task: AdvancedInstallerTool@1
            inputs:
              advinstVersion: $(adv_installer_version)
              advinstLicense: $(adv_installer_license)
  
          # download azuresigntool and ducttape. register ducttape with Advanced Installer
          - powershell: |
              dotnet tool install --global AzureSignTool --version $(az_sign_tool_version)

              Invoke-WebRequest -UseBasicParsing -OutFile ducttape.exe -URI https://github.com/Intelecy/ducttape/releases/download/$(ducttape_version)/ducttape.exe

              .\ducttape.exe register
  
            displayName: Install signing tools
            env:
              DOTNET_SKIP_FIRST_TIME_EXPERIENCE: "true"

          # build our installer, signing binaries using the previously registered `ducttape.exe`
          - task: AdvancedInstaller@2
            inputs:
              aipPath: "installer/my-project.aip"
              aipOutputFolder: $(Build.ArtifactStagingDirectory)
              aipExtraCommands: |
                NewPathVariable -name SRC_DIR -value installer -valuetype Folder
                SetVersion "1.0.1337"
            env:
              DUCTTAPE_SIGN_DESCRIPTION_URL: https://example.com
              DUCTTAPE_SIGN_TIMESTAMP_URL_RFC3161: http://timestamp.globalsign.com/scripts/timestamp.dll
              DUCTTAPE_SIGN_AZ_KEY_VAULT_URL:  https://my-vault-name.vault.azure.net
              DUCTTAPE_SIGN_AZ_KEY_VAULT_CERT: my-cert-name
              DUCTTAPE_SIGN_AZ_KEY_VAULT_CLIENT_ID: 00000000-0000-0000-0000-000000000000
              DUCTTAPE_SIGN_AZ_KEY_VAULT_CLIENT_SECRET: "****"

          # export ducttape logs
          - task: PublishBuildArtifacts@1
            displayName: Export ducttape logs
            condition: succeededOrFailed()
            inputs:
              pathToPublish: $(TEMP)/ducttape
              artifactName: ducttape-logs

          # export our installer
          - task: PublishBuildArtifacts@1
            inputs:
              pathToPublish: $(Build.ArtifactStagingDirectory)
              artifactName: installer
```

## Example `project.aip` fragment

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<DOCUMENT Type="Advanced Installer" CreateVersion="16.9" version="16.9" Modules="professional" RootPath="." Language="en" Id="{00000000-0000-0000-0000-00000000000}">
    <COMPONENT cid="caphyon.advinst.msicomp.MsiFilesComponent">
        <ROW File="app.exe" Component_="app.exe" FileName="APP.EXE|app.exe" Attributes="0" SourcePath="&lt;SRC_DIR&gt;app.exe" SelfReg="false" DigSign="true"/>
        <ROW File="license.rtf" Component_="license.rtf" FileName="license.rtf" Attributes="0" SourcePath="&lt;SRC_DIR&gt;\resources\license.rtf" SelfReg="false"/>
        <ROW File="readme.rtf" Component_="readme.rtf" FileName="readme.rtf" Attributes="0" SourcePath="&lt;SRC_DIR&gt;\resources\readme.rtf" SelfReg="false"/>
    </COMPONENT>
    <COMPONENT cid="caphyon.advinst.msicomp.DigCertStoreComponent">
        <ROW TimeStampUrl="http://rfc3161timestamp.globalsign.com/advanced" SignerDescription="[|ProductName]" SignOptions="7" SignTool="0" UseSha256="1"/>
    </COMPONENT>
</DOCUMENT>
```

## Command line and environmental parameters

> note: forward slashes are also allowed for flags. i.e. `ducttape.exe /v sign /sha1 abc /d "my signed binary"` 

```
$ ducttape.exe /?
NAME:
   ducttape - Tool to bridge Advanced Installer, SignTool.exe and Azure Key Vault.

USAGE:
   ducttape [global options] command [command options] [arguments...]

AUTHOR:
   Jonathan Camp <jonathan.camp@intelecy.com>

COMMANDS:
   register  Registers this executable with Advanced Installer as a SignTool.exe replacement.
   sign      Sign files using an embedded signature.

GLOBAL OPTIONS:
   --verbose, -v    Include additional output in the log. (default: true) [$DUCTTAPE_VERBOSE]
   --log-dir value  Directory for log files (default: "/tmp/ducttape") [$DUCTTAPE_LOG_DIR]
   -h, -?           show help (default: false)

COPYRIGHT:
   Intelecy AS
```

```
$ ducttape.exe sign /?
NAME:
   ducttape sign - Sign files using an embedded signature.

USAGE:
   ducttape sign [command options] <files_to_sign...>

OPTIONS:
   -a                                                  Select the best signing cert automatically. Note: ignored by this tool. (default: false)
   --sha1 value                                        Specify the SHA1 thumbprint of the signing cert. [$DUCTTAPE_SIGN_SHA1]
   --fd value                                          Specifies the file digest algorithm to use for creating file signatures. (default: "SHA1") [$DUCTTAPE_SIGN_FILE_DIGEST]
   -s value                                            Specify the Store to open when searching for the cert. (default: "MY") [$DUCTTAPE_SIGN_STORE]
   -d value                                            Provide a description of the signed content. [$DUCTTAPE_SIGN_DESCRIPTION]
   --du value                                          A URL with more information of the signed content. This parameter serves the same purpose as the '/du' option in the Windows SDK 'signtool'. If this parameter is not supplied, the signature will not contain a URL description. [$DUCTTAPE_SIGN_DESCRIPTION_URL]
   -t value                                            Specify the timestamp server's URL. If this option is not present, the signed file will not be timestamped. A warning is generated if timestamping fails. [$DUCTTAPE_SIGN_TIMESTAMP_URL]
   --tr value                                          Specifies the RFC 3161 timestamp server's URL. If this option (or /t) is not specified, the signed file will not be timestamped. A warning is generated if timestamping fails. This switch cannot be used with the /t switch [$DUCTTAPE_SIGN_TIMESTAMP_URL_RFC3161]
   --td value                                          Used with the /tr or /tseal switch to request a digest algorithm used by the RFC 3161 timestamp server. [$DUCTTAPE_SIGN_TIMESTAMP_DIGEST_ALGO]
   --azure-sign-tool value, --st value                 Path to azuresigntool.exe. [$DUCTTAPE_SIGN_AZ_SIGNTOOL]
   --azure-key-vault-url value, --kvu value            A fully qualified URL of the key vault with the certificate that will be used for signing. An example value might be https://my-vault.vault.azure.net. [$DUCTTAPE_SIGN_AZ_KEY_VAULT_URL]
   --azure-key-vault-client-id value, --kvi value      This is the client ID used to authenticate to Azure, which will be used to generate an access token. This parameter is not required if an access token is supplied directly with the '--azure-key-vault-accesstoken' option. If this parameter is supplied, '--azure-key-vault-client-secret' must be supplied as well. [$DUCTTAPE_SIGN_AZ_KEY_VAULT_CLIENT_ID]
   --azure-key-vault-client-secret value, --kvs value  This is the client secret used to authenticate to Azure, which will be used to generate an access token. This parameter is not required if an access token is supplied directly with the '--azure-key-vault-accesstoken' option. If this parameter is supplied, '--azure-key-vault-client-id' must be supplied as well. [$DUCTTAPE_SIGN_AZ_KEY_VAULT_CLIENT_SECRET]
   --azure-key-vault-certificate value, --kvc value    The name of the certificate used to perform the signing operation. [$DUCTTAPE_SIGN_AZ_KEY_VAULT_CERT]
   --azure-key-vault-accesstoken value, --kva value    An access token used to authenticate to Azure. This can be used instead of the '--azure-key-vault-client-id' and '--azure-key-vault-client-secret' options. This is useful if AzureSignTool is being used as part of another program that is already authenticated and has an access token to Azure. [$DUCTTAPE_SIGN_AZ_KEY_VAULT_ACCESS_TOKEN]
   -h, -?                                              show help (default: false)

```