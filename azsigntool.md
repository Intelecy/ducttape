# azuresigntool.exe

> From version: `v2.0.17`

* `--azure-key-vault-url` [short: `-kvu`, required: yes]: A fully qualified URL of the key vault with
	the certificate that will be used for signing. An example value might be `https://my-vault.vault.azure.net`.

* `--azure-key-vault-client-id` [short: `-kvi`, required: possibly]: This is the client ID used to authenticate to
	Azure, which will be used to generate an access token. This parameter is not required if an access token is supplied
	directly with the `--azure-key-vault-accesstoken` option. If this parameter is supplied, `--azure-key-vault-client-secret`
	must be supplied as well.

* `--azure-key-vault-client-secret` [short: `-kvs`, required: possibly]: This is the client secret used to authenticate to
	Azure, which will be used to generate an access token. This parameter is not required if an access token is supplied
	directly with the `--azure-key-vault-accesstoken` option. If this parameter is supplied, `--azure-key-vault-client-id`
	must be supplied as well.

* `--azure-key-vault-certificate` [short: `-kvc`, required: yes]: The name of the certificate used to perform the signing
	operation.

* `--azure-key-vault-accesstoken` [short: `-kva`, required: possibly]: An access token used to authenticate to Azure. This
	can be used instead of the `--azure-key-vault-client-id` and `--azure-key-vault-client-secret` options. This is useful
	if AzureSignTool is being used as part of another program that is already authenticated and has an access token to
	Azure.

* `--description` [short: `-d`, required: no]: A description of the signed content. This parameter serves the same purpose
	as the `/d` option in the Windows SDK `signtool`. If this parameter is not supplied, the signature will not contain a
	description.

* `--description-url` [short: `-du`, required: no]: A URL with more information of the signed content. This parameter serves
	the same purpose as the `/du` option in the Windows SDK `signtool`. If this parameter is not supplied, the signature will
	not contain a URL description.

* `--timestamp-rfc3161` [short: `-tr`, required: no]: A URL to an RFC3161 compliant timestamping service. This parameter serves the
	same purpose as the `/tr` option in the Windows SDK `signtool`. This parameter should be used in favor of the `--timestamp` option.
	Using this parameter will allow using modern, RFC3161 timestamps which also support timestamp digest algorithms other than SHA1.

* `--timestamp-authenticode` [short: `-t`, required: no]: A URL to a legacy "Authenticode" timestamping service. This parameter serves the
	same purpose as the `/t` option in the Windows SDK `signtool`. Using a "Authenicode" timestamping service is deprecated.
	Instead, use the `--timestamp-rfc3161` option.

* `--timestamp-digest` [short: `-td`, required: no]: The name of the digest algorithm used for timestamping. This parameter is ignored
	unless the `--timestamp-rfc3161` parameter is also supplied. The default value is `sha256`. Possible values:
	* sha1
	* sha256
	* sha384
	* sha512

* `--file-digest` [short: `-fd`, required: no]: The name of the digest algorithm used for hashing the file being signed.  The default
 	value is `sha256`. Possible values:
	* sha1
	* sha256
	* sha384
	* sha512
	
* `--additional-certificates` [short: `-ac`, required: no]: A list of paths to additional certificates to aide in building a full chain
	for the signing certificate. Azure SignTool will build a chain, either as deep as it can or to a trusted root. This will also use
	the Windows certificate store, in addition to any certificates specified with this option. Specifying this option does not guarantee
	the inclusion of the certificate, only if it is part of the chain. To include multiple certificates, specify this option mulitple
	times, such as `-ac file1.cer -ac file2.cer`. The files specified must be public certificates only. They cannot be PFX, PKCS12 or
	PFX files.
	
* `--verbose` [short: `-v`, required: no]: Include additional output in the log. This parameter does not accept a value and cannot be
	combine with the `--quiet` option.

* `--quiet` [short: `-q`, required: no]: Do not print output to the log. This parameter does not accept a value and cannot be
	combine with the `--verbose` option. The exit code of the process can be used to determine success or failure of the sign operation.
	
* `--coninue-on-error` [short: `-coe`, required: no]: If multiple files to sign are specified, this flag will cause the signing process to
	move on to the next file when signing fails. This flag modifies the exit code of the program. See the Exit Codes section for more
	information.
	
* `--input-file-list` [short: `-ifl`, required: no]: Specifies a path to a text file which contains a list of files to sign, with one
	file per-line in the text file. If this parameter is specified, it is combined with files directly specified on the command line. The
	distinct result of the two options is signed.
	
### Advanced

* `--page-hashing` [short: `-ph`, required: no]: Causes the Authenticode signing process to generate hashes of pages for verifying when
	the application is paged in to memory. If this flag is omitted, the default configuration for the operating system will be used.
	This flag will not affect non-PE file formats.
	
* `---no-page-hashing` [short: `-nph`, required: no]: Causes the Authenticode signing process to exclude hashes of pages for verifying when
	the application is paged in to memory. If this flag is omitted, the default configuration for the operating system will be used.
	This flag will not affect non-PE file formats.
	
* `--max-degree-of-parallelism` [short: `-mdop`, required: no]: When signing multiple files, specifies the maximum number of concurrent
	operations. Setting this value does not guarentee that number of concurrent operations will be performed. If this value is unspecified,
	the system will use the default based on the number of available processor threads. Setting this value to "1" disable concurrent
	signing.