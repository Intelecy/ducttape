//go:generate goversioninfo -64

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"

	"github.com/pkg/errors"
)

const (
	azSignToolExe = "azuresigntool.exe"
)

var (
	binName  = "notset" // set via Makefile
	zlog     *zap.SugaredLogger
	toCensor []string
)

func init() {
	cli.HelpFlag = &cli.BoolFlag{
		Aliases: []string{"h", "?"},
		Usage:   "show help",
	}
}

func main() {
	defer func() {
		if zlog != nil {
			_ = zlog.Sync()
		}
	}()

	if !strings.HasSuffix(os.Args[0], binName) {
		// wtf!? advanced installer invokes the signtool _without_ arg[0] set to the exe name. :rage:
		os.Args = append([]string{binName}, os.Args...)
	}

	args := normalizeArgs(os.Args)

	app := &cli.App{
		Name:  binName,
		Usage: "Tool to bridge Advanced Installer, SignTool.exe and Azure Key Vault.",
		Authors: []*cli.Author{
			{
				Name:  "Jonathan Camp",
				Email: "jonathan.camp@intelecy.com",
			},
		},
		Copyright:       "Intelecy AS",
		HideHelpCommand: true,
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "verbose",
				Usage:   "Include additional output in the log.",
				Aliases: []string{"v"},
				Value:   true,
				EnvVars: []string{"DUCTTAPE_VERBOSE"},
			},
			&cli.PathFlag{
				Name:    "log-dir",
				Usage:   "Directory for log files",
				Value:   filepath.Join(os.TempDir(), "ducttape"),
				EnvVars: []string{"DUCTTAPE_LOG_DIR"},
			},
		},
		Before: func(c *cli.Context) error {
			addToCensor(os.Getenv("DUCTTAPE_SIGN_AZ_KEY_VAULT_CLIENT_SECRET"))
			addToCensor(os.Getenv("DUCTTAPE_SIGN_AZ_KEY_VAULT_ACCESS_TOKEN"))
			return nil
		},
		Commands: []*cli.Command{
			{
				Name:  "register",
				Usage: "Registers this executable with Advanced Installer as a SignTool.exe replacement.",
				Action: func(c *cli.Context) error {
					if err := initLogging(c); err != nil {
						return err
					}

					return registerAction(c)
				},
			},
			{
				Name:      "sign",
				Usage:     "Sign files using an embedded signature.",
				UsageText: fmt.Sprintf("%s sign [command options] <files_to_sign...>", binName),
				Before: func(c *cli.Context) error {
					addToCensor(c.String("kvs"))
					addToCensor(c.String("kva"))
					return nil
				},
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "a",
						Usage: "Select the best signing cert automatically. Note: ignored by this tool.",
					},
					&cli.StringFlag{
						Name:     "sha1",
						Usage:    "Specify the SHA1 thumbprint of the signing cert.",
						Required: false,
						EnvVars:  []string{"DUCTTAPE_SIGN_SHA1"},
					},
					&cli.StringFlag{
						Name:    "fd",
						Usage:   " Specifies the file digest algorithm to use for creating file signatures.",
						Value:   "SHA1",
						EnvVars: []string{"DUCTTAPE_SIGN_FILE_DIGEST"},
					},
					&cli.StringFlag{
						Name:    "s",
						Usage:   "Specify the Store to open when searching for the cert.",
						Value:   "MY",
						EnvVars: []string{"DUCTTAPE_SIGN_STORE"},
					},
					&cli.StringFlag{
						Name:    "d",
						Usage:   "Provide a description of the signed content.",
						EnvVars: []string{"DUCTTAPE_SIGN_DESCRIPTION"},
					},
					&cli.StringFlag{
						Name:    "du",
						Usage:   "A URL with more information of the signed content. This parameter serves the same purpose as the '/du' option in the Windows SDK 'signtool'. If this parameter is not supplied, the signature will not contain a URL description.",
						EnvVars: []string{"DUCTTAPE_SIGN_DESCRIPTION_URL"},
					},
					&cli.StringFlag{
						Name:    "t",
						Usage:   "Specify the timestamp server's URL. If this option is not present, the signed file will not be timestamped. A warning is generated if timestamping fails.",
						EnvVars: []string{"DUCTTAPE_SIGN_TIMESTAMP_URL"},
					},
					&cli.StringFlag{
						Name:    "tr",
						Usage:   "Specifies the RFC 3161 timestamp server's URL. If this option (or /t) is not specified, the signed file will not be timestamped. A warning is generated if timestamping fails. This switch cannot be used with the /t switch",
						EnvVars: []string{"DUCTTAPE_SIGN_TIMESTAMP_URL_RFC3161"},
					},
					&cli.StringFlag{
						Name:    "td",
						Usage:   "Used with the /tr or /tseal switch to request a digest algorithm used by the RFC 3161 timestamp server.",
						EnvVars: []string{"DUCTTAPE_SIGN_TIMESTAMP_DIGEST_ALGO"},
					},
					buildAZToolPathFlag(),
					&cli.StringFlag{
						Name:     "azure-key-vault-url",
						Aliases:  []string{"kvu"},
						Required: true,
						Usage:    "A fully qualified URL of the key vault with the certificate that will be used for signing. An example value might be https://my-vault.vault.azure.net.",
						EnvVars:  []string{"DUCTTAPE_SIGN_AZ_KEY_VAULT_URL"},
					},
					&cli.StringFlag{
						Name:     "azure-key-vault-client-id",
						Aliases:  []string{"kvi"},
						Required: false,
						Usage:    "This is the client ID used to authenticate to Azure, which will be used to generate an access token. This parameter is not required if an access token is supplied directly with the '--azure-key-vault-accesstoken' option. If this parameter is supplied, '--azure-key-vault-client-secret' must be supplied as well.",
						EnvVars:  []string{"DUCTTAPE_SIGN_AZ_KEY_VAULT_CLIENT_ID"},
					},
					&cli.StringFlag{
						Name:     "azure-key-vault-client-secret",
						Aliases:  []string{"kvs"},
						Required: false,
						Usage:    "This is the client secret used to authenticate to Azure, which will be used to generate an access token. This parameter is not required if an access token is supplied directly with the '--azure-key-vault-accesstoken' option. If this parameter is supplied, '--azure-key-vault-client-id' must be supplied as well.",
						EnvVars:  []string{"DUCTTAPE_SIGN_AZ_KEY_VAULT_CLIENT_SECRET"},
					},
					&cli.StringFlag{
						Name:     "azure-key-vault-certificate",
						Aliases:  []string{"kvc"},
						Required: true,
						Usage:    "The name of the certificate used to perform the signing operation.",
						EnvVars:  []string{"DUCTTAPE_SIGN_AZ_KEY_VAULT_CERT"},
					},
					&cli.StringFlag{
						Name:     "azure-key-vault-accesstoken",
						Aliases:  []string{"kva"},
						Required: false,
						Usage:    "An access token used to authenticate to Azure. This can be used instead of the '--azure-key-vault-client-id' and '--azure-key-vault-client-secret' options. This is useful if AzureSignTool is being used as part of another program that is already authenticated and has an access token to Azure.",
						EnvVars:  []string{"DUCTTAPE_SIGN_AZ_KEY_VAULT_ACCESS_TOKEN"},
					},
				},
				Action: func(c *cli.Context) error {
					var err error

					if err = initLogging(c); err != nil {
						return err
					}

					st := c.Path("azure-sign-tool")
					if st == "" {
						return errors.Errorf("%s not found in $PATH. Download from https://github.com/vcsjones/AzureSignTool/releases.", azSignToolExe)
					}

					if !exeExists(st) && !fileExists(st) {
						return errors.Errorf("%s not found in $PATH. Download %s from https://github.com/vcsjones/AzureSignTool/releases.", st, azSignToolExe)
					}

					if c.NArg() == 0 {
						return errors.New("Must specify at least one file to sign.")
					}

					var stp string

					if fileExists(st) {
						if stp, err = filepath.Abs(st); err != nil {
							return err
						}
					} else {
						if stp, err = exec.LookPath(st); err != nil {
							return err
						}
					}

					logInfo("using signtool: %s", stp)

					ctx, cancel := context.WithTimeout(c.Context, time.Second*time.Duration(30*c.NArg()))
					defer cancel()

					args := []string{
						"sign",
						"-kvu", c.String("kvu"),
						"-kvc", c.String("kvc"),
					}

					if c.Bool("verbose") {
						args = append(args, "-v")
					}

					args = appendIfSet(c, args, "kvi")
					args = appendIfSet(c, args, "kva")
					args = appendIfSet(c, args, "kvs")
					args = appendIfSet(c, args, "d")

					if c.IsSet("tr") {
						args = appendIfSet(c, args, "tr")
					} else if c.IsSet("t") {
						args = appendIfSet(c, args, "t")
					}

					for n := 0; n < c.NArg(); n++ {
						args = append(args, c.Args().Get(n))
					}

					logDebug("signtool args: %+v", args)

					cmd := exec.CommandContext(ctx, stp, args...)

					output, err := cmd.CombinedOutput()
					if len(output) > 0 {
						logInfo("exec output:\n%s", string(output))
					}

					if err != nil {
						return err
					}

					return nil
				},
			},
		},
	}

	if err := app.Run(args); err != nil {
		logError("error: %+v", err)
		os.Exit(1)
	}
}

func appendIfSet(c *cli.Context, args []string, name string) []string {
	if c.IsSet(name) {
		return append(args, fmt.Sprintf("-%s", name), c.String(name))
	}
	return args
}

func addToCensor(s string) {
	if s != "" {
		toCensor = append(toCensor, s)
	}
}

func censor(format string, a ...interface{}) string {
	s := fmt.Sprintf(format, a...)

	for _, c := range toCensor {
		if c != "" {
			s = strings.ReplaceAll(s, c, "********")
		}
	}

	return s
}

func logInfo(format string, a ...interface{}) {
	if zlog != nil {
		zlog.Info(censor(format, a...))
	}
}

func logDebug(format string, a ...interface{}) {
	if zlog != nil {
		zlog.Debug(censor(format, a...))
	}
}

func logError(format string, a ...interface{}) {
	if zlog != nil {
		zlog.Error(censor(format, a...))
	} else {
		_, _ = fmt.Fprint(os.Stdout, censor(format, a...))
	}
}

func initLogging(c *cli.Context) error {
	var err error
	dir := c.Path("log-dir")
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	cfg := zap.NewDevelopmentConfig()

	if c.Bool("verbose") {
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	} else {
		cfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	fpath, err := normalizePath(filepath.Join(dir, fmt.Sprintf("ducttape-log-%d.txt", time.Now().UnixNano())))
	if err != nil {
		return err
	}

	cfg.OutputPaths = []string{"stdout", fpath}

	logger, err := cfg.Build()
	if err != nil {
		return err
	}

	zlog = logger.Sugar()

	logInfo("setting log output to: %+v", cfg.OutputPaths)

	logDebug("os.Args: %v", os.Args)

	for _, kv := range os.Environ() {
		logDebug("env: %s", kv)
	}

	return nil
}

func buildAZToolPathFlag() cli.Flag {
	f := &cli.PathFlag{
		Name:    "azure-sign-tool",
		Aliases: []string{"st"},
		Usage:   fmt.Sprintf("Path to %s.", azSignToolExe),
		EnvVars: []string{"DUCTTAPE_SIGN_AZ_SIGNTOOL"},
	}

	if path, err := exec.LookPath(azSignToolExe); err == nil {
		// set default value _iff_ the sign tool is found
		f.Value = path
	}

	return f
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func exeExists(filename string) bool {
	_, err := exec.LookPath(filename)
	return err == nil
}

func normalizeArgs(windows []string) []string {
	args := make([]string, len(windows))
	copy(args, windows)

	for i := range args {
		if args[i][0] == '/' {
			if len(args[i]) == 2 {
				args[i] = strings.Replace(args[i], "/", "-", 1)
			} else {
				args[i] = strings.Replace(args[i], "/", "--", 1)
			}
		}
	}

	return args
}
