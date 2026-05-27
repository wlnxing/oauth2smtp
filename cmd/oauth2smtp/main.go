package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"oauth2smtp/internal/config"
	"oauth2smtp/internal/oauthms"
	"oauth2smtp/internal/smtpserver"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return errors.New("missing command")
	}

	switch args[0] {
	case "serve":
		return runServe(args[1:])
	case "account":
		return runAccount(args[1:])
	case "help", "-h", "--help":
		printUsage()
		return nil
	case "version":
		fmt.Println(version)
		return nil
	default:
		printUsage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "config.yaml", "path to YAML config")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	cfg.ApplyDefaults()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger := log.New(os.Stdout, "", log.LstdFlags)
	server := smtpserver.New(*configPath, cfg, logger, &http.Client{Timeout: 30 * time.Second})
	return server.ListenAndServe(ctx)
}

func runAccount(args []string) error {
	if len(args) == 0 {
		printAccountUsage()
		return errors.New("missing account subcommand")
	}

	switch args[0] {
	case "add":
		return runAccountAdd(args[1:])
	case "auth":
		return runAccountAuth(args[1:])
	case "set-password":
		return runAccountSetPassword(args[1:])
	case "list":
		return runAccountList(args[1:])
	case "help", "-h", "--help":
		printAccountUsage()
		return nil
	default:
		printAccountUsage()
		return fmt.Errorf("unknown account subcommand %q", args[0])
	}
}

func runAccountAdd(args []string) error {
	fs := flag.NewFlagSet("account add", flag.ExitOnError)
	configPath := fs.String("config", "config.yaml", "path to YAML config")
	name := fs.String("name", "", "account name")
	smtpUser := fs.String("smtp-user", "", "SMTP login username")
	smtpPassword := fs.String("smtp-password", "", "SMTP login password")
	email := fs.String("email", "", "authorized mailbox address")
	allowedFrom := fs.String("allowed-from", "", "comma-separated allowed From addresses")
	aliasRoutes := fs.String("alias-route", "", "comma-separated alias routes, format from=graph_user")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" || *smtpUser == "" || *smtpPassword == "" {
		return errors.New("account add requires --name, --smtp-user and --smtp-password")
	}

	cfg, err := config.LoadOrDefault(*configPath)
	if err != nil {
		return err
	}
	cfg.ApplyDefaults()
	if cfg.FindAccountByName(*name) != nil {
		return fmt.Errorf("account %q already exists", *name)
	}
	if cfg.FindAccountBySMTPUsername(*smtpUser) != nil {
		return fmt.Errorf("smtp user %q already exists", *smtpUser)
	}

	mailbox := strings.TrimSpace(*email)
	if mailbox == "" {
		mailbox = strings.TrimSpace(*smtpUser)
	}
	froms := splitComma(*allowedFrom)
	if len(froms) == 0 && mailbox != "" {
		froms = []string{mailbox}
	}

	routes, err := parseAliasRoutes(*aliasRoutes)
	if err != nil {
		return err
	}

	cfg.Accounts = append(cfg.Accounts, config.Account{
		Name:         strings.TrimSpace(*name),
		SMTPUsername: strings.TrimSpace(*smtpUser),
		SMTPPassword: *smtpPassword,
		Email:        mailbox,
		AllowedFrom:  froms,
		AliasRoutes:  routes,
	})
	return config.Save(*configPath, cfg)
}

func runAccountAuth(args []string) error {
	fs := flag.NewFlagSet("account auth", flag.ExitOnError)
	configPath := fs.String("config", "config.yaml", "path to YAML config")
	name := fs.String("name", "", "account name")
	manual := fs.Bool("manual", false, "paste the full redirect URL manually instead of listening for callback")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("account auth requires --name")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	cfg.ApplyDefaults()
	acc := cfg.FindAccountByName(*name)
	if acc == nil {
		return fmt.Errorf("account %q not found", *name)
	}

	token, err := oauthms.AuthorizeInteractive(context.Background(), cfg.OAuth, *manual, os.Stdin, os.Stdout, &http.Client{Timeout: 30 * time.Second})
	if err != nil {
		return err
	}
	acc.Token = token
	return config.Save(*configPath, cfg)
}

func runAccountSetPassword(args []string) error {
	fs := flag.NewFlagSet("account set-password", flag.ExitOnError)
	configPath := fs.String("config", "config.yaml", "path to YAML config")
	name := fs.String("name", "", "account name")
	smtpPassword := fs.String("smtp-password", "", "new SMTP login password")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" || *smtpPassword == "" {
		return errors.New("account set-password requires --name and --smtp-password")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	acc := cfg.FindAccountByName(*name)
	if acc == nil {
		return fmt.Errorf("account %q not found", *name)
	}
	acc.SMTPPassword = *smtpPassword
	return config.Save(*configPath, cfg)
}

func runAccountList(args []string) error {
	fs := flag.NewFlagSet("account list", flag.ExitOnError)
	configPath := fs.String("config", "config.yaml", "path to YAML config")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	for _, acc := range cfg.Accounts {
		fmt.Printf("%s\tsmtp_user=%s\temail=%s\tallowed_from=%s\n", acc.Name, acc.SMTPUsername, acc.Email, strings.Join(acc.AllowedFrom, ","))
	}
	return nil
}

func splitComma(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseAliasRoutes(s string) ([]config.AliasRoute, error) {
	parts := splitComma(s)
	routes := make([]config.AliasRoute, 0, len(parts))
	for _, part := range parts {
		from, graphUser, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("invalid alias route %q, expected from=graph_user", part)
		}
		from = strings.TrimSpace(from)
		graphUser = strings.TrimSpace(graphUser)
		if from == "" || graphUser == "" {
			return nil, fmt.Errorf("invalid alias route %q, from and graph_user are required", part)
		}
		routes = append(routes, config.AliasRoute{From: from, GraphUser: graphUser})
	}
	return routes, nil
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage:
  oauth2smtp serve --config config.yaml
  oauth2smtp account <add|auth|set-password|list> [options]
  oauth2smtp version`)
}

func printAccountUsage() {
	fmt.Fprintln(os.Stderr, `Usage:
  oauth2smtp account add --config config.yaml --name NAME --smtp-user USER --smtp-password PASS [--email EMAIL] [--allowed-from a@b,c@d] [--alias-route alias@b=shared@b]
  oauth2smtp account auth --config config.yaml --name NAME [--manual]
  oauth2smtp account set-password --config config.yaml --name NAME --smtp-password PASS
  oauth2smtp account list --config config.yaml`)
}
