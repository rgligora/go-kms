package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Server struct {
		Port       int    `mapstructure:"port"`
		ServerCert string `mapstructure:"serverCert"`
		ServerKey  string `mapstructure:"serverKey"`
		CaCert     string `mapstructure:"caCert"`
	} `mapstructure:"server"`

	KMS struct {
		// Path to a file containing the master passphrase (0400 perms).
		// If empty, an interactive prompt will be used.
		PassphraseFile string `mapstructure:"master_passphrase_file"`
	} `mapstructure:"kms"`

	Database struct {
		DSN string `mapstructure:"dsn"`
	} `mapstructure:"database"`
}

func Load() (*Config, error) {
	env := os.Getenv("KMS_ENV")
	if env == "prod" {
		env = "prod"
	} else {
		env = "dev"
	}

	viper.SetConfigName(fmt.Sprintf("config.%s", env))
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	viper.AddConfigPath("/etc/go-kms/")

	// Allow override via ENV var KMS_MASTER_PASSPHRASE_FILE
	viper.SetEnvPrefix("KMS")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	
	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}
	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
