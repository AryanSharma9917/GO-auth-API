package configs

type ConfigDatabase struct {
	Port                string `yaml:"port" env:"PORT" env-default:"1323"`
	Host                string `yaml:"host" env:"HOST" env-default:"localhost"`
	DatabaseName        string `yaml:"host" env:"DBNAME" env-default:"goapi-auth"`
	UserCollection      string `yaml:"host" env:"USERCLC" env-default:"users"`
	TokenCollection     string `yaml:"host" env:"TOKENS" env-default:"TOKENS"`
	BlacklistCollection string `yaml:"host" env:"BLACKLISTCLC" env-default:"blacklisted-tokens"`
	JwtSecret           string `yaml:"host" env:"JWTSECRET"  env-default:"aryansharma"`
}

var Cfg ConfigDatabase
