package configs

type ConfigDatabase struct {
	Port                string `yaml:"port" env:"PORT" env-default:"8080"`
	Host                string `yaml:"host" env:"HOST" env-default:"localhost"`
	DatabaseName        string `yaml:"dbname" env:"DBNAME" env-default:"goapi-auth"`
	UserCollection      string `yaml:"userCollection" env:"USERCLC" env-default:"users"`
	TokenCollection     string `yaml:"tokenCollection" env:"TOKENS" env-default:"tokens"`
	BlacklistCollection string `yaml:"blacklistCollection" env:"BLACKLISTCLC" env-default:"blacklisted-tokens"`
	JwtSecret           string `yaml:"jwtSecret" env:"JWTSECRET" env-default:"supersecretkey123"`
}

var Cfg ConfigDatabase
