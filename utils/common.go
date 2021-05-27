package utils

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

func Check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func goDotEnvVar(key string) string {
	err := godotenv.Load(".env")
	Check(err)

	return os.Getenv(key)
}
