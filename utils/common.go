package utils

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
)

func Check(err error) {
	if err != nil {
		fmt.Println(err.Error())
		log.Fatal(err)
	}
}

func goDotEnvVar(key string) string {
	err := godotenv.Load(".env")
	Check(err)

	return os.Getenv(key)
}
