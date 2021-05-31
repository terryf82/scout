package utils

import (
	"strings"

	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
)

var driver neo4j.Driver

func init() {
	var err error
	driver, err = neo4j.NewDriver(goDotEnvVar("NEO4J_SERVER_ADDRESS"), neo4j.BasicAuth(goDotEnvVar("NEO4J_USER"), goDotEnvVar("NEO4J_PASSWORD"), ""))
	Check(err)
}

func WriteQuery(db string, query []string, params map[string]interface{}) (result neo4j.Result, queryErr error) {

	session := driver.NewSession(neo4j.SessionConfig{
		AccessMode:   neo4j.AccessModeRead,
		DatabaseName: db,
	})

	defer session.Close()

	_, err := session.WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
		result, queryErr := tx.Run(
			strings.Join(query, " "),
			params)

		Check(queryErr)

		if result.Next() {
			return result.Record().Values[0], nil
		}

		return nil, result.Err()
	})

	Check(err)
	return
}

func ReadList(db string, query []string, params map[string]interface{}) (interface{}, error) {

	session := driver.NewSession(neo4j.SessionConfig{
		AccessMode:   neo4j.AccessModeRead,
		DatabaseName: db,
	})

	defer session.Close()

	list, err := session.ReadTransaction(func(tx neo4j.Transaction) (interface{}, error) {
		var rows []string

		result, err := tx.Run(strings.Join(query, " "), params)
		if err != nil {
			// Return no result & encountered error
			return nil, err
		}

		for result.Next() {
			rows = append(rows, result.Record().Values[0].(string))
		}

		// Guards against error encountered while iterating results?
		if err = result.Err(); err != nil {
			return nil, err
		}

		return rows, nil
	})

	if err != nil {
		return nil, err
	}

	return list, nil
}
