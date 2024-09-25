package api

import "encoding/json"

func mapToJSONString(data map[string]interface{}) string {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return ""
	}
	return string(jsonBytes)
}
