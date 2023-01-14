package polai

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func containsEntity(list []Entity, id string) bool {
	for _, v := range list {
		if v.Identifier == id {
			return true
		}
	}

	return false
}
