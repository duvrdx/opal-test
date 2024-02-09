package app.rbac

default allow := false

allow {
	input.user == "bob"
}

