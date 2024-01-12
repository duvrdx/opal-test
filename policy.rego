package factor.sign_document

import future.keywords.if
import future.keywords.in

default can_read_document := false
default can_write_document := false

is_document(resource) if {
	resource.type == "document"
}

is_owner(user, resource) if {
	user in resource.owners
}

is_confidential(resource) if {
	resource.confidential
}

is_tenant(user, resource) if {
	user := data.user_attributes[input.user]
	resource := data.resource_attributes[input.resource]

	some user_tenant in user.tenants
	user_tenant in resource.tenants
}

can_read_document if {
	user := data.user_attributes[input.user]
	resource := data.resource_attributes[input.resource]

	is_tenant(user, resource)
	is_document(resource)

	not is_confidential(resource)
}

can_read_document if {
	is_tenant(user, resource)
	is_document(resource)
	is_owner(user, resource)
}

can_write_document if {
	is_tenant(user, resource)
	is_document(resource)
	is_owner(user, resource)
}
