package factor.sign_document

import future.keywords.if
import future.keywords.in

default can_read_document := false

default can_write_document := false

is_document if {
	resource := data.resource_attributes[input.resource]
	resource.type == "document"
}

is_owner if {
	resource := data.resource_attributes[input.resource]
	input.user in resource.owners
}

is_confidential if {
	resource := data.resource_attributes[input.resource]
	resource.confidential
}

is_tenant if {
	user := data.user_attributes[input.user]
	resource := data.resource_attributes[input.resource]

	some user_tenant in user.tenants
	user_tenant in resource.tenants
}

can_read_document if {
	is_tenant
	is_document

	not is_confidential
}

can_read_document if {
	is_tenant
	is_document
	is_owner
}

can_write_document if {
	is_tenant
	is_document
	is_owner
}
