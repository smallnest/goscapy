package packet

// BindingRule defines how an upper protocol layer binds to a field on its lower layer.
// When UpperProto is stacked on top of LowerProto, LowerProto's FieldName is
// automatically set to FieldValue.
type BindingRule struct {
	UpperProto string
	LowerProto string
	FieldName  string
	FieldValue any
}

var bindingRules []BindingRule

// RegisterBinding registers a field binding between two adjacent protocol layers.
// When upper is stacked on lower, lower.FieldName is set to FieldValue.
func RegisterBinding(upper, lower, field string, value any) {
	bindingRules = append(bindingRules, BindingRule{
		UpperProto: upper,
		LowerProto: lower,
		FieldName:  field,
		FieldValue: value,
	})
}

// applyBindings applies registered binding rules for the given layer pair.
func applyBindings(lower, upper *Layer) {
	for _, rule := range bindingRules {
		if rule.UpperProto == upper.Proto() && rule.LowerProto == lower.Proto() {
			lower.Set(rule.FieldName, rule.FieldValue)
		}
	}
}
