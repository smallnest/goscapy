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

// bindingRules maps upperProto → lowerProto → rules for O(1) lookup.
var bindingRules = make(map[string]map[string][]BindingRule)

// RegisterBinding registers a field binding between two adjacent protocol layers.
// When upper is stacked on lower, lower.FieldName is set to FieldValue.
func RegisterBinding(upper, lower, field string, value any) {
	if bindingRules[upper] == nil {
		bindingRules[upper] = make(map[string][]BindingRule)
	}
	bindingRules[upper][lower] = append(bindingRules[upper][lower], BindingRule{
		UpperProto: upper,
		LowerProto: lower,
		FieldName:  field,
		FieldValue: value,
	})
}

// applyBindings applies registered binding rules for the given layer pair.
func applyBindings(lower, upper *Layer) {
	upperMap, ok := bindingRules[upper.Proto()]
	if !ok {
		return
	}
	rules, ok := upperMap[lower.Proto()]
	if !ok {
		return
	}
	for _, rule := range rules {
		lower.Set(rule.FieldName, rule.FieldValue)
	}
}
