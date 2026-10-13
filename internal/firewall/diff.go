package firewall

import "fmt"

func ruleKey(r Rule) string {
	return r.Table + "/" + r.Chain
}
func ruleSig(r Rule) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%v|%v|%s|%s|%d|%v|%s|%v", r.Action, r.Protocol, r.Source.Type, r.Source.Value, r.Destination.Type, r.Destination.Value, r.SourcePorts, r.DestPorts, r.InInterface, r.OutInterface, r.ToPort, r.States, r.Comment, r.Enabled)
}
func ruleLabel(r Rule) string {
	label := r.Table + "/" + r.Chain + " " + r.Action
	if r.Protocol != "" && r.Protocol != "all" {
		label += " " + r.Protocol
	}
	if r.Source.Value != "" {
		label += " src=" + r.Source.Value
	}
	if r.Destination.Value != "" {
		label += " dst=" + r.Destination.Value
	}
	if len(r.DestPorts) > 0 {
		label += fmt.Sprintf(" dport=%d", r.DestPorts[0].From)
	}
	if r.Comment != "" {
		label += " (" + r.Comment + ")"
	}
	return label
}
func DiffRulesets(live, draft *Ruleset) *DiffResult {
	res := &DiffResult{}
	for chain, policy := range draft.Policies {
		if live.Policies[chain] != policy {
			res.Entries = append(res.Entries, DiffEntry{Kind: "changed", Object: "policy:" + chain, Details: live.Policies[chain] + " -> " + policy})
		}
	}
	liveByKey := map[string][]Rule{}
	for _, r := range live.Rules {
		liveByKey[ruleKey(r)] = append(liveByKey[ruleKey(r)], r)
	}
	draftByKey := map[string][]Rule{}
	for _, r := range draft.Rules {
		draftByKey[ruleKey(r)] = append(draftByKey[ruleKey(r)], r)
	}
	for key, drules := range draftByKey {
		lrules := liveByKey[key]
		matched := make([]bool, len(lrules))
		for i, dr := range drules {
			found := -1
			for j, lr := range lrules {
				if !matched[j] && ruleSig(lr) == ruleSig(dr) {
					found = j
					break
				}
			}
			if found >= 0 {
				matched[found] = true
				if found != i {
					res.Entries = append(res.Entries, DiffEntry{Kind: "reordered", Object: key, Details: ruleLabel(dr)})
				}
			} else {
				res.Entries = append(res.Entries, DiffEntry{Kind: "added", Object: key, Details: ruleLabel(dr)})
			}
		}
		for j, lr := range lrules {
			if !matched[j] {
				res.Entries = append(res.Entries, DiffEntry{Kind: "removed", Object: key, Details: ruleLabel(lr)})
			}
		}
	}
	for key, lrules := range liveByKey {
		if _, ok := draftByKey[key]; !ok {
			for _, lr := range lrules {
				res.Entries = append(res.Entries, DiffEntry{Kind: "removed", Object: key, Details: ruleLabel(lr)})
			}
		}
	}
	res.Changed = len(res.Entries)
	return res
}
