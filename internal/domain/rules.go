package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"time"
)

func ActivatePlan(plan *RolloutPlan, now time.Time) error {
	if plan.State != PlanDraft {
		return InvalidState("plan can be activated only from draft", map[string]any{
			"plan_id": plan.ID,
			"state":   plan.State,
		})
	}
	if plan.LatestRevisionID == "" {
		return InvalidState("plan needs a zone revision before activation", map[string]any{
			"plan_id": plan.ID,
		})
	}
	plan.State = PlanActive
	plan.ActivatedAt = timePointer(now.UTC())
	return nil
}

func CompletePlan(plan *RolloutPlan, now time.Time) error {
	if plan.State != PlanActive {
		return InvalidState("plan can be completed only from active", map[string]any{
			"plan_id": plan.ID,
			"state":   plan.State,
		})
	}
	plan.State = PlanCompleted
	plan.CompletedAt = timePointer(now.UTC())
	return nil
}

func LeaseFingerprint(planID string, input LeaseInput) string {
	payload := fmt.Sprintf(
		"%s|%s|%s|%d|%d",
		planID,
		input.RequestKey,
		input.Region,
		input.LeaseSeconds,
		input.MaxNodes,
	)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func ProbeFingerprint(leaseID string, input ProbeInput) string {
	payload := fmt.Sprintf(
		"%s|%s|%t|%d|%d|%s",
		leaseID,
		input.RequestKey,
		input.Success,
		input.ObservedSerial,
		input.LatencyMS,
		input.ObservedAt.UTC().Format(time.RFC3339Nano),
	)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func BuildAssessment(
	id string,
	plan RolloutPlan,
	revision ZoneRevision,
	probes []Probe,
	now time.Time,
) RolloutAssessment {
	reasons := make(map[string]struct{})
	if len(probes) == 0 {
		reasons["no_probes"] = struct{}{}
	}
	probeCount := len(probes)
	successCount := 0
	maximumLatency := 0
	nodes := make(map[string]struct{})
	for _, probe := range probes {
		nodes[probe.NodeID] = struct{}{}
		if probe.LatencyMS > maximumLatency {
			maximumLatency = probe.LatencyMS
		}
		if probe.Success {
			successCount++
			if probe.ObservedSerial != revision.Serial {
				reasons["serial_mismatch"] = struct{}{}
			}
		}
	}
	if len(nodes) < plan.ExpectedNodes {
		reasons["node_not_observed"] = struct{}{}
	}
	successRatio := 0.0
	if probeCount > 0 {
		successRatio = round(float64(successCount)/float64(probeCount), 6)
	}
	if successRatio < plan.MinimumSuccessRatio {
		reasons["success_ratio_below_minimum"] = struct{}{}
	}
	if maximumLatency > plan.MaximumLatencyMS {
		reasons["latency_limit_exceeded"] = struct{}{}
	}
	reasonList := make([]string, 0, len(reasons))
	for reason := range reasons {
		reasonList = append(reasonList, reason)
	}
	sort.Strings(reasonList)
	verdict := VerdictConsistent
	if len(reasonList) > 0 {
		verdict = VerdictReviewRequired
	}
	return RolloutAssessment{
		ID:               id,
		PlanID:           plan.ID,
		RevisionID:       revision.ID,
		Verdict:          verdict,
		Reasons:          reasonList,
		ProbeCount:       probeCount,
		SuccessCount:     successCount,
		SuccessRatio:     successRatio,
		MaximumLatencyMS: maximumLatency,
		CreatedAt:        now.UTC(),
	}
}

func round(value float64, places int) float64 {
	scale := math.Pow10(places)
	return math.Round(value*scale) / scale
}

// PlanFenceFor reports the durable fence that guards a plan aggregate.
func PlanFenceFor(state *State, planID string) uint64 {
	if state == nil {
		return 0
	}
	return state.PlanFences[planID]
}

// AdvancePlanFence records that a plan aggregate changed at the given store
// revision so later submissions can be fenced against that revision.
func AdvancePlanFence(state *State, planID string, revision uint64) {
	if state.PlanFences == nil {
		state.PlanFences = make(map[string]uint64)
	}
	if revision > state.PlanFences[planID] {
		state.PlanFences[planID] = revision
	}
}

// ObservePlanFences keeps every plan fence aligned with the latest durable
// revision so a version read from plan detail always matches the fence used by
// the next write precondition.
func ObservePlanFences(state *State) {
	if state.PlanFences == nil {
		state.PlanFences = make(map[string]uint64)
	}
	for planID := range state.Plans {
		state.PlanFences[planID] = state.Revision
	}
}

// RebuildPlanFences reconstructs every plan fence from the persisted plan
// history whenever a snapshot is loaded.
func RebuildPlanFences(state *State) {
	fences := make(map[string]uint64, len(state.Plans))
	for planID := range state.Plans {
		fences[planID] = 1
	}
	for _, revision := range state.Revisions {
		if _, ok := fences[revision.PlanID]; ok {
			fences[revision.PlanID]++
		}
	}
	for _, assessment := range state.Assessments {
		if _, ok := fences[assessment.PlanID]; ok {
			fences[assessment.PlanID]++
		}
	}
	state.PlanFences = fences
}

// PlanVersion projects the durable fence into a plan aggregate for responses.
func PlanVersion(state *State, plan RolloutPlan) RolloutPlan {
	plan.Version = PlanFenceFor(state, plan.ID)
	return plan
}

// PlanVersionMatches reports whether a submission carries the current fence.
func PlanVersionMatches(state *State, planID string, expected uint64) bool {
	return expected != 0 && PlanFenceFor(state, planID) == expected
}

func timePointer(value time.Time) *time.Time {
	return &value
}
