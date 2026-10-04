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

// PlanFenceFor reports the optimistic-concurrency version that guards a plan
// aggregate. A plan version is advanced solely by successful commits of that
// same plan aggregate; it is never tied to the global store revision, so writes
// to other entities or to other plans cannot move it.
func PlanFenceFor(state *State, planID string) uint64 {
	if state == nil {
		return 0
	}
	if plan, ok := state.Plans[planID]; ok {
		return plan.Version
	}
	return 0
}

// ObservePlanFences keeps the derived fence index aligned with the version
// carried by every plan aggregate. Only versions the plan itself already
// committed are reflected; the global store revision is intentionally not used
// here so unrelated writes cannot shift a plan's version.
func ObservePlanFences(state *State) {
	if state.PlanFences == nil {
		state.PlanFences = make(map[string]uint64)
	}
	for planID, plan := range state.Plans {
		state.PlanFences[planID] = plan.Version
	}
}

// RebuildPlanFences reconstructs each plan's version from that plan's own
// committed history whenever a snapshot is loaded. Counting the revision,
// activation, completion and assessment commits deterministically yields the
// same monotonic version the aggregate held before the restart, independent of
// the global revision interleaved with writes to other plans.
func RebuildPlanFences(state *State) {
	fences := make(map[string]uint64, len(state.Plans))
	for planID, plan := range state.Plans {
		version := uint64(1) // plan creation
		if plan.ActivatedAt != nil {
			version++ // activation commit
		}
		if plan.CompletedAt != nil {
			version++ // completion commit
		}
		fences[planID] = version
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
	for planID, version := range fences {
		plan := state.Plans[planID]
		plan.Version = version
		state.Plans[planID] = plan
	}
	state.PlanFences = fences
}

// PlanVersion projects the committed plan version into an aggregate for
// responses.
func PlanVersion(state *State, plan RolloutPlan) RolloutPlan {
	if version := PlanFenceFor(state, plan.ID); version != 0 {
		plan.Version = version
	}
	return plan
}

// PlanVersionMatches reports whether a submission carries the plan's current
// version.
func PlanVersionMatches(state *State, planID string, expected uint64) bool {
	return expected != 0 && PlanFenceFor(state, planID) == expected
}

func timePointer(value time.Time) *time.Time {
	return &value
}
