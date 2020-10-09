//  Copyright (c) 2019 Couchbase, Inc.
//  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
//  except in compliance with the License. You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//  Unless required by applicable law or agreed to in writing, software distributed under the
//  License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
//  either express or implied. See the License for the specific language governing permissions
//  and limitations under the License.
//
// +build enterprise

package planner

import (
	"sort"

	"github.com/couchbase/query-ee/dictionary"
	"github.com/couchbase/query-ee/optutil"
	"github.com/couchbase/query/algebra"
	"github.com/couchbase/query/datastore"
	"github.com/couchbase/query/errors"
	"github.com/couchbase/query/expression"
	"github.com/couchbase/query/plan"
	base "github.com/couchbase/query/plannerbase"
	"github.com/couchbase/query/util"
)

func checkCostModel(featureControls uint64) {
	if util.IsFeatureEnabled(featureControls, util.N1QL_CBO_NEW) {
		optutil.SetNewCostModel()
	}
}

func optDocCount(keyspace datastore.Keyspace) float64 {
	docCount, _, _ := dictionary.GetKeyspaceInfo(keyspace.QualifiedName())
	return float64(docCount)
}

func optExprSelec(keyspaces map[string]string, pred expression.Expression, advisorValidate bool) (
	float64, float64) {
	sel, arrSel, def := optutil.ExprSelec(keyspaces, pred, advisorValidate)
	if def {
		return OPT_SELEC_NOT_AVAIL, OPT_SELEC_NOT_AVAIL
	}
	return sel, arrSel
}

func optDefInSelec(keyspace, key string, advisorValidate bool) float64 {
	return optutil.DefInSelec(keyspace, key, advisorValidate)
}

func optDefLikeSelec(keyspace, key string, advisorValidate bool) float64 {
	return optutil.DefLikeSelec(keyspace, key, advisorValidate)
}

func optMarkIndexFilters(keys expression.Expressions, spans plan.Spans2,
	condition expression.Expression, filters base.Filters) {
	optutil.MarkIndexFilters(keys, spans, condition, filters)
}

func optMinCost() float64 {
	return optutil.MinCost()
}

func primaryIndexScanCost(primary datastore.PrimaryIndex, requestId string) (cost, cardinality float64) {
	return optutil.CalcPrimaryIndexScanCost(primary, requestId)
}

func indexScanCost(index datastore.Index, sargKeys expression.Expressions, requestId string,
	spans SargSpans, alias string, advisorValidate bool) (cost float64, sel float64, card float64, err error) {
	switch spans := spans.(type) {
	case *TermSpans:
		return optutil.CalcIndexScanCost(index, sargKeys, requestId, spans.spans, alias, advisorValidate)
	case *IntersectSpans:
		return multiIndexCost(index, sargKeys, requestId, spans.spans, alias, false, advisorValidate)
	case *UnionSpans:
		return multiIndexCost(index, sargKeys, requestId, spans.spans, alias, true, advisorValidate)
	}

	return OPT_COST_NOT_AVAIL, OPT_SELEC_NOT_AVAIL, OPT_CARD_NOT_AVAIL, errors.NewPlanInternalError("indexScanCost: unexpected span type")
}

func multiIndexCost(index datastore.Index, sargKeys expression.Expressions, requestId string,
	spans []SargSpans, alias string, union, advisorValidate bool) (cost float64, sel float64, card float64, err error) {
	var nrows float64
	for i, span := range spans {
		tcost, tsel, tcard, e := indexScanCost(index, sargKeys, requestId, span, alias, advisorValidate)
		if e != nil {
			return tcost, tsel, tcard, e
		}
		cost += tcost
		tnrows := tcard / tsel
		if i == 0 {
			sel = tsel
			nrows = tnrows
		} else {
			tsel = tsel * (tnrows / nrows)
			if union {
				sel = sel + tsel - (sel * tsel)
			} else {
				sel = sel * tsel
			}
		}
	}

	return cost, sel, (sel * nrows), nil
}

func indexSelec(index datastore.Index, sargKeys expression.Expressions, skipKeys []bool,
	spans SargSpans, alias string, considerInternal bool) (sel float64, err error) {
	switch spans := spans.(type) {
	case *TermSpans:
		sel, _ := optutil.CalcIndexSelec(index, sargKeys, skipKeys, spans.spans, alias, considerInternal)
		return sel, nil
	case *IntersectSpans:
		return multiIndexSelec(index, sargKeys, skipKeys, spans.spans, alias, false, considerInternal)
	case *UnionSpans:
		return multiIndexSelec(index, sargKeys, skipKeys, spans.spans, alias, true, considerInternal)
	}

	return OPT_SELEC_NOT_AVAIL, errors.NewPlanInternalError("indexSelec: unexpected span type")
}

func multiIndexSelec(index datastore.Index, sargKeys expression.Expressions, skipKeys []bool,
	spans []SargSpans, alias string, union, considerInternal bool) (sel float64, err error) {
	for i, span := range spans {
		tsel, e := indexSelec(index, sargKeys, skipKeys, span, alias, considerInternal)
		if e != nil {
			return tsel, e
		}
		if i == 0 {
			sel = tsel
		} else {
			if union {
				sel = sel + tsel - (sel * tsel)
			} else {
				sel = sel * tsel
			}
		}
	}

	return sel, nil
}

func getIndexProjectionCost(index datastore.Index, indexProjection *plan.IndexProjection,
	cardinality float64) (float64, float64) {
	return optutil.CalcIndexProjectionCost(index, indexProjection, cardinality, 0, 0, 0)
}

func getIndexGroupAggsCost(index datastore.Index, indexGroupAggs *plan.IndexGroupAggregates,
	indexProjection *plan.IndexProjection, keyspaces map[string]string,
	cardinality float64) (float64, float64) {
	return optutil.CalcIndexGroupAggsCost(index, indexGroupAggs, indexProjection, keyspaces, cardinality)
}

func getKeyScanCost(keys expression.Expression) (float64, float64) {
	return optutil.CalcKeyScanCost(keys)
}

func getFetchCost(keyspace datastore.Keyspace, cardinality float64) float64 {
	return optutil.CalcFetchCost(keyspace, cardinality)
}

func getDistinctScanCost(index datastore.Index, cardinality float64) (float64, float64) {
	return optutil.CalcDistinctScanCost(index, cardinality, true)
}

func getExpressionScanCost(expr expression.Expression, keyspaces map[string]string) (float64, float64) {
	return optutil.CalcExpressionScanCost(expr, keyspaces)
}

func getValueScanCost(pairs algebra.Pairs) (float64, float64) {
	return optutil.CalcValueScanCost(pairs)
}

func getDummyScanCost() (float64, float64) {
	return optutil.CalcDummyScanCost()
}

func getCountScanCost() (float64, float64) {
	return optutil.CalcCountScanCost()
}

func getNLJoinCost(left, right plan.Operator, leftKeyspaces []string, rightKeyspace string,
	filters base.Filters, outer bool, op string) (float64, float64) {
	jointype := optutil.COST_JOIN
	if op == "nest" {
		jointype = optutil.COST_NEST
	}
	return optutil.CalcNLJoinCost(left, right, leftKeyspaces, rightKeyspace, filters, outer, jointype)
}

func getHashJoinCost(left, right plan.Operator, buildExprs, probeExprs expression.Expressions,
	leftKeyspaces []string, rightKeyspace string, buildRight, force bool, filters base.Filters,
	outer bool, op string) (float64, float64, bool) {
	jointype := optutil.COST_JOIN
	if op == "nest" {
		jointype = optutil.COST_NEST
	}
	return optutil.CalcHashJoinCost(left, right, buildExprs, probeExprs,
		leftKeyspaces, rightKeyspace, buildRight, force, filters, outer, jointype)
}

func getNLJoinCost2(left, right plan.Operator, joinCardinality float64, outer bool, op string) (float64, float64) {
	jointype := optutil.COST_JOIN
	if op == "nest" {
		jointype = optutil.COST_NEST
	}
	return optutil.CalcNLJoinCost2(left, right, joinCardinality, outer, jointype)
}

func getHashJoinCost2(left, right plan.Operator, buildExprs, probeExprs expression.Expressions,
	joinCardinality float64, buildRight, force bool, outer bool, op string) (float64, float64, bool) {
	jointype := optutil.COST_JOIN
	if op == "nest" {
		jointype = optutil.COST_NEST
	}
	return optutil.CalcHashJoinCost2(left, right, buildExprs, probeExprs, joinCardinality, buildRight, force, outer, jointype)
}

func getLookupJoinCost(left plan.Operator, outer bool, right *algebra.KeyspaceTerm,
	leftKeyspaces []string, rightKeyspace string) (float64, float64) {
	return optutil.CalcLookupJoinNestCost(left, outer, right, leftKeyspaces, rightKeyspace, optutil.COST_JOIN)
}

func getLookupJoinCost2(left plan.Operator, outer bool, right *algebra.KeyspaceTerm,
	rightKeyspace *base.BaseKeyspace) (float64, float64) {
	return optutil.CalcLookupJoinNestCost2(left, outer, right, rightKeyspace, optutil.COST_JOIN)
}

func getIndexJoinCost(left plan.Operator, outer bool, right *algebra.KeyspaceTerm,
	leftKeyspaces []string, rightKeyspace string, covered bool, index datastore.Index,
	requestId string, advisorValidate bool) (float64, float64) {
	return optutil.CalcIndexJoinNestCost(left, outer, right, leftKeyspaces, rightKeyspace,
		covered, index, requestId, optutil.COST_JOIN, advisorValidate)
}

func getLookupNestCost(left plan.Operator, outer bool, right *algebra.KeyspaceTerm,
	leftKeyspaces []string, rightKeyspace string) (float64, float64) {
	return optutil.CalcLookupJoinNestCost(left, outer, right, leftKeyspaces, rightKeyspace, optutil.COST_NEST)
}

func getIndexNestCost(left plan.Operator, outer bool, right *algebra.KeyspaceTerm,
	leftKeyspaces []string, rightKeyspace string, index datastore.Index,
	requestId string, advisorValidate bool) (float64, float64) {
	return optutil.CalcIndexJoinNestCost(left, outer, right, leftKeyspaces, rightKeyspace,
		false, index, requestId, optutil.COST_NEST, advisorValidate)
}

func getUnnestCost(node *algebra.Unnest, lastOp plan.Operator, keyspaces map[string]string, advisorValidate bool) (float64, float64) {
	return optutil.CalcUnnestCost(node, lastOp, keyspaces, advisorValidate)
}

func getSimpleFromTermCost(left, right plan.Operator, filters base.Filters) (float64, float64) {
	return optutil.CalcSimpleFromTermCost(left, right, filters)
}

func getSimpleFromTermCost2(left, right plan.Operator, joinCardinality float64, filters base.Filters) (float64, float64) {
	return optutil.CalcSimpleFromTermCost2(left, right, joinCardinality, filters)
}

func getSimpleFilterCost(cost, cardinality, selec float64) (float64, float64) {
	return optutil.CalcSimpleFilterCost(cost, cardinality, selec)
}

func getFilterCost(lastOp plan.Operator, expr expression.Expression,
	baseKeyspaces map[string]*base.BaseKeyspace, keyspaceNames map[string]string, advisorValidate bool) (float64, float64) {

	return optutil.CalcFilterCost(lastOp, expr, baseKeyspaces, keyspaceNames, advisorValidate)
}

func getFilterCostWithInput(expr expression.Expression, baseKeyspaces map[string]*base.BaseKeyspace,
	keyspaceNames map[string]string, cost, cardinality float64, advisorValidate bool) (float64, float64) {
	return optutil.CalcFilterCostWithInput(expr, baseKeyspaces, keyspaceNames, cost, cardinality, advisorValidate)
}

func getLetCost(lastOp plan.Operator) (float64, float64) {
	return optutil.CalcLetCost(lastOp)
}

func getWithCost(lastOp plan.Operator, with expression.Bindings) (float64, float64) {
	return optutil.CalcWithCost(lastOp, with)
}

func getOffsetCost(lastOp plan.Operator, noffset int64) (float64, float64) {
	return optutil.CalcOffsetCost(lastOp, noffset)
}

func getLimitCost(lastOp plan.Operator, nlimit int64) (float64, float64) {
	return optutil.CalcLimitCost(lastOp, nlimit)
}

func getUnnestPredSelec(pred expression.Expression, variable string, mapping expression.Expression,
	keyspaces map[string]string, advisorValidate bool) float64 {
	return optutil.GetUnnestPredSelec(pred, variable, mapping, keyspaces, advisorValidate)
}

func optChooseIntersectScan(keyspace datastore.Keyspace, sargables map[datastore.Index]*indexEntry,
	nTerms int, alias string, advisorValidate bool) map[datastore.Index]*indexEntry {

	indexes := make([]*base.IndexCost, 0, len(sargables))

	hasOrder := false
	for s, e := range sargables {
		skipKeys := make([]bool, len(e.sargKeys))
		icost := base.NewIndexCost(s, e.cost, e.cardinality, e.selectivity, skipKeys)
		if e.IsPushDownProperty(_PUSHDOWN_ORDER) {
			icost.SetOrder()
			hasOrder = true
		}
		indexes = append(indexes, icost)
	}

	if hasOrder && nTerms > 0 {
		// If some plans have Order pushdown, then add a SORT cost to all plans that
		// do not have Order pushdown.
		// Note that since we are still at keyspace level, the SORT cost is not going
		// to be the same as actual SORT cost which is done at the top of the plan,
		// however this is the best estimation we could do at this level.
		// (also ignore limit and offset for this calculation).
		for _, ic := range indexes {
			if !ic.HasOrder() {
				sortCost, _ := getSortCost(nTerms, ic.Cardinality(), 0, 0)
				if sortCost > 0.0 {
					ic.SetCost(ic.Cost() + sortCost)
				}
			}
		}
	}

	adjustIndexSelectivity(indexes, sargables, alias, advisorValidate)

	indexes = optutil.ChooseIntersectScan(keyspace, indexes)

	newSargables := make(map[datastore.Index]*indexEntry, len(indexes))
	for _, idx := range indexes {
		newSargables[idx.Index()] = sargables[idx.Index()]
	}

	return newSargables
}

func adjustIndexSelectivity(indexes []*base.IndexCost, sargables map[datastore.Index]*indexEntry,
	alias string, considerInternal bool) {

	if len(indexes) <= 1 {
		return
	}

	// first sort the slice
	sort.Slice(indexes, func(i, j int) bool {
		return ((indexes[i].Selectivity() < indexes[j].Selectivity()) ||
			((indexes[i].Selectivity() == indexes[j].Selectivity()) &&
				(indexes[i].Cost() < indexes[j].Cost())) ||
			((indexes[i].Selectivity() == indexes[j].Selectivity()) &&
				(indexes[i].Cost() == indexes[j].Cost()) &&
				(indexes[i].Cardinality() < indexes[j].Cardinality())))
	})

	used := make(map[string]bool, len(sargables[indexes[0].Index()].sargKeys))
	for i, idx := range indexes {
		entry := sargables[idx.Index()]
		adjust := false
		for j, key := range entry.sargKeys {
			if idx.HasSkipKey(j) {
				continue
			}
			s := key.String()
			// for array index key, ignore the distinct part
			if arr, ok := key.(*expression.All); ok {
				s = arr.Array().String()
			}

			if i == 0 {
				// this is the best index
				used[s] = true
			} else {
				// check and adjust remaining indexes
				if _, ok := used[s]; ok {
					idx.SetSkipKey(j)
					adjust = true
				}
			}
		}
		if adjust {
			sel, e := indexSelec(idx.Index(), entry.sargKeys, idx.SkipKeys(), entry.spans,
				alias, considerInternal)
			if e == nil {
				origSel := idx.Selectivity()
				origCard := idx.Cardinality()
				newCard := (origCard / origSel) * sel
				idx.SetSelectivity(sel)
				idx.SetCardinality(newCard)
			}
		}
	}

	// recurse on remaining indexes
	adjustIndexSelectivity(indexes[1:], sargables, alias, considerInternal)
}

func getSortCost(nterms int, cardinality float64, limit, offset int64) (float64, float64) {
	return optutil.CalcSortCost(nterms, cardinality, limit, offset)
}

func getInitialProjectCost(projection *algebra.Projection, cardinality float64) (float64, float64) {
	return optutil.CalcInitialProjectionCost(projection, cardinality)
}

func getGroupCosts(group *algebra.Group, aggregates algebra.Aggregates, cost, cardinality float64,
	keyspaces map[string]string, maxParallelism int) (
	float64, float64, float64, float64, float64, float64) {
	if maxParallelism <= 0 {
		maxParallelism = plan.GetMaxParallelism()
	}
	return optutil.CalcGroupCosts(group, aggregates, cost, cardinality, keyspaces, maxParallelism)
}

func getDistinctCost(terms algebra.ResultTerms, cardinality float64, keyspaces map[string]string, advisorValidate bool) (float64, float64) {
	return optutil.CalcDistinctCost(terms, cardinality, keyspaces)
}

func getUnionDistinctCost(cost, cardinality float64, first, second plan.Operator, compatible bool) (float64, float64) {
	return optutil.CalcUnionDistinctCost(cost, cardinality, first, second, compatible)
}

func getUnionAllCost(first, second plan.Operator, compatible bool) (float64, float64) {
	return optutil.CalcSetOpCost(first, second, compatible, optutil.COST_UNION)
}

func getIntersectAllCost(first, second plan.Operator, compatible bool) (float64, float64) {
	return optutil.CalcSetOpCost(first, second, compatible, optutil.COST_INTERSECT)
}

func getExceptAllCost(first, second plan.Operator, compatible bool) (float64, float64) {
	return optutil.CalcSetOpCost(first, second, compatible, optutil.COST_EXCEPT)
}

func getInsertCost(keyspace datastore.Keyspace, key, value, options, limit expression.Expression,
	cost, cardinality float64) (float64, float64) {
	return optutil.CalcInsertCost(keyspace, key, value, options, limit, cost, cardinality)
}

func getUpsertCost(keyspace datastore.Keyspace, key, value, options expression.Expression,
	cost, cardinality float64) (float64, float64) {
	return optutil.CalcUpsertCost(keyspace, key, value, options, cost, cardinality)
}

func getDeleteCost(keyspace datastore.Keyspace, limit expression.Expression,
	cost, cardinality float64) (float64, float64) {
	return optutil.CalcDeleteCost(keyspace, limit, cost, cardinality)
}

func getCloneCost(keyspace datastore.Keyspace, cost, cardinality float64) (float64, float64) {
	return optutil.CalcCloneCost(keyspace, cost, cardinality)
}

func getUpdateSetCost(keyspace datastore.Keyspace, set *algebra.Set, cost, cardinality float64) (float64, float64) {
	return optutil.CalcUpdateSetCost(keyspace, set, cost, cardinality)
}

func getUpdateUnsetCost(keyspace datastore.Keyspace, unset *algebra.Unset, cost, cardinality float64) (float64, float64) {
	return optutil.CalcUpdateUnsetCost(keyspace, unset, cost, cardinality)
}

func getUpdateSendCost(keyspace datastore.Keyspace, limit expression.Expression,
	cost, cardinality float64) (float64, float64) {
	return optutil.CalcUpdateSendCost(keyspace, limit, cost, cardinality)
}

func getWindowAggCost(aggs algebra.Aggregates, cost, cardinality float64) (float64, float64) {
	return optutil.CalcWindowAggCost(aggs, cost, cardinality)
}
