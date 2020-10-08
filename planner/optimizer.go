//  Copyright (c) 2020 Couchbase, Inc.
//  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
//  except in compliance with the License. You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//  Unless required by applicable law or agreed to in writing, software distributed under the
//  License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
//  either express or implied. See the License for the specific language governing permissions
//  and limitations under the License.
//

package planner

import (
	"fmt"
	"github.com/couchbase/query/algebra"
	"github.com/couchbase/query/datastore"
	"github.com/couchbase/query/errors"
	"github.com/couchbase/query/expression"
	"github.com/couchbase/query/plan"
	base "github.com/couchbase/query/plannerbase"
	"github.com/couchbase/query/util"
)

type Optimizer interface {
	Initialize(builder Builder)
	OptimizeQueryBlock(node algebra.Node) ([]plan.Operator, []plan.Operator, []plan.CoveringOperator, plan.Operator, error)
	DoJoinEnumeration() bool
}
type IntermediatePlan interface {
	GetPlan() []plan.Operator
	SetPlan([]plan.Operator)
	GetChildren() []plan.Operator
	SetChildren([]plan.Operator)
	GetSubChildren() []plan.Operator
	SetSubChildren([]plan.Operator)
	GetCoveringScans() []plan.CoveringOperator
	SetCoveringScans([]plan.CoveringOperator)
	GetCountScan() plan.CoveringOperator
	GetOrderScan() plan.SecondaryScan
	GetLastOp() plan.Operator
	SetLastOp(plan.Operator)
	GetIndexPushDowns() IndexPushDowns
	AddChildren(ops ...plan.Operator)
	AddSubchildrenParallel() *plan.Parallel
	Copy() IntermediatePlan
	GetBaseKeyspaceNames() []string
	GetCard() float64
	GetCumCard() float64
	GetCumCost() float64
}

type Builder interface {
	CopyBuilder() *builder
	GetBaseKeyspaces() map[string]*base.BaseKeyspace
	GetKeyspaceNames() map[string]string
	GetTermKeyspace(node *algebra.KeyspaceTerm) (datastore.Keyspace, error)
	AllHints(keyspace datastore.Keyspace, hints algebra.IndexRefs, indexes []datastore.Index, indexApiVersion int, useFts bool) ([]datastore.Index, error)
	GetSimpleFromTerms() map[string]algebra.SimpleFromTerm
	GetPrepareContext() *PrepareContext
	GetChildren() []plan.Operator
	GetSubChildren() []plan.Operator
	GetCoveringScans() []plan.CoveringOperator
	GetCountScan() plan.CoveringOperator
	GetOrderScan() plan.SecondaryScan
	GetLastOp() plan.Operator
	GetCover() expression.HasExpressions
	GetWhere() expression.Expression
	GetFilter() expression.Expression
	GetCorrelated() bool
	GetCoveredUnnests() map[*algebra.Unnest]bool
	GetPushableOnclause() expression.Expression
	GetBuilderFlags() uint32
	GetMaxParallelism() int
	GetIndexPushDowns() IndexPushDowns
	SetCoveringScans(coveringScans []plan.CoveringOperator)
	SetCover(cover expression.HasExpressions)
	SetWhere(where expression.Expression)
	SetFilter(filter expression.Expression)
	SetCorrelated(correlated bool)
	SetCoveredUnnests(coveredUnnests map[*algebra.Unnest]bool)
	SetCountScan(countScan plan.CoveringOperator)
	SetOrderScan(orderScan plan.SecondaryScan)
	SetLastOp(lastOp plan.Operator)
	SetBaseKeyspaces(basekeyspaces map[string]*base.BaseKeyspace)
	SetKeyspaceNames(keyspaceNames map[string]string)
	SetPushableOnclause(pushableOnclause expression.Expression)
	SetBuilderFlags(builderFlags uint32)
	SetMaxParallelism(maxParallelism int)
	SetIndexPushDowns(idxPushDowns IndexPushDowns)
	PrimaryScan() bool
	SetPrimaryScan()
	UnsetPrimaryScan()
	SecondaryScan() bool
	SetSecondaryScan()
	UnsetSecondaryScan()

	BuildScan(node algebra.SimpleFromTerm) ([]plan.Operator, []plan.CoveringOperator, error)
	BuildHashJoin(right algebra.SimpleFromTerm, onClause []expression.Expression, leftPlan IntermediatePlan, rightPlan IntermediatePlan, joinCardinality float64) (*plan.HashJoin, []plan.Operator, error)
	BuildJoin(right algebra.SimpleFromTerm, onClause []expression.Expression, origJoinFilters base.Filters, leftPlan IntermediatePlan, rightPlan IntermediatePlan, joinCardinality float64) (*plan.NLJoin, *plan.Join, IntermediatePlan, error)
}

func (this *builder) CopyBuilder() *builder {
	return this.Copy()
}
func (this *builder) GetBaseKeyspaces() map[string]*base.BaseKeyspace {
	return this.baseKeyspaces
}

func (this *builder) GetKeyspaceNames() map[string]string {
	return this.keyspaceNames
}

func (this *builder) GetTermKeyspace(node *algebra.KeyspaceTerm) (datastore.Keyspace, error) {
	return this.getTermKeyspace(node)
}

func (this *builder) AllHints(keyspace datastore.Keyspace, hints algebra.IndexRefs, indexes []datastore.Index, indexApiVersion int, useFts bool) (
	[]datastore.Index, error) {
	return this.allHints(keyspace, hints, indexes, indexApiVersion, useFts)
}

func (this *builder) GetSimpleFromTerms() map[string]algebra.SimpleFromTerm {
	return this.simpleFromTerms
}

func (this *builder) GetPrepareContext() *PrepareContext {
	return this.context
}

func (this *builder) GetChildren() []plan.Operator {
	return this.children
}

func (this *builder) GetSubChildren() []plan.Operator {
	return this.subChildren
}

func (this *builder) GetCoveringScans() []plan.CoveringOperator {
	return this.coveringScans
}

func (this *builder) GetCountScan() plan.CoveringOperator {
	return this.countScan
}

func (this *builder) GetOrderScan() plan.SecondaryScan {
	return this.orderScan
}

func (this *builder) GetLastOp() plan.Operator {
	return this.lastOp
}

func (this *builder) GetCover() expression.HasExpressions {
	return this.cover
}

func (this *builder) GetWhere() expression.Expression {
	return this.where
}

func (this *builder) GetFilter() expression.Expression {
	return this.filter
}

func (this *builder) GetCorrelated() bool {
	return this.correlated
}

func (this *builder) GetCoveredUnnests() map[*algebra.Unnest]bool {
	return this.coveredUnnests
}

func (this *builder) GetPushableOnclause() expression.Expression {
	return this.pushableOnclause
}

func (this *builder) GetBuilderFlags() uint32 {
	return this.builderFlags
}

func (this *builder) GetMaxParallelism() int {
	return this.maxParallelism
}

func (this *builder) GetIndexPushDowns() IndexPushDowns {
	return this.IndexPushDowns
}

func (this *builder) SetCoveringScans(coveringScans []plan.CoveringOperator) {
	this.coveringScans = coveringScans
}

func (this *builder) SetCover(cover expression.HasExpressions) {
	this.cover = cover
}

func (this *builder) SetWhere(where expression.Expression) {
	this.where = where
}

func (this *builder) SetFilter(filter expression.Expression) {
	this.filter = filter
}

func (this *builder) SetCorrelated(correlated bool) {
	this.correlated = correlated
}

func (this *builder) SetCoveredUnnests(coveredUnnests map[*algebra.Unnest]bool) {
	this.coveredUnnests = coveredUnnests
}

func (this *builder) SetCountScan(countScan plan.CoveringOperator) {
	this.countScan = countScan
}

func (this *builder) SetOrderScan(orderScan plan.SecondaryScan) {
	this.orderScan = orderScan
}

func (this *builder) SetLastOp(lastOp plan.Operator) {
	this.lastOp = lastOp
}

func (this *builder) SetBaseKeyspaces(basekeyspaces map[string]*base.BaseKeyspace) {
	this.baseKeyspaces = basekeyspaces
}

func (this *builder) SetKeyspaceNames(keyspaceNames map[string]string) {
	this.keyspaceNames = keyspaceNames
}

func (this *builder) SetPushableOnclause(pushableOnclause expression.Expression) {
	this.pushableOnclause = pushableOnclause
}

func (this *builder) SetBuilderFlags(builderFlags uint32) {
	this.builderFlags = builderFlags
}

func (this *builder) SetMaxParallelism(maxParallelism int) {
	this.maxParallelism = maxParallelism
}

func (this *builder) SetIndexPushDowns(idxPushDowns IndexPushDowns) {
	this.IndexPushDowns = idxPushDowns
}

func (this *builder) PrimaryScan() bool {
	return (this.builderFlags & BUILDER_PRIMARY_SCAN) != 0
}

func (this *builder) SetPrimaryScan() {
	this.builderFlags |= BUILDER_PRIMARY_SCAN
}

func (this *builder) UnsetPrimaryScan() {
	this.builderFlags &^= BUILDER_PRIMARY_SCAN
}

func (this *builder) SecondaryScan() bool {
	return (this.builderFlags & BUILDER_SECONDARY_SCAN) != 0
}

func (this *builder) SetSecondaryScan() {
	this.builderFlags |= BUILDER_SECONDARY_SCAN
}

func (this *builder) UnsetSecondaryScan() {
	this.builderFlags &^= BUILDER_SECONDARY_SCAN
}

func (this *builder) BuildScan(node algebra.SimpleFromTerm) ([]plan.Operator, []plan.CoveringOperator, error) {
	this.children = make([]plan.Operator, 0, 16)
	this.subChildren = make([]plan.Operator, 0, 16)
	this.coveringScans = nil
	this.countScan = nil
	this.order = nil
	this.orderScan = nil
	this.limit = nil
	this.offset = nil
	this.lastOp = nil

	_, err := node.Accept(this)
	if err != nil {
		return nil, nil, err
	}
	return this.children, this.coveringScans, nil
}

func (this *builder) BuildHashJoin(right algebra.SimpleFromTerm, onClause []expression.Expression, leftPlan IntermediatePlan, rightPlan IntermediatePlan, joinCardinality float64) (hjoin *plan.HashJoin, probePlan []plan.Operator, err error) {

	if onClause == nil {
		return nil, nil, nil
	}
	this.requirePrimaryKey = true

	var andedOnClause expression.Expression
	for idx, expr := range onClause {
		if idx == 0 {
			andedOnClause = expr.Copy()
		} else {
			andedOnClause = expression.NewAnd(andedOnClause, expr.Copy())
		}
	}

	/*	if term, ok := node.PrimaryTerm().(*algebra.ExpressionTerm); ok && term.IsKeyspace() &&
			this.group == nil && node.Right().JoinHint() != algebra.USE_HASH_PROBE {
			this.resetProjection()
			this.resetIndexGroupAggs()
			this.resetOffsetLimit()
		} else {
			this.resetPushDowns()
		}
	*/

	//if err != nil && !this.indexAdvisor {
	//	return nil, err
	//}
	// Start BuildAnsiJoinOp

	//	right := node.Right()

	if ksterm := algebra.GetKeyspaceTerm(right); ksterm != nil {
		right = ksterm
	}

	useCBO := this.useCBO

	baseKeyspace, _ := this.baseKeyspaces[right.Alias()]

	switch right := right.(type) {
	case *algebra.KeyspaceTerm:
		// Commented out for now, will revisit this when join enumeration handles outer joins.
		//		err := this.processOnclause(right.Alias(), node.Onclause(), node.Outer(), node.Pushable())
		// if err != nil {
		//	return nil, err
		//}

		this.extractKeyspacePredicates(nil, andedOnClause)

		if len(baseKeyspace.Filters()) > 0 {
			baseKeyspace.Filters().ClearPlanFlags()
		}
		filter, selec, err := this.getFilter(right.Alias(), andedOnClause)
		if err != nil {
			return nil, nil, err
		}

		if util.IsFeatureEnabled(this.context.FeatureControls(), util.N1QL_HASH_JOIN) &&
			(useCBO || right.PreferHash()) {
			hjoin, probePlan, err = this.constructHashJoin(right, onClause, leftPlan, rightPlan, false /*outerflag is set to false for now */, filter, selec, joinCardinality, "join")
			if err != nil || hjoin == nil {
				return nil, nil, err
			} else {
				return hjoin, probePlan, nil
			}
		}

	case *algebra.ExpressionTerm, *algebra.SubqueryTerm:
		//err := this.processOnclause(right.Alias(), node.Onclause(), node.Outer(), node.Pushable())
		//if err != nil {
		//	return nil, err
		//}

		filter, selec, err := this.getFilter(right.Alias(), andedOnClause)
		if err != nil {
			return nil, nil, err
		}

		if util.IsFeatureEnabled(this.context.FeatureControls(), util.N1QL_HASH_JOIN) {
			// for expression term and subquery term, consider hash join
			// even without USE HASH hint, as long as USE NL is not specified
			if !right.PreferNL() {
				hjoin, probePlan, err := this.constructHashJoin(right, onClause, leftPlan, rightPlan, false /*outerflag is set to false for now */, filter, selec, joinCardinality, "join")
				if err != nil || hjoin == nil {
					return nil, nil, err
				} else {
					return hjoin, probePlan, nil
				}
			}
		}
	default:
		return nil, nil, errors.NewPlanInternalError(fmt.Sprintf("buildAnsiJoin: Unexpected right-hand side node type"))
	}

	/*	if err != nil {
		this.processadviseJF(node.Alias())
		return nil, err
	}*/
	//		if this.useCBO {
	// once the join is finalized, properly mark plan flags on the right-hand side
	//			err = this.markPlanFlags(op, right)//node.Right())
	//		}
	// end buildAnsiJoin
	/*		if err != nil {
				this.processadviseJF(node.Alias())
				return nil, err
			}
	*/

	//	err = this.processKeyspaceDone(right.Alias())
	//	if err != nil {
	//	return nil, err
	//	}

	return nil, nil, nil
}

func (this *builder) BuildJoin(right algebra.SimpleFromTerm, onClause []expression.Expression, origJoinFilters base.Filters, leftPlan IntermediatePlan, rightPlan IntermediatePlan, joinCardinality float64) (nljoin *plan.NLJoin, lookupjoin *plan.Join, probePlan IntermediatePlan, err error) {

	if onClause == nil {
		return nil, nil, nil, nil
	}
	this.requirePrimaryKey = true

	var andedOnClause expression.Expression
	for idx, expr := range onClause {
		if idx == 0 {
			andedOnClause = expr.Copy()
		} else {
			andedOnClause = expression.NewAnd(andedOnClause, expr.Copy())
		}
	}

	/*	if term, ok := node.PrimaryTerm().(*algebra.ExpressionTerm); ok && term.IsKeyspace() &&
			this.group == nil && node.Right().JoinHint() != algebra.USE_HASH_PROBE {
			this.resetProjection()
			this.resetIndexGroupAggs()
			this.resetOffsetLimit()
		} else {
			this.resetPushDowns()
		}
	*/

	//if err != nil && !this.indexAdvisor {
	//	return nil, err
	//}
	// Start BuildAnsiJoinOp

	//	right := node.Right()

	if ksterm := algebra.GetKeyspaceTerm(right); ksterm != nil {
		right = ksterm
	}

	useCBO := this.useCBO
	baseKeyspace, _ := this.baseKeyspaces[right.Alias()]

	switch right := right.(type) {
	case *algebra.KeyspaceTerm:
		/*		err := this.processOnclause(right.Alias(), andedOnClause, false, node.Outer(), node.Pushable())
				if err != nil {
					return nil,nil, err
				}
		*/
		this.extractKeyspacePredicates(nil, andedOnClause)

		if len(baseKeyspace.Filters()) > 0 {
			baseKeyspace.Filters().ClearPlanFlags()
		}

		filter, selec, err := this.getFilter(right.Alias(), andedOnClause)
		if err != nil {
			return nil, nil, nil, err
		}

		origOnclause := andedOnClause
		right.SetUnderNL()
		scans, probePlan, primaryJoinKeys, newOnclause, newFilter, cost, cardinality, err := this.constructJoin(right, onClause, andedOnClause, origJoinFilters, leftPlan, rightPlan, filter, joinCardinality, false /*outerflag is set to false for now */, "join")
		if err != nil { // && !useCBO {
			// in case of CBO, defer returning error in case hash join is feasible
			return nil, nil, nil, err
		}

		if len(scans.GetPlan()) > 0 {
			//			if newOnclause != nil {
			//				node.SetOnclause(newOnclause)
			//			}
			if useCBO && (cost > 0.0) && (cardinality > 0.0) && (selec > 0.0) && (filter != nil) {
				selec = this.adjustForIndexFilters(right.Alias(), origOnclause, selec)
				cost, cardinality = getSimpleFilterCost(cost, cardinality, selec)
			}
			cumCost := leftPlan.GetCumCost() + cost
			return plan.NewNLJoinJE(plan.NewSequence(scans.GetPlan()...), false /*for now */, newOnclause, right.Alias(), newFilter, cost, cumCost, joinCardinality), nil, probePlan /*.GetPlan()*/, nil
		} else if err != nil { //&& useCBO {
			// error occurred and neither nested-loop join nor hash join is available
			return nil, nil, nil, err
		}

		right.UnsetUnderNL()

		if !right.IsPrimaryJoin() {
			return nil, nil, nil, errors.NewPlanInternalError(fmt.Sprintf("buildAnsiJoin: no plan built for %s", right.Alias()))
		}

		// put filter back to this.filter since Join cannot evaluate filter
		if filter != nil {
			if this.filter == nil {
				this.filter = filter
			} else {
				this.filter = expression.NewAnd(this.filter, filter)
			}
		}

		// if joining on primary key (meta().id) and no secondary index
		// scan is available, create a "regular" join
		keyspace, err := this.getTermKeyspace(right)
		if err != nil {
			return nil, nil, nil, err
		}

		// make a copy of the original KeyspaceTerm with the extra
		// primaryJoinKeys and construct a JOIN operator
		newKeyspaceTerm := algebra.NewKeyspaceTermFromPath(right.Path(), right.As(), nil, right.Indexes())
		newKeyspaceTerm.SetProperty(right.Property())
		newKeyspaceTerm.SetJoinKeys(primaryJoinKeys)
		cost = OPT_COST_NOT_AVAIL
		cardinality = OPT_CARD_NOT_AVAIL
		if this.useCBO {
			cost, cardinality = getLookupJoinCost2(rightPlan.GetLastOp(), false, /*node.Outer(), */
				newKeyspaceTerm, this.baseKeyspaces[right.Alias()])
		}
		cumCost := leftPlan.GetCumCost() + cost
		return nil, plan.NewJoinFromAnsiJE(keyspace, newKeyspaceTerm, false /*node.Outer(), */, cost, cumCost, cardinality), probePlan, nil
	case *algebra.ExpressionTerm, *algebra.SubqueryTerm:
		//		err := this.processOnclause(right.Alias(), andedOnClause, node.Outer(), node.Pushable())
		//		if err != nil {
		//			return nil, err
		//		}

		filter, selec, err := this.getFilter(right.Alias(), andedOnClause)
		if err != nil {
			return nil, nil, nil, err
		}

		scans, probePlan, newOnclause, cost, cardinality, err := this.constructAnsiJoinSimpleFromTerm(right, leftPlan, rightPlan, joinCardinality, andedOnClause)
		if err != nil {
			return nil, nil, nil, err
		}

		//		if newOnclause != nil {
		//			node.SetOnclause(newOnclause)
		//		}

		if useCBO && (cost > 0.0) && (cardinality > 0.0) && (selec > 0.0) && (filter != nil) {
			cost, cardinality = getSimpleFilterCost(cost, cardinality, selec)
		}
		cumCost := leftPlan.GetCumCost() + cost
		return plan.NewNLJoinJE(plan.NewSequence(scans.GetPlan()...), false /*for now */, newOnclause, right.Alias(), filter, cost, cumCost, joinCardinality), nil, probePlan, nil
	default:
		return nil, nil, nil, errors.NewPlanInternalError(fmt.Sprintf("buildAnsiJoin: Unexpected right-hand side node type"))
	}
}
