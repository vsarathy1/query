//  Copyright (c) 2017 Couchbase, Inc.
//  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
//  except in compliance with the License. You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//  Unless required by applicable law or agreed to in writing, software distributed under the
//  License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
//  either express or implied. See the License for the specific language governing permissions
//  and limitations under the License.

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

func (this *builder) buildAnsiJoin(node *algebra.AnsiJoin) (op plan.Operator, err error) {
	op, err = this.buildAnsiJoinOp(node)
	if err != nil {
		return nil, err
	}

	if this.useCBO {
		// once the join is finalized, properly mark plan flags on the right-hand side
		err = this.markPlanFlags(op, node.Right())
	}

	return
}

func (this *builder) buildAnsiNest(node *algebra.AnsiNest) (op plan.Operator, err error) {
	op, err = this.buildAnsiNestOp(node)
	if err != nil {
		return nil, err
	}

	if this.useCBO {
		// once the join is finalized, properly mark plan flags on the right-hand side
		err = this.markPlanFlags(op, node.Right())
	}

	return
}

func (this *builder) buildAnsiJoinOp(node *algebra.AnsiJoin) (op plan.Operator, err error) {
	right := node.Right()

	if ksterm := algebra.GetKeyspaceTerm(right); ksterm != nil {
		right = ksterm
	}

	useCBO := this.useCBO

	switch right := right.(type) {
	case *algebra.KeyspaceTerm:
		err := this.processOnclause(right.Alias(), node.Onclause(), node.Outer(), node.Pushable())
		if err != nil {
			return nil, err
		}

		this.extractKeyspacePredicates(nil, node.Onclause())

		baseKeyspace, _ := this.baseKeyspaces[right.Alias()]
		if len(baseKeyspace.Filters()) > 0 {
			baseKeyspace.Filters().ClearPlanFlags()
		}

		filter, selec, err := this.getFilter(right.Alias(), node.Onclause())
		if err != nil {
			return nil, err
		}

		var hjoin *plan.HashJoin
		var jps, hjps *joinPlannerState
		var hjOnclause expression.Expression
		jps = this.saveJoinPlannerState()
		origOnclause := node.Onclause()
		hjCost := float64(OPT_COST_NOT_AVAIL)

		if util.IsFeatureEnabled(this.context.FeatureControls(), util.N1QL_HASH_JOIN) {
			tryHash := false
			if useCBO {
				tryHash = true
			} else if right.PreferHash() {
				// only consider hash join when USE HASH hint is specified
				tryHash = true
			}
			if tryHash {
				hjoin, err = this.buildHashJoin(node, filter, selec)
				if err != nil && !useCBO {
					// in case of CBO, ignore error (e.g. no index found)
					// try nested-loop below
					return nil, err
				}
				if hjoin != nil {
					if useCBO && !right.PreferHash() {
						hjCost = hjoin.Cost()
						hjps = this.saveJoinPlannerState()
						hjOnclause = node.Onclause()
					} else {
						return hjoin, nil
					}
				}
			}
		}

		// when building hash join this.children could have been switched,
		// restore before attempting to build nested-loop join
		this.restoreJoinPlannerState(jps)
		node.SetOnclause(origOnclause)
		right.SetUnderNL()
		scans, primaryJoinKeys, newOnclause, newFilter, cost, cardinality, err := this.buildAnsiJoinScan(right, node.Onclause(), filter, node.Outer(), "join")
		if err != nil && !useCBO {
			// in case of CBO, defer returning error in case hash join is feasible
			return nil, err
		}

		if len(scans) > 0 {
			if useCBO && !right.PreferNL() && (hjCost > 0.0) && (cost > hjCost) {
				this.restoreJoinPlannerState(hjps)
				node.SetOnclause(hjOnclause)
				return hjoin, nil
			}

			if right.PreferHash() {
				node.SetHintError(algebra.USE_HASH_NOT_FOLLOWED)
			}
			if newOnclause != nil {
				node.SetOnclause(newOnclause)
			}
			if useCBO && (cost > 0.0) && (cardinality > 0.0) && (selec > 0.0) && (filter != nil) {
				selec = this.adjustForIndexFilters(right.Alias(), origOnclause, selec)
				cost, cardinality = getSimpleFilterCost(cost, cardinality, selec)
			}
			return plan.NewNLJoin(node, plan.NewSequence(scans...), newFilter, cost, cardinality), nil
		} else if hjCost > 0.0 {
			this.restoreJoinPlannerState(hjps)
			node.SetOnclause(hjOnclause)
			if right.PreferNL() {
				node.SetHintError(algebra.USE_NL_NOT_FOLLOWED)
			}
			return hjoin, nil
		} else if err != nil && useCBO {
			// error occurred and neither nested-loop join nor hash join is available
			return nil, err
		}

		right.UnsetUnderNL()

		if !right.IsPrimaryJoin() {
			return nil, errors.NewPlanInternalError(fmt.Sprintf("buildAnsiJoin: no plan built for %s", node.Alias()))
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
			return nil, err
		}

		// make a copy of the original KeyspaceTerm with the extra
		// primaryJoinKeys and construct a JOIN operator
		newKeyspaceTerm := algebra.NewKeyspaceTermFromPath(right.Path(), right.As(), nil, right.Indexes())
		newKeyspaceTerm.SetProperty(right.Property())
		newKeyspaceTerm.SetJoinKeys(primaryJoinKeys)
		cost = OPT_COST_NOT_AVAIL
		cardinality = OPT_CARD_NOT_AVAIL
		if this.useCBO {
			leftKeyspaces, _, rightKeyspace, _ := this.getKeyspacesAliases(right.Alias())
			cost, cardinality = getLookupJoinCost(this.lastOp, node.Outer(),
				newKeyspaceTerm, leftKeyspaces, rightKeyspace)
		}
		return plan.NewJoinFromAnsi(keyspace, newKeyspaceTerm, node.Outer(), cost, cardinality), nil
	case *algebra.ExpressionTerm, *algebra.SubqueryTerm:
		err := this.processOnclause(right.Alias(), node.Onclause(), node.Outer(), node.Pushable())
		if err != nil {
			return nil, err
		}

		filter, selec, err := this.getFilter(right.Alias(), node.Onclause())
		if err != nil {
			return nil, err
		}

		if util.IsFeatureEnabled(this.context.FeatureControls(), util.N1QL_HASH_JOIN) {
			// for expression term and subquery term, consider hash join
			// even without USE HASH hint, as long as USE NL is not specified
			if !right.PreferNL() {
				hjoin, err := this.buildHashJoin(node, filter, selec)
				if hjoin != nil || err != nil {
					return hjoin, err
				}
			}
		}

		scans, newOnclause, cost, cardinality, err := this.buildAnsiJoinSimpleFromTerm(right, node.Onclause())
		if err != nil {
			return nil, err
		}

		if newOnclause != nil {
			node.SetOnclause(newOnclause)
		}

		if useCBO && (cost > 0.0) && (cardinality > 0.0) && (selec > 0.0) && (filter != nil) {
			cost, cardinality = getSimpleFilterCost(cost, cardinality, selec)
		}

		return plan.NewNLJoin(node, plan.NewSequence(scans...), filter, cost, cardinality), nil
	default:
		return nil, errors.NewPlanInternalError(fmt.Sprintf("buildAnsiJoin: Unexpected right-hand side node type"))
	}
}

func (this *builder) buildAnsiNestOp(node *algebra.AnsiNest) (op plan.Operator, err error) {
	right := node.Right()

	if ksterm := algebra.GetKeyspaceTerm(right); ksterm != nil {
		right = ksterm
	}

	useCBO := this.useCBO

	switch right := right.(type) {
	case *algebra.KeyspaceTerm:
		err := this.processOnclause(right.Alias(), node.Onclause(), node.Outer(), node.Pushable())
		if err != nil {
			return nil, err
		}

		this.extractKeyspacePredicates(nil, node.Onclause())

		baseKeyspace, _ := this.baseKeyspaces[right.Alias()]
		if len(baseKeyspace.Filters()) > 0 {
			baseKeyspace.Filters().ClearPlanFlags()
		}

		filter, selec, err := this.getFilter(right.Alias(), node.Onclause())
		if err != nil {
			return nil, err
		}

		var hnest *plan.HashNest
		var jps, hjps *joinPlannerState
		var hnOnclause expression.Expression
		jps = this.saveJoinPlannerState()
		origOnclause := node.Onclause()
		hnCost := float64(OPT_COST_NOT_AVAIL)

		if util.IsFeatureEnabled(this.context.FeatureControls(), util.N1QL_HASH_JOIN) {
			tryHash := false
			if useCBO {
				tryHash = true
			} else if right.PreferHash() {
				// only consider hash nest when USE HASH hint is specified
				tryHash = true
			}
			if tryHash {
				hnest, err = this.buildHashNest(node, filter, selec)
				if err != nil && !useCBO {
					// in case of CBO, ignore error (e.g. no index found)
					// try nested-loop below
					return nil, err
				}
				if hnest != nil {
					if useCBO && !right.PreferHash() {
						hnCost = hnest.Cost()
						hjps = this.saveJoinPlannerState()
						hnOnclause = node.Onclause()
					} else {
						return hnest, nil
					}
				}
			}
		}

		// when building hash nest this.children could have been switched,
		// restore before attempting to build nested-loop nest
		this.restoreJoinPlannerState(jps)
		node.SetOnclause(origOnclause)
		right.SetUnderNL()
		scans, primaryJoinKeys, newOnclause, newFilter, cost, cardinality, err := this.buildAnsiJoinScan(right, node.Onclause(), nil, node.Outer(), "nest")
		if err != nil && !useCBO {
			// in case of CBO, defer returning error in case hash join is feasible
			return nil, err
		}

		if len(scans) > 0 {
			if useCBO && !right.PreferNL() && (hnCost > 0.0) && (cost > hnCost) {
				this.restoreJoinPlannerState(hjps)
				node.SetOnclause(hnOnclause)
				return hnest, nil
			}

			if right.PreferHash() {
				node.SetHintError(algebra.USE_HASH_NOT_FOLLOWED)
			}
			if newOnclause != nil {
				node.SetOnclause(newOnclause)
			}
			if useCBO && (cost > 0.0) && (cardinality > 0.0) && (selec > 0.0) && (filter != nil) {
				selec = this.adjustForIndexFilters(right.Alias(), origOnclause, selec)
				cost, cardinality = getSimpleFilterCost(cost, cardinality, selec)
			}
			return plan.NewNLNest(node, plan.NewSequence(scans...), newFilter, cost, cardinality), nil
		} else if hnCost > 0.0 {
			this.restoreJoinPlannerState(hjps)
			node.SetOnclause(hnOnclause)
			if right.PreferNL() {
				node.SetHintError(algebra.USE_NL_NOT_FOLLOWED)
			}
			return hnest, nil
		} else if err != nil && useCBO {
			// error occurred and neither nested-loop join nor hash join is available
			return nil, err
		}

		right.UnsetUnderNL()

		if !right.IsPrimaryJoin() {
			return nil, errors.NewPlanInternalError(fmt.Sprintf("buildAnsiNest: no plan built for %s", node.Alias()))
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
		// scan is available, create a "regular" nest
		keyspace, err := this.getTermKeyspace(right)
		if err != nil {
			return nil, err
		}

		// make a copy of the original KeyspaceTerm with the extra
		// primaryJoinKeys and construct a NEST operator
		newKeyspaceTerm := algebra.NewKeyspaceTermFromPath(right.Path(), right.As(), nil, right.Indexes())
		newKeyspaceTerm.SetProperty(right.Property())
		newKeyspaceTerm.SetJoinKeys(primaryJoinKeys)
		cost = OPT_COST_NOT_AVAIL
		cardinality = OPT_CARD_NOT_AVAIL
		if this.useCBO {
			leftKeyspaces, _, rightKeyspace, _ := this.getKeyspacesAliases(right.Alias())
			cost, cardinality = getLookupNestCost(this.lastOp, node.Outer(),
				newKeyspaceTerm, leftKeyspaces, rightKeyspace)
		}
		return plan.NewNestFromAnsi(keyspace, newKeyspaceTerm, node.Outer(), cost, cardinality), nil
	case *algebra.ExpressionTerm, *algebra.SubqueryTerm:
		filter, selec, err := this.getFilter(right.Alias(), node.Onclause())
		if err != nil {
			return nil, err
		}

		if util.IsFeatureEnabled(this.context.FeatureControls(), util.N1QL_HASH_JOIN) {
			// for expression term and subquery term, consider hash join
			// even without USE HASH hint, as long as USE NL is not specified
			if !right.PreferNL() {
				hnest, err := this.buildHashNest(node, filter, selec)
				if hnest != nil || err != nil {
					return hnest, err
				}
			}
		}

		scans, newOnclause, cost, cardinality, err := this.buildAnsiJoinSimpleFromTerm(right, node.Onclause())
		if err != nil {
			return nil, err
		}

		if newOnclause != nil {
			node.SetOnclause(newOnclause)
		}

		if useCBO && (cost > 0.0) && (cardinality > 0.0) && (selec > 0.0) {
			cost, cardinality = getSimpleFilterCost(cost, cardinality, selec)
		}

		return plan.NewNLNest(node, plan.NewSequence(scans...), filter, cost, cardinality), nil
	default:
		return nil, errors.NewPlanInternalError(fmt.Sprintf("buildAnsiNest: Unexpected right-hand side node type"))
	}
}

func (this *builder) processOnclause(alias string, onclause expression.Expression, outer, pushable bool) (err error) {
	baseKeyspace, ok := this.baseKeyspaces[alias]
	if !ok {
		return errors.NewPlanInternalError(fmt.Sprintf("processOnclause: missing baseKeyspace %s", alias))
	}

	// add ON-clause if it's not already part of this.pushableOnclause
	if outer || !pushable {
		// For the keyspace as the inner of an ANSI JOIN, the processPredicate() call
		// will effectively put ON clause filters on top of WHERE clause filters
		// for each keyspace, as a result, both ON clause filters and WHERE clause
		// filters will be used for index selection for the inner keyspace, which
		// is ok for outer joins.
		// Note this will also put ON clause filters of an outer join on the outer
		// keyspace as well however since index selection for the outer keyspace
		// is already done, ON clause filters from an outer join is NOT used for
		// index selection consideration of the outer keyspace (ON-clause of an
		// inner join is used for index selection for outer keyspace, as part of
		// this.pushableOnclause).
		_, err = this.processPredicate(onclause, true)
		if err != nil {
			return err
		}
	}

	// MB-38564: in case of outer join, filters from the WHERE clause should not
	// be pushed to a subservient table
	err = CombineFilters(baseKeyspace, true, outer)
	if err != nil {
		return err
	}

	return nil
}

func (this *builder) buildAnsiJoinScan(node *algebra.KeyspaceTerm, onclause, filter expression.Expression,
	outer bool, op string) (
	[]plan.Operator, expression.Expression, expression.Expression, expression.Expression, float64, float64, error) {

	children := this.children
	subChildren := this.subChildren
	coveringScans := this.coveringScans
	countScan := this.countScan
	orderScan := this.orderScan
	lastOp := this.lastOp
	indexPushDowns := this.storeIndexPushDowns()
	defer func() {
		this.children = children
		this.subChildren = subChildren
		this.countScan = countScan
		this.orderScan = orderScan
		this.lastOp = lastOp
		this.restoreIndexPushDowns(indexPushDowns, true)

		if len(this.coveringScans) > 0 {
			this.coveringScans = append(coveringScans, this.coveringScans...)
		} else {
			this.coveringScans = coveringScans
		}
	}()

	this.children = make([]plan.Operator, 0, 16)
	this.subChildren = make([]plan.Operator, 0, 16)
	this.coveringScans = nil
	this.countScan = nil
	this.order = nil
	this.orderScan = nil
	this.limit = nil
	this.offset = nil
	this.lastOp = nil

	var err error

	baseKeyspace, _ := this.baseKeyspaces[node.Alias()]

	// check whether joining on meta().id
	id := expression.NewField(
		expression.NewMeta(expression.NewIdentifier(node.Alias())),
		expression.NewFieldName("id", false))

	var primaryJoinKeys expression.Expression

	for _, fltr := range baseKeyspace.Filters() {
		if fltr.IsOnclause() {
			if eqFltr, ok := fltr.FltrExpr().(*expression.Eq); ok {
				if eqFltr.First().EquivalentTo(id) {
					node.SetPrimaryJoin()
					primaryJoinKeys = eqFltr.Second().Copy()
					break
				} else if eqFltr.Second().EquivalentTo(id) {
					node.SetPrimaryJoin()
					primaryJoinKeys = eqFltr.First().Copy()
					break
				}
			} else if inFltr, ok := fltr.FltrExpr().(*expression.In); ok {
				if inFltr.First().EquivalentTo(id) {
					node.SetPrimaryJoin()
					primaryJoinKeys = inFltr.Second().Copy()
					break
				}
			}
		}
	}

	_, err = node.Accept(this)
	if err != nil {
		switch e := err.(type) {
		case errors.Error:
			if e.Code() == errors.NO_ANSI_JOIN &&
				baseKeyspace.DnfPred() != nil && baseKeyspace.Onclause() != nil {

				// did not find an appropriate index path using both
				// on clause and where clause filters, try using just
				// the on clause filters
				baseKeyspace.SetOnclauseOnly()
				_, err = node.Accept(this)
			}
		}

		if err != nil {
			return nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
		}
	}

	if len(this.subChildren) > 0 {
		this.addChildren(this.addSubchildrenParallel())
	}

	// temporarily mark index filters for selectivity calculation
	err = markPlanFlagsChildren(node.Alias(), baseKeyspace.Filters(), this.children)
	if err != nil {
		return nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
	}

	// perform cover transformation for ON-clause
	// this needs to be done here since we build plan.AnsiJoin or plan.AnsiNest
	// by the caller right after returning from this function, and the plan
	// operators gets onclause expression from algebra.AnsiJoin or algebra.AnsiNest,
	// in case the entire ON-clause is transformed into a cover() expression
	// (e.g., an ANY clause as the entire ON-clause), this transformation needs to
	// be done before we build plan.AnsiJoin or plan.AnsiNest (since the root of
	// the expression changes), otherwise the transformed onclause will not be in
	// the plan operators.

	var newFilter expression.Expression
	if filter != nil {
		newFilter = filter.Copy()
	}

	newOnclause := onclause.Copy()

	// do right-hand-side covering index scan first, in case an ANY clause contains
	// a join filter, if part of the join filter gets transformed first, the ANY clause
	// will no longer match during transformation.
	// (note this assumes the ANY clause is on the right-hand-side keyspace)
	if len(this.coveringScans) > 0 {
		for _, op := range this.coveringScans {
			coverer := expression.NewCoverer(op.Covers(), op.FilterCovers())

			if primaryJoinKeys != nil {
				primaryJoinKeys, err = coverer.Map(primaryJoinKeys)
				if err != nil {
					return nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
				}
			}
			if newFilter != nil {
				newFilter, err = coverer.Map(newFilter)
				if err != nil {
					return nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
				}
			}
			newOnclause, err = coverer.Map(newOnclause)
			if err != nil {
				return nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
			}
		}
	}

	if len(coveringScans) > 0 {
		for _, op := range coveringScans {
			coverer := expression.NewCoverer(op.Covers(), op.FilterCovers())

			if primaryJoinKeys != nil {
				primaryJoinKeys, err = coverer.Map(primaryJoinKeys)
				if err != nil {
					return nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
				}
			}
			if newFilter != nil {
				newFilter, err = coverer.Map(newFilter)
				if err != nil {
					return nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
				}
			}
			newOnclause, err = coverer.Map(newOnclause)
			if err != nil {
				return nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
			}

			// also need to perform cover transformation for index spans for
			// right-hand-side index scans since left-hand-side expressions
			// could be used as part of index spans for right-hand-side index scan
			for _, child := range this.children {
				if secondary, ok := child.(plan.SecondaryScan); ok {
					err := secondary.CoverJoinSpanExpressions(coverer)
					if err != nil {
						return nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
					}
				}
			}
		}
	}

	cost := float64(OPT_COST_NOT_AVAIL)
	cardinality := float64(OPT_CARD_NOT_AVAIL)
	useCBO := this.useCBO
	if useCBO && len(this.children) > 0 {
		leftKeyspaces, _, rightKeyspace, _ := this.getKeyspacesAliases(node.Alias())
		cost, cardinality = getNLJoinCost(lastOp, this.lastOp, leftKeyspaces, rightKeyspace,
			baseKeyspace.Filters(), outer, op)
	}

	return this.children, primaryJoinKeys, newOnclause, newFilter, cost, cardinality, nil
}

func (this *builder) buildHashJoin(node *algebra.AnsiJoin, filter expression.Expression, selec float64) (hjoin *plan.HashJoin, err error) {
	child, buildExprs, probeExprs, aliases, newOnclause, newFilter, cost, cardinality, err := this.buildHashJoinScan(node.Right(), node.Outer(), node.Onclause(), filter, "join")
	if err != nil || child == nil {
		// cannot do hash join
		return nil, err
	}
	if this.useCBO && (cost > 0.0) && (cardinality > 0.0) && (selec > 0.0) && (filter != nil) {
		selec = this.adjustForHashFilters(node.Alias(), node.Onclause(), selec)
		cost, cardinality = getSimpleFilterCost(cost, cardinality, selec)
	}
	if newOnclause != nil {
		node.SetOnclause(newOnclause)
	}
	return plan.NewHashJoin(node, child, buildExprs, probeExprs, aliases, newFilter, cost, cardinality), nil
}

func (this *builder) buildHashNest(node *algebra.AnsiNest, filter expression.Expression, selec float64) (hnest *plan.HashNest, err error) {
	child, buildExprs, probeExprs, aliases, newOnclause, newFilter, cost, cardinality, err := this.buildHashJoinScan(node.Right(), node.Outer(), node.Onclause(), nil, "nest")
	if err != nil || child == nil {
		// cannot do hash nest
		return nil, err
	}
	if len(aliases) != 1 {
		return nil, errors.NewPlanInternalError(fmt.Sprintf("buildHashNest: multiple (%d) build aliases", len(aliases)))
	}
	if this.useCBO && (cost > 0.0) && (cardinality > 0.0) && (selec > 0.0) && (filter != nil) {
		selec = this.adjustForHashFilters(node.Alias(), node.Onclause(), selec)
		cost, cardinality = getSimpleFilterCost(cost, cardinality, selec)
	}
	if newOnclause != nil {
		node.SetOnclause(newOnclause)
	}
	return plan.NewHashNest(node, child, buildExprs, probeExprs, aliases[0], newFilter, cost, cardinality), nil
}

func (this *builder) buildHashJoinScan(right algebra.SimpleFromTerm, outer bool,
	onclause, filter expression.Expression, op string) (
	child plan.Operator, buildExprs expression.Expressions, probeExprs expression.Expressions,
	buildAliases []string, newOnclause, newFilter expression.Expression, cost, cardinality float64, err error) {

	var ksterm *algebra.KeyspaceTerm
	var keyspace string
	var defaultBuildRight bool

	if ksterm = algebra.GetKeyspaceTerm(right); ksterm != nil {
		right = ksterm
	}

	switch right := right.(type) {
	case *algebra.KeyspaceTerm:
		// if USE HASH and USE KEYS are specified together, make sure the document key
		// expressions does not reference any keyspaces, otherwise hash join cannot be
		// used.
		if ksterm.Keys() != nil && ksterm.Keys().Static() == nil {
			return nil, nil, nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, nil
		}
		keyspace = ksterm.Keyspace()
	case *algebra.ExpressionTerm:
		// hash join cannot handle expression term with any correlated references
		if right.IsCorrelated() {
			return nil, nil, nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, nil
		}

		defaultBuildRight = true
	case *algebra.SubqueryTerm:
		// hash join cannot handle correlated subquery
		if right.Subquery().IsCorrelated() {
			return nil, nil, nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, nil
		}

		defaultBuildRight = true
	default:
		return nil, nil, nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, errors.NewPlanInternalError(fmt.Sprintf("buildHashJoinScan: unexpected right-hand side node type"))
	}

	useCBO := this.useCBO
	buildRight := false
	force := true
	joinHint := right.JoinHint()
	if joinHint == algebra.USE_HASH_BUILD {
		buildRight = true
	} else if joinHint == algebra.USE_HASH_PROBE {
		// in case of outer join, cannot build on dominant side
		// also in case of nest, can only build on right-hand-side
		if outer || op == "nest" {
			return nil, nil, nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, nil
		}
	} else if outer || op == "nest" {
		// for outer join or nest, must build on right-hand side
		buildRight = true
	} else if defaultBuildRight {
		// for expression term and subquery term, if no USE HASH hint is
		// specified, then consider hash join/nest with the right-hand side
		// as build side
		buildRight = true
		force = false
	} else {
		force = false
	}

	alias := right.Alias()

	keyspaceNames := make(map[string]string, 1)
	keyspaceNames[alias] = keyspace

	baseKeyspace, _ := this.baseKeyspaces[alias]
	filters := baseKeyspace.Filters()
	if len(filters) > 0 {
		filters.ClearHashFlag()
	}

	// expressions for building and probing
	leftExprs := make(expression.Expressions, 0, 4)
	rightExprs := make(expression.Expressions, 0, 4)

	// look for equality join predicates
	for _, fltr := range filters {
		if !fltr.IsJoin() {
			continue
		}

		if eqFltr, ok := fltr.FltrExpr().(*expression.Eq); ok {
			if !eqFltr.First().Indexable() || !eqFltr.Second().Indexable() {
				continue
			}

			// make sure only one side of the equality predicate references
			// alias (which is right-hand-side of the join)
			firstRef := expression.HasKeyspaceReferences(eqFltr.First(), keyspaceNames)
			secondRef := expression.HasKeyspaceReferences(eqFltr.Second(), keyspaceNames)

			found := false
			if firstRef && !secondRef {
				rightExprs = append(rightExprs, eqFltr.First().Copy())
				leftExprs = append(leftExprs, eqFltr.Second().Copy())
				found = true
			} else if !firstRef && secondRef {
				leftExprs = append(leftExprs, eqFltr.First().Copy())
				rightExprs = append(rightExprs, eqFltr.Second().Copy())
				found = true
			}

			if useCBO && found {
				if fltr.Selec() > 0.0 {
					fltr.SetHJFlag()
				} else {
					useCBO = false
				}
			}
		}
	}

	if len(leftExprs) == 0 || len(rightExprs) == 0 {
		return nil, nil, nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, nil
	}

	// left hand side is already built
	if len(this.subChildren) > 0 {
		this.addChildren(this.addSubchildrenParallel())
	}

	// build right hand side

	coveringScans := this.coveringScans
	countScan := this.countScan
	orderScan := this.orderScan
	lastOp := this.lastOp
	indexPushDowns := this.storeIndexPushDowns()
	defer func() {
		this.countScan = countScan
		this.orderScan = orderScan
		this.lastOp = lastOp
		this.restoreIndexPushDowns(indexPushDowns, true)

		if len(this.coveringScans) > 0 {
			this.coveringScans = append(coveringScans, this.coveringScans...)
		} else {
			this.coveringScans = coveringScans
		}
	}()

	this.coveringScans = nil
	this.countScan = nil
	this.order = nil
	this.orderScan = nil
	this.limit = nil
	this.offset = nil
	this.lastOp = nil

	children := this.children
	subChildren := this.subChildren
	this.children = make([]plan.Operator, 0, 16)
	this.subChildren = make([]plan.Operator, 0, 16)

	// Note that by this point join filters involving keyspaces that's already done planning
	// are already moved into filters and thus is available for index selection. This is ok
	// if we are doing nested-loop join. However, for hash join, since both sides of the
	// hash join are independent of each other, we cannot use join filters for index selection
	// when planning for the right-hand side.
	if ksterm != nil {
		ksterm.SetUnderHash()
		defer func() {
			ksterm.UnsetUnderHash()
		}()
	}

	_, err = right.Accept(this)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
	}

	// if no plan generated, bail out
	if len(this.children) == 0 {
		return nil, nil, nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, nil
	}

	// perform cover transformation of leftExprs and rightExprs and onclause
	if filter != nil {
		newFilter = filter.Copy()
	}

	newOnclause = onclause.Copy()

	if len(this.coveringScans) > 0 {
		for _, op := range this.coveringScans {
			coverer := expression.NewCoverer(op.Covers(), op.FilterCovers())

			if newFilter != nil {
				newFilter, err = coverer.Map(newFilter)
				if err != nil {
					return nil, nil, nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
				}
			}

			newOnclause, err = coverer.Map(newOnclause)
			if err != nil {
				return nil, nil, nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
			}

			for i, _ := range rightExprs {
				rightExprs[i], err = coverer.Map(rightExprs[i])
				if err != nil {
					return nil, nil, nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
				}
			}
		}
	}

	if len(coveringScans) > 0 {
		for _, op := range coveringScans {
			coverer := expression.NewCoverer(op.Covers(), op.FilterCovers())

			if newFilter != nil {
				newFilter, err = coverer.Map(newFilter)
				if err != nil {
					return nil, nil, nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
				}
			}

			newOnclause, err = coverer.Map(newOnclause)
			if err != nil {
				return nil, nil, nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
			}

			for i, _ := range leftExprs {
				leftExprs[i], err = coverer.Map(leftExprs[i])
				if err != nil {
					return nil, nil, nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
				}
			}
		}
	}

	leftKeyspaces, leftAliases, rightKeyspace, rightAlias := this.getKeyspacesAliases(alias)

	if useCBO {
		var bldRight bool
		cost, cardinality, bldRight = getHashJoinCost(lastOp, this.lastOp, leftExprs, rightExprs, leftKeyspaces, rightKeyspace, buildRight, force, filters, outer, op)
		if cost > 0.0 && cardinality > 0.0 {
			buildRight = bldRight
		}
	} else {
		cost = OPT_COST_NOT_AVAIL
		cardinality = OPT_COST_NOT_AVAIL
	}

	if buildRight {
		if len(this.subChildren) > 0 {
			this.addChildren(this.addSubchildrenParallel())
		}
		child = plan.NewSequence(this.children...)
		this.children = children
		this.subChildren = subChildren
		probeExprs = leftExprs
		buildExprs = rightExprs
		buildAliases = []string{rightAlias}
	} else {
		if len(subChildren) > 0 {
			children = append(children, this.addParallel(subChildren...))
		}
		child = plan.NewSequence(children...)
		buildExprs = leftExprs
		probeExprs = rightExprs
		buildAliases = leftAliases
		this.lastOp = this.children[len(this.children)-1]
	}

	return child, buildExprs, probeExprs, buildAliases, newOnclause, newFilter, cost, cardinality, nil
}

func (this *builder) constructHashJoin(right algebra.SimpleFromTerm, onClause []expression.Expression, leftPlan IntermediatePlan, rightPlan IntermediatePlan, outer bool,
	filter expression.Expression, selec float64, joinCardinality float64, op string) (hjoin *plan.HashJoin, probePlan []plan.Operator, err error) {

	var ksterm *algebra.KeyspaceTerm
	var keyspace string
	var defaultBuildRight bool

	var andedOnClause expression.Expression
	for idx, expr := range onClause {
		if idx == 0 {
			andedOnClause = expr.Copy()
		} else {
			andedOnClause = expression.NewAnd(andedOnClause, expr.Copy())
		}
	}
	if ksterm = algebra.GetKeyspaceTerm(right); ksterm != nil {
		right = ksterm
	}

	switch right := right.(type) {
	case *algebra.KeyspaceTerm:
		// if USE HASH and USE KEYS are specified together, make sure the document key
		// expressions does not reference any keyspaces, otherwise hash join cannot be
		// used.
		if ksterm.Keys() != nil && ksterm.Keys().Static() == nil {
			return nil, nil, nil
		}
		keyspace = ksterm.Keyspace()
	case *algebra.ExpressionTerm:
		// hash join cannot handle expression term with any correlated references
		if right.IsCorrelated() {
			return nil, nil, nil
		}
		defaultBuildRight = true
	case *algebra.SubqueryTerm:
		// hash join cannot handle correlated subquery
		if right.Subquery().IsCorrelated() {
			return nil, nil, nil
		}

		defaultBuildRight = true
	default:
		return nil, nil, errors.NewPlanInternalError(fmt.Sprintf("buildHashJoinScan: unexpected right-hand side node type"))
	}

	useCBO := this.useCBO
	buildRight := false
	force := true
	joinHint := right.JoinHint()
	if joinHint == algebra.USE_HASH_BUILD {
		buildRight = true
	} else if joinHint == algebra.USE_HASH_PROBE {
		// in case of outer join, cannot build on dominant side
		// also in case of nest, can only build on right-hand-side
		if outer || op == "nest" {
			return nil, nil, nil
		}
	} else if outer || op == "nest" {
		// for outer join or nest, must build on right-hand side
		buildRight = true
	} else if defaultBuildRight {
		// for expression term and subquery term, if no USE HASH hint is
		// specified, then consider hash join/nest with the right-hand side
		// as build side
		buildRight = true
		force = false
	} else {
		force = false
	}

	alias := right.Alias()

	keyspaceNames := make(map[string]string, 1)
	keyspaceNames[alias] = keyspace

	leftExprs := make(expression.Expressions, 0, 4)
	rightExprs := make(expression.Expressions, 0, 4)
	for _, expr := range onClause {
		if eqFltr, ok := expr.(*expression.Eq); ok {
			if ok == false {
				return nil, nil, nil
			}
			// make sure only one side of the equality predicate references
			// alias (which is right-hand-side of the join)
			firstRef := expression.HasKeyspaceReferences(eqFltr.First(), keyspaceNames)
			secondRef := expression.HasKeyspaceReferences(eqFltr.Second(), keyspaceNames)

			found := false
			if firstRef && !secondRef {
				rightExprs = append(rightExprs, eqFltr.First().Copy())
				leftExprs = append(leftExprs, eqFltr.Second().Copy())
				found = true
			} else if !firstRef && secondRef {
				leftExprs = append(leftExprs, eqFltr.First().Copy())
				rightExprs = append(rightExprs, eqFltr.Second().Copy())
				found = true
			}
			if found == false {
				return nil, nil, nil
			}
		}
	}

	//	baseKeyspace, _ := this.baseKeyspaces[alias]
	//	filters := baseKeyspace.JoinFilters()

	if len(leftExprs) == 0 || len(rightExprs) == 0 {
		return nil, nil, nil
	}

	// Note that by this point join filters involving keyspaces that's already done planning
	// are already moved into filters and thus is available for index selection. This is ok
	// if we are doing nested-loop join. However, for hash join, since both sides of the
	// hash join are independent of each other, we cannot use join filters for index selection
	// when planning for the right-hand side.

	if ksterm != nil {
		ksterm.SetUnderHash()
		defer func() {
			ksterm.UnsetUnderHash()
		}()
	}

	// if no right plan generated, bail out
	if len(rightPlan.GetPlan()) == 0 {
		return nil, nil, nil
	}

	// perform cover transformation of leftExprs and rightExprs and onclause
	var newFilter expression.Expression
	if filter != nil {
		newFilter = filter.Copy()
	}

	newOnclause := andedOnClause.Copy()

	if len(rightPlan.GetCoveringScans()) > 0 {
		for _, op := range rightPlan.GetCoveringScans() {
			coverer := expression.NewCoverer(op.Covers(), op.FilterCovers())

			if newFilter != nil {
				newFilter, err = coverer.Map(newFilter)
				if err != nil {
					return nil, nil, err
				}
			}

			newOnclause, err = coverer.Map(newOnclause)
			if err != nil {
				return nil, nil, err
			}

			for i, _ := range rightExprs {
				rightExprs[i], err = coverer.Map(rightExprs[i])
				if err != nil {
					return nil, nil, err
				}
			}
		}
	}

	if len(leftPlan.GetCoveringScans()) > 0 {
		for _, op := range leftPlan.GetCoveringScans() {
			coverer := expression.NewCoverer(op.Covers(), op.FilterCovers())

			if newFilter != nil {
				newFilter, err = coverer.Map(newFilter)
				if err != nil {
					return nil, nil, err
				}
			}

			newOnclause, err = coverer.Map(newOnclause)
			if err != nil {
				return nil, nil, err
			}

			for i, _ := range leftExprs {
				leftExprs[i], err = coverer.Map(leftExprs[i])
				if err != nil {
					return nil, nil, err
				}
			}
		}
	}

	var cost, cardinality float64
	var child plan.Operator
	var probeExprs, buildExprs expression.Expressions
	var buildAliases []string

	if useCBO {
		var bldRight bool
		cost, cardinality, bldRight = getHashJoinCost2(leftPlan.GetLastOp(), rightPlan.GetLastOp(), leftExprs, rightExprs, joinCardinality, buildRight, force, outer, op)
		if cost > 0.0 && cardinality > 0.0 {
			buildRight = bldRight
		}
	} else {
		cost = OPT_COST_NOT_AVAIL
		cardinality = OPT_COST_NOT_AVAIL
	}

	leftPlanCopy := leftPlan.Copy()
	rightPlanCopy := rightPlan.Copy()
	if buildRight {
		if len(rightPlan.GetSubChildren()) > 0 {
			rightPlanCopy.AddChildren(rightPlanCopy.AddSubchildrenParallel())
		}

		child = plan.NewSequence(rightPlanCopy.GetPlan()...)
		if len(leftPlan.GetSubChildren()) > 0 {
			leftPlanCopy.AddChildren(leftPlanCopy.AddSubchildrenParallel())
		}
		probePlan = leftPlanCopy.GetPlan()
		probeExprs = leftExprs
		buildExprs = rightExprs
		buildAliases = []string{alias}
	} else {
		if len(leftPlan.GetSubChildren()) > 0 {
			leftPlanCopy.AddChildren(leftPlanCopy.AddSubchildrenParallel())
		}
		if len(rightPlan.GetSubChildren()) > 0 {
			rightPlanCopy.AddChildren(rightPlanCopy.AddSubchildrenParallel())
		}
		probePlan = rightPlanCopy.GetPlan()
		child = plan.NewSequence(leftPlanCopy.GetPlan()...)
		buildExprs = leftExprs
		probeExprs = rightExprs
		buildAliases = leftPlanCopy.GetBaseKeyspaceNames()
	}

	if err != nil || child == nil {
		// cannot do hash join
		return nil, nil, err
	}
	if this.useCBO && (cost > 0.0) && (cardinality > 0.0) && (selec > 0.0) && (filter != nil) {
		selec = this.adjustForHashFilters(right.Alias(), andedOnClause, selec)
		cost, cardinality = getSimpleFilterCost(cost, cardinality, selec)
	}
	//	if newOnclause != nil {
	//		node.SetOnclause(newOnclause)
	//	}
	cumCost := leftPlan.GetCumCost() + rightPlan.GetCumCost() + cost
	return plan.NewHashJoinJE(child, false, newOnclause, buildExprs, probeExprs, buildAliases, newFilter, cost, cumCost, joinCardinality), probePlan, nil
}

func (this *builder) constructJoin(right algebra.SimpleFromTerm, onClause []expression.Expression, andedOnClause expression.Expression, origJoinFilters base.Filters, leftPlan IntermediatePlan, rightPlan IntermediatePlan, filter expression.Expression, joinCardinality float64, outer bool, op string) (
	IntermediatePlan, IntermediatePlan /*[]plan.Operator, []plan.Operator, */, expression.Expression, expression.Expression, expression.Expression, float64, float64, error) {
	baseKeyspace, _ := this.baseKeyspaces[right.Alias()]

	// check whether joining on meta().id
	id := expression.NewField(
		expression.NewMeta(expression.NewIdentifier(right.Alias())),
		expression.NewFieldName("id", false))

	var primaryJoinKeys expression.Expression
	for _, fltr := range onClause { //range baseKeyspace.Filters() {
		//		if fltr.IsOnclause() {
		if eqFltr, ok := fltr.(*expression.Eq); ok {
			if eqFltr.First().EquivalentTo(id) {
				//right.SetPrimaryJoin()
				primaryJoinKeys = eqFltr.Second().Copy()
				break
			} else if eqFltr.Second().EquivalentTo(id) {
				//node.SetPrimaryJoin()
				primaryJoinKeys = eqFltr.First().Copy()
				break
			}
		} else if inFltr, ok := fltr.(*expression.In); ok {
			if inFltr.First().EquivalentTo(id) {
				//node.SetPrimaryJoin()
				primaryJoinKeys = inFltr.Second().Copy()
				break
			}
		}
		//	}
	}

	/* Save off the filters, so they can be restored after the call to BuildScan() */
	fltrs := baseKeyspace.Filters()
	joinfltrs := baseKeyspace.JoinFilters()
	dnfPred := baseKeyspace.DnfPred()
	origPred := baseKeyspace.OrigPred()
	onclause := baseKeyspace.Onclause()

	baseKeyspace.AddFilters(origJoinFilters)
	err := CombineFilters(baseKeyspace, true, outer)
	if err != nil {
		return nil, nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
	}

	_, _, err = this.BuildScan(right)
	if err != nil {
		switch e := err.(type) {
		case errors.Error:
			if e.Code() == errors.NO_ANSI_JOIN &&
				baseKeyspace.DnfPred() != nil && baseKeyspace.Onclause() != nil {

				// did not find an appropriate index path using both
				// on clause and where clause filters, try using just
				// the on clause filters
				baseKeyspace.SetOnclauseOnly()
				_, _, err = this.BuildScan(right)
			}
		}
		if err != nil {
			return nil, nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
		}
	}

	rightPlanCopy := rightPlan.Copy()
	rightPlanCopy.SetPlan(this.GetChildren())
	rightPlanCopy.SetChildren(this.GetChildren())
	rightPlanCopy.SetSubChildren(this.GetSubChildren())
	rightPlanCopy.SetCoveringScans(this.GetCoveringScans())
	rightPlanCopy.SetLastOp(this.GetLastOp())

	// Restore the filters
	baseKeyspace.SetFilters(fltrs, joinfltrs)
	baseKeyspace.SetPreds(dnfPred, origPred, onclause)

	leftPlanCopy := leftPlan.Copy()
	if len(rightPlanCopy.GetSubChildren()) > 0 {
		rightPlanCopy.AddChildren(rightPlanCopy.AddSubchildrenParallel())
	}

	// temporarily mark index filters for selectivity calculation
	err = markPlanFlagsChildren(right.Alias(), baseKeyspace.Filters(), rightPlanCopy.GetPlan())
	if err != nil {
		return nil, nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
	}

	// perform cover transformation for ON-clause
	// this needs to be done here since we build plan.AnsiJoin or plan.AnsiNest
	// by the caller right after returning from this function, and the plan
	// operators gets onclause expression from algebra.AnsiJoin or algebra.AnsiNest,
	// in case the entire ON-clause is transformed into a cover() expression
	// (e.g., an ANY clause as the entire ON-clause), this transformation needs to
	// be done before we build plan.AnsiJoin or plan.AnsiNest (since the root of
	// the expression changes), otherwise the transformed onclause will not be in
	// the plan operators.

	var newFilter expression.Expression
	if filter != nil {
		newFilter = filter.Copy()
	}

	newOnclause := andedOnClause.Copy()

	// do right-hand-side covering index scan first, in case an ANY clause contains
	// a join filter, if part of the join filter gets transformed first, the ANY clause
	// will no longer match during transformation.
	// (note this assumes the ANY clause is on the right-hand-side keyspace)
	//Change to rightPlanCopy
	if len(rightPlanCopy.GetCoveringScans()) > 0 {
		for _, op := range rightPlanCopy.GetCoveringScans() {
			coverer := expression.NewCoverer(op.Covers(), op.FilterCovers())

			if primaryJoinKeys != nil {
				primaryJoinKeys, err = coverer.Map(primaryJoinKeys)
				if err != nil {
					return nil, nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
				}
			}
			if newFilter != nil {
				newFilter, err = coverer.Map(newFilter)
				if err != nil {
					return nil, nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
				}
			}
			newOnclause, err = coverer.Map(newOnclause)
			if err != nil {
				return nil, nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
			}
		}
	}

	if len(leftPlan.GetCoveringScans()) > 0 {
		for _, op := range leftPlan.GetCoveringScans() {
			coverer := expression.NewCoverer(op.Covers(), op.FilterCovers())
			if primaryJoinKeys != nil {
				primaryJoinKeys, err = coverer.Map(primaryJoinKeys)
				if err != nil {
					return nil, nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
				}
			}
			if newFilter != nil {
				newFilter, err = coverer.Map(newFilter)
				if err != nil {
					return nil, nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
				}
			}
			newOnclause, err = coverer.Map(newOnclause)
			if err != nil {
				return nil, nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
			}

			// also need to perform cover transformation for index spans for
			// right-hand-side index scans since left-hand-side expressions
			// could be used as part of index spans for right-hand-side index scan
			for _, child := range rightPlanCopy.GetCoveringScans() {
				if secondary, ok := child.(plan.SecondaryScan); ok {
					err := secondary.CoverJoinSpanExpressions(coverer)
					if err != nil {
						return nil, nil, nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
					}
				}
			}
		}
	}

	cost := float64(OPT_COST_NOT_AVAIL)
	cardinality := float64(OPT_CARD_NOT_AVAIL)
	useCBO := this.useCBO
	if useCBO {
		if len(rightPlanCopy.GetPlan()) > 0 {
			cost, cardinality = getNLJoinCost2(leftPlanCopy.GetLastOp(), rightPlanCopy.GetLastOp(), joinCardinality, outer, op)
		}
	}
	return rightPlanCopy, leftPlanCopy, primaryJoinKeys, newOnclause, newFilter, cost, cardinality, nil
}

func (this *builder) getKeyspacesAliases(alias string) (
	leftKeyspaces, leftAliases []string, rightKeyspace, rightAliase string) {

	leftAliases = make([]string, 0, len(this.baseKeyspaces)-1)
	leftKeyspaces = make([]string, 0, len(this.baseKeyspaces)-1)
	for _, kspace := range this.baseKeyspaces {
		if kspace.PlanDone() {
			if kspace.Name() == alias {
				rightAliase = kspace.Name()
				rightKeyspace = kspace.Keyspace()
			} else {
				leftAliases = append(leftAliases, kspace.Name())
				leftKeyspaces = append(leftKeyspaces, kspace.Keyspace())
			}
		}
	}
	return
}

func (this *builder) buildAnsiJoinSimpleFromTerm(node algebra.SimpleFromTerm, onclause expression.Expression) (
	[]plan.Operator, expression.Expression, float64, float64, error) {

	var newOnclause expression.Expression
	var err error

	baseKeyspace, _ := this.baseKeyspaces[node.Alias()]
	filters := baseKeyspace.Filters()
	if len(filters) > 0 {
		filters.ClearIndexFlag()
	}

	// perform covering transformation
	if len(this.coveringScans) > 0 {
		var exprTerm *algebra.ExpressionTerm
		var fromExpr expression.Expression

		if term, ok := node.(*algebra.ExpressionTerm); ok {
			exprTerm = term
			if exprTerm.IsCorrelated() {
				fromExpr = exprTerm.ExpressionTerm().Copy()
			}
		}

		newOnclause = onclause.Copy()

		for _, op := range this.coveringScans {
			coverer := expression.NewCoverer(op.Covers(), op.FilterCovers())

			newOnclause, err = coverer.Map(newOnclause)
			if err != nil {
				return nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
			}

			if fromExpr != nil {
				fromExpr, err = coverer.Map(fromExpr)
				if err != nil {
					return nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
				}
			}
		}

		if exprTerm != nil && fromExpr != nil {
			exprTerm.SetExpressionTerm(fromExpr)
		}
	}

	children := this.children
	subChildren := this.subChildren
	lastOp := this.lastOp
	defer func() {
		this.children = children
		this.subChildren = subChildren
		this.lastOp = lastOp
	}()

	// new slices of this.children and this.subChildren are made in function
	// VisitSubqueryTerm() or VisitExpressionTerm()
	this.children = nil
	this.subChildren = nil
	this.lastOp = nil

	_, err = node.Accept(this)
	if err != nil {
		return nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
	}

	if len(this.subChildren) > 0 {
		this.addChildren(this.addSubchildrenParallel())
	}

	cost := OPT_COST_NOT_AVAIL
	cardinality := OPT_CARD_NOT_AVAIL

	if this.useCBO {
		cost, cardinality = getSimpleFromTermCost(lastOp, this.lastOp, filters)
	}

	return this.children, newOnclause, cost, cardinality, nil
}

func (this *builder) constructAnsiJoinSimpleFromTerm(node algebra.SimpleFromTerm, leftPlan IntermediatePlan, rightPlan IntermediatePlan, joinCardinality float64, onclause expression.Expression) (
	IntermediatePlan, IntermediatePlan /*[]plan.Operator, []plan.Operator, */, expression.Expression, float64, float64, error) {

	var newOnclause expression.Expression
	var err error

	baseKeyspace, _ := this.baseKeyspaces[node.Alias()]
	filters := baseKeyspace.Filters()
	if len(filters) > 0 {
		filters.ClearIndexFlag()
	}

	// perform covering transformation
	if len(leftPlan.GetCoveringScans()) > 0 {
		var exprTerm *algebra.ExpressionTerm
		var fromExpr expression.Expression

		if term, ok := node.(*algebra.ExpressionTerm); ok {
			exprTerm = term
			if exprTerm.IsCorrelated() {
				fromExpr = exprTerm.ExpressionTerm().Copy()
			}
		}

		newOnclause = onclause.Copy()

		for _, op := range leftPlan.GetCoveringScans() {
			coverer := expression.NewCoverer(op.Covers(), op.FilterCovers())

			newOnclause, err = coverer.Map(newOnclause)
			if err != nil {
				return nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
			}

			if fromExpr != nil {
				fromExpr, err = coverer.Map(fromExpr)
				if err != nil {
					return nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
				}
			}
		}

		if exprTerm != nil && fromExpr != nil {
			exprTerm.SetExpressionTerm(fromExpr)
		}
	}

	// new slices of this.children and this.subChildren are made in function
	// VisitSubqueryTerm() or VisitExpressionTerm()
	this.children = nil
	this.subChildren = nil
	this.lastOp = nil

	_, _, err = this.BuildScan(node)
	if err != nil {
		return nil, nil, nil, OPT_COST_NOT_AVAIL, OPT_CARD_NOT_AVAIL, err
	}

	rightPlanCopy := rightPlan.Copy()
	rightPlanCopy.SetPlan(this.GetChildren())
	rightPlanCopy.SetChildren(this.GetChildren())
	rightPlanCopy.SetSubChildren(this.GetSubChildren())
	rightPlanCopy.SetCoveringScans(this.GetCoveringScans())
	rightPlanCopy.SetLastOp(this.GetLastOp())

	if len(rightPlanCopy.GetSubChildren()) > 0 {
		rightPlanCopy.AddChildren(rightPlanCopy.AddSubchildrenParallel())
	}

	cost := OPT_COST_NOT_AVAIL
	cardinality := OPT_CARD_NOT_AVAIL

	if this.useCBO {
		cost, cardinality = getSimpleFromTermCost2(leftPlan.GetLastOp(), rightPlan.GetLastOp(), joinCardinality, filters)
	}

	leftPlanCopy := leftPlan.Copy()
	return rightPlanCopy, leftPlanCopy, newOnclause, cost, cardinality, nil
}

func (this *builder) markPlanFlags(op plan.Operator, term algebra.SimpleFromTerm) error {
	if op == nil || term == nil {
		s := ""
		if op == nil {
			s += "op == nil"
		}
		if term == nil {
			if len(s) > 0 {
				s += " "
			}
			s += "term == nil"
		}
		return errors.NewPlanInternalError(fmt.Sprintf("markPlanFlags: invalid arguments %s", s))
	}

	if op.Cost() <= 0.0 || op.Cardinality() <= 0.0 {
		return nil
	}

	ksterm := algebra.GetKeyspaceTerm(term)
	if ksterm == nil {
		// nothing to do
		return nil
	}

	alias := ksterm.Alias()
	baseKeyspace, _ := this.baseKeyspaces[alias]
	filters := baseKeyspace.Filters()
	if len(filters) > 0 {
		filters.ClearIndexFlag()
	}
	var children []plan.Operator

	switch op := op.(type) {
	case *plan.Join, *plan.Nest:
		// nothing to do
		return nil
	case *plan.NLJoin:
		// expect the child to be a sequence operator
		if seq, ok := op.Child().(*plan.Sequence); ok {
			children = seq.Children()
		}
		if len(filters) > 0 {
			filters.ClearHashFlag()
		}
	case *plan.NLNest:
		// expect the child to be a sequence operator
		if seq, ok := op.Child().(*plan.Sequence); ok {
			children = seq.Children()
		}
		if len(filters) > 0 {
			filters.ClearHashFlag()
		}
	case *plan.HashJoin:
		buildRight := false
		for _, ba := range op.BuildAliases() {
			if ba == alias {
				buildRight = true
				break
			}
		}
		if buildRight {
			// expect the child to be a sequence operator
			if seq, ok := op.Child().(*plan.Sequence); ok {
				children = seq.Children()
			}
		} else {
			children = this.children
		}
	case *plan.HashNest:
		if op.BuildAlias() == alias {
			// expect the child to be a sequence operator
			if seq, ok := op.Child().(*plan.Sequence); ok {
				children = seq.Children()
			}
		} else {
			children = this.children
		}
	case *plan.DistinctScan, *plan.IntersectScan, *plan.OrderedIntersectScan, *plan.UnionScan, *plan.IndexScan3:
		return markPlanFlagsScanOperator(alias, filters, op.(plan.SecondaryScan))
	case *plan.PrimaryScan3:
		// nothing to do
		return nil
	}

	if len(children) == 0 {
		return nil
	}

	return markPlanFlagsChildren(alias, filters, children)
}

func markPlanFlagsChildren(alias string, filters base.Filters, children []plan.Operator) error {
	for _, child := range children {
		// only linear join is supported currently
		// if more complex plan shape is supported in the future, needs
		// update logic below to handle more operator types
		// (e.g. Sequence, Parallel, NLJoin, HashJoin, NLNest, HashNest, etc)
		if scan, ok := child.(plan.SecondaryScan); ok {
			// recurse to handle SecondaryScans under join/nest
			err := markPlanFlagsScanOperator(alias, filters, scan)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func markPlanFlagsScanOperator(alias string, filters base.Filters, scan plan.SecondaryScan) error {
	switch op := scan.(type) {
	case *plan.DistinctScan:
		return markPlanFlagsSecondaryScans(alias, filters, op.Scan())
	case *plan.IntersectScan:
		return markPlanFlagsSecondaryScans(alias, filters, op.Scans()...)
	case *plan.OrderedIntersectScan:
		return markPlanFlagsSecondaryScans(alias, filters, op.Scans()...)
	case *plan.UnionScan:
		return markPlanFlagsSecondaryScans(alias, filters, op.Scans()...)
	case *plan.IndexScan3:
		return markPlanFlagsSecondaryScans(alias, filters, op)
	}

	return nil
}

func markPlanFlagsSecondaryScans(alias string, filters base.Filters, scans ...plan.SecondaryScan) error {
	// look for index scan
	var err error
	for _, scan := range scans {
		if iscan, ok := scan.(*plan.IndexScan3); ok {
			sterm := iscan.Term()
			if sterm != nil && sterm.Alias() == alias {
				err = markIndexFlags(iscan.Index(), iscan.Spans(), sterm.Alias(), filters)
				if err != nil {
					return err
				}
			}
		} else if sscan, ok := scan.(plan.SecondaryScan); ok {
			err = markPlanFlagsScanOperator(alias, filters, sscan)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func markIndexFlags(index datastore.Index, spans plan.Spans2, alias string, filters base.Filters) error {
	var err error
	var keys expression.Expressions
	var condition expression.Expression

	if !index.IsPrimary() {
		keys = index.RangeKey().Copy()
	}
	if index.Condition() != nil {
		condition = index.Condition().Copy()
	}
	if len(keys) > 0 || condition != nil {
		formalizer := expression.NewSelfFormalizer(alias, nil)

		for i, key := range keys {
			key = key.Copy()

			formalizer.SetIndexScope()
			key, err = formalizer.Map(key)
			formalizer.ClearIndexScope()
			if err != nil {
				break
			}

			keys[i] = key
		}

		if condition != nil && err == nil {
			condition, err = formalizer.Map(condition)
		}
	}
	if index.IsPrimary() {
		meta := expression.NewMeta(expression.NewIdentifier(alias))
		keys = append(keys, meta)
	}
	if err != nil {
		return err
	}

	optMarkIndexFilters(keys, spans, condition, filters)

	return nil
}

// if both nested-loop join and hash join are to be attempted (in case of CBO),
// need to save/restore certain planner states in between consideration of
// the two join methods
type joinPlannerState struct {
	children      []plan.Operator
	subChildren   []plan.Operator
	coveringScans []plan.CoveringOperator
	lastOp        plan.Operator
}

func (this *builder) saveJoinPlannerState() *joinPlannerState {
	return &joinPlannerState{
		children:      this.children,
		subChildren:   this.subChildren,
		coveringScans: this.coveringScans,
		lastOp:        this.lastOp,
	}
}

func (this *builder) restoreJoinPlannerState(jps *joinPlannerState) {
	this.children = jps.children
	this.subChildren = jps.subChildren
	this.coveringScans = jps.coveringScans
	this.lastOp = jps.lastOp
}
