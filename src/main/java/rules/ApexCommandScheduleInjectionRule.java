/*
 * BSD-style license; for more info see http://pmd.sourceforge.net/license.html
 */
package net.sourceforge.pmd.lang.apex.rule.security;

import java.util.HashSet;
import java.util.Set;

import net.sourceforge.pmd.lang.apex.ast.ASTAssignmentExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTBinaryExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTMethod;
import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTParameter;
import net.sourceforge.pmd.lang.apex.ast.ASTUserClass;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableDeclaration;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;
import net.sourceforge.pmd.lang.apex.rule.internal.Helper;
import net.sourceforge.pmd.lang.rule.RuleTargetSelector;

/**
 * HIGH priority
 * Detects user-controlled input flowing into scheduling or enqueue APIs (System.schedule / enqueueJob / Database.executeBatch)
 * where CRON expressions or job identifiers are built from tainted inputs or concatenations.
 */
public class ApexCommandScheduleInjectionRule extends AbstractApexRule {

    private final Set<String> taintedVars = new HashSet<>();
    private final Set<String> sanitizedVars = new HashSet<>();
    private final Set<String> sanitizers = Set.of("escapeSingleQuotes", "sanitizeCronPart");

    @Override
    protected RuleTargetSelector buildTargetSelector() {
        return RuleTargetSelector.forTypes(ASTUserClass.class);
    }

    @Override
    public Object visit(ASTUserClass node, Object data) {
        if (Helper.isTestMethodOrClass(node) || Helper.isSystemLevelClass(node)) return data;

        // seed params as tainted
        for (ASTMethod m : node.descendants(ASTMethod.class)) {
            for (ASTParameter p : m.children(ASTParameter.class)) {
                if (m.isPublic() || m.hasDescendant(net.sourceforge.pmd.lang.apex.ast.ASTAnnotation.class)) {
                    taintedVars.add(Helper.getFQVariableName(p));
                }
            }
        }

        // propagate assignments
        for (ASTVariableDeclaration vd : node.descendants(ASTVariableDeclaration.class)) {
            propagateAssignment(vd);
        }
        for (ASTAssignmentExpression ae : node.descendants(ASTAssignmentExpression.class)) {
            propagateAssignment(ae);
        }

        // check scheduling calls
        for (ASTMethodCallExpression call : node.descendants(ASTMethodCallExpression.class)) {
            if (isSchedulingCall(call)) {
                // binary concatenation checks
                for (ASTBinaryExpression b : call.descendants(ASTBinaryExpression.class)) {
                    for (ASTVariableExpression v : b.descendants(ASTVariableExpression.class)) {
                        String fq = Helper.getFQVariableName(v);
                        if (taintedVars.contains(fq) && !sanitizedVars.contains(fq)) {
                            asCtx(data).addViolation(call);
                        }
                    }
                }
                // direct var usage checks
                for (ASTVariableExpression v : call.descendants(ASTVariableExpression.class)) {
                    String fq = Helper.getFQVariableName(v);
                    if (taintedVars.contains(fq) && !sanitizedVars.contains(fq)) {
                        asCtx(data).addViolation(v);
                    }
                }
            }
        }

        taintedVars.clear();
        sanitizedVars.clear();
        return data;
    }

    private void propagateAssignment(net.sourceforge.pmd.lang.apex.ast.ApexNode<?> node) {
        net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression left = node.firstChild(net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression.class);
        if (left == null) return;
        String leftFq = Helper.getFQVariableName(left);

        net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression rightCall = node.firstChild(net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression.class);
        if (rightCall != null) {
            if (sanitizers.contains(rightCall.getMethodName())) {
                sanitizedVars.add(leftFq);
                return;
            }
            for (net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression v : rightCall.descendants(net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression.class)) {
                if (taintedVars.contains(Helper.getFQVariableName(v))) {
                    taintedVars.add(leftFq);
                    return;
                }
            }
        }

        net.sourceforge.pmd.lang.apex.ast.ASTBinaryExpression bin = node.firstChild(net.sourceforge.pmd.lang.apex.ast.ASTBinaryExpression.class);
        if (bin != null) {
            for (net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression v : bin.descendants(net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression.class)) {
                if (taintedVars.contains(Helper.getFQVariableName(v))) {
                    taintedVars.add(leftFq);
                    return;
                }
            }
        }

        net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression rightVar = node.getFirstDescendantOfType(net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression.class);
        if (rightVar != null) {
            if (taintedVars.contains(Helper.getFQVariableName(rightVar))) {
                taintedVars.add(leftFq);
            }
        }
    }

    private boolean isSchedulingCall(ASTMethodCallExpression call) {
        String def = call.getDefiningType() == null ? "" : call.getDefiningType();
        String m = call.getMethodName() == null ? "" : call.getMethodName();
        return ("System".equals(def) && "schedule".equals(m))
                || ("System".equals(def) && "enqueueJob".equals(m))
                || ("Database".equals(def) && "executeBatch".equals(m))
                || "executeBatch".equals(m) || "enqueueJob".equals(m);
    }
}
