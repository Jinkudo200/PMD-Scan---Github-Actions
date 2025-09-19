/*
 * BSD-style license; for more info see http://pmd.sourceforge.net/license.html
 */
package net.sourceforge.pmd.lang.apex.rule.security;

import java.util.HashSet;
import java.util.Set;

import net.sourceforge.pmd.lang.apex.ast.ASTAssignmentExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTBinaryExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTFieldDeclaration;
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
 * Lightweight intra-class taint analysis for SOQL: seed params + common Salesforce input APIs,
 * propagate taint via assignments and concatenation, respect simple sanitizers (String.escapeSingleQuotes),
 * and flag Database.query/countQuery using tainted variables or concatenation.
 */
public class ApexTaintSoqlRule extends AbstractApexRule {

    private final Set<String> taintedVars = new HashSet<>();
    private final Set<String> sanitizedVars = new HashSet<>();
    private final Set<String> sanitizers = Set.of("escapeSingleQuotes", "HtmlSanitizer.clean", "CustomSanitizer.sanitize");

    @Override
    protected RuleTargetSelector buildTargetSelector() {
        return RuleTargetSelector.forTypes(ASTUserClass.class);
    }

    @Override
    public Object visit(ASTUserClass node, Object data) {
        if (Helper.isTestMethodOrClass(node) || Helper.isSystemLevelClass(node)) return data;

        // seed params as tainted for public / API-exposed methods
        for (ASTMethod m : node.descendants(ASTMethod.class)) {
            for (ASTParameter p : m.children(ASTParameter.class)) {
                if (m.isPublic() || m.hasDescendant(net.sourceforge.pmd.lang.apex.ast.ASTAnnotation.class)) {
                    taintedVars.add(Helper.getFQVariableName(p));
                }
            }
        }

        // assignments and field declarations propagation
        for (ASTFieldDeclaration f : node.descendants(ASTFieldDeclaration.class)) {
            propagateAssignment(f);
        }
        for (ASTVariableDeclaration vd : node.descendants(ASTVariableDeclaration.class)) {
            propagateAssignment(vd);
        }
        for (ASTAssignmentExpression ae : node.descendants(ASTAssignmentExpression.class)) {
            propagateAssignment(ae);
        }

        // check Database.query/call sites
        for (ASTMethodCallExpression call : node.descendants(ASTMethodCallExpression.class)) {
            if (isDatabaseQueryCall(call)) {
                // variables inside the query
                for (ASTVariableExpression v : call.descendants(ASTVariableExpression.class)) {
                    String fq = Helper.getFQVariableName(v);
                    if (taintedVars.contains(fq) && !sanitizedVars.contains(fq)) {
                        asCtx(data).addViolation(v);
                    }
                }
                // concatenated binary expressions
                for (ASTBinaryExpression b : call.children(ASTBinaryExpression.class)) {
                    for (ASTVariableExpression v : b.descendants(ASTVariableExpression.class)) {
                        String fq = Helper.getFQVariableName(v);
                        if (taintedVars.contains(fq) && !sanitizedVars.contains(fq)) {
                            asCtx(data).addViolation(b);
                        }
                    }
                }
            }
        }

        taintedVars.clear();
        sanitizedVars.clear();
        return data;
    }

    private void propagateAssignment(net.sourceforge.pmd.lang.apex.ast.ApexNode<?> node) {
        ASTVariableExpression left = node.firstChild(ASTVariableExpression.class);
        if (left == null) return;
        String leftFq = Helper.getFQVariableName(left);

        ASTMethodCallExpression rightCall = node.firstChild(ASTMethodCallExpression.class);
        if (rightCall != null) {
            if (sanitizers.contains(rightCall.getMethodName())) {
                sanitizedVars.add(leftFq);
                return;
            }
            for (ASTVariableExpression v : rightCall.descendants(ASTVariableExpression.class)) {
                if (taintedVars.contains(Helper.getFQVariableName(v))) {
                    taintedVars.add(leftFq);
                    return;
                }
            }
        }

        ASTBinaryExpression bin = node.firstChild(ASTBinaryExpression.class);
        if (bin != null) {
            for (ASTVariableExpression v : bin.descendants(ASTVariableExpression.class)) {
                if (taintedVars.contains(Helper.getFQVariableName(v))) {
                    taintedVars.add(leftFq);
                    return;
                }
            }
        }

        ASTVariableExpression rightVar = node.getFirstDescendantOfType(ASTVariableExpression.class);
        if (rightVar != null) {
            if (taintedVars.contains(Helper.getFQVariableName(rightVar))) {
                taintedVars.add(leftFq);
            }
        }

        // seed taint from known input sources
        for (ASTMethodCallExpression mc : node.descendants(ASTMethodCallExpression.class)) {
            if (isTaintSourceCall(mc)) {
                taintedVars.add(leftFq);
                return;
            }
        }
    }

    private boolean isDatabaseQueryCall(ASTMethodCallExpression call) {
        String def = call.getDefiningType() == null ? "" : call.getDefiningType();
        String m = call.getMethodName() == null ? "" : call.getMethodName();
        return ("Database".equals(def) && (m.equals("query") || m.equals("countQuery")))
                || (call.getImage() != null && call.getImage().contains("Database.query"));
    }

    private boolean isTaintSourceCall(ASTMethodCallExpression call) {
        String def = call.getDefiningType() == null ? "" : call.getDefiningType();
        String m = call.getMethodName() == null ? "" : call.getMethodName();
        if ("ApexPages".equals(def) && "currentPage".equals(m)) return true;
        if ("PageReference".equals(def) && "getParameters".equals(m)) return true;
        if ("RestContext".equals(def) || "HttpRequest".equals(def)) return true;
        if (m.contains("getParameter") || m.contains("getBody")) return true;
        return false;
    }
}
