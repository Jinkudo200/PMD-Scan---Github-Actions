/*
 * BSD-style license; for more info see http://pmd.sourceforge.net/license.html
 */

package rules;

import java.util.Set;
import java.util.HashSet;

import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTUserClass;
import net.sourceforge.pmd.lang.apex.ast.ApexNode;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;
import net.sourceforge.pmd.lang.rule.RuleTargetSelector;
import net.sourceforge.pmd.lang.rule.RulePriority;
import net.sourceforge.pmd.lang.apex.rule.internal.Helper;

/**
 * Detects insecure logging of sensitive data like DML or SOQL results in Apex.
 * High security priority.
 */
public class ApexSensitiveLoggingRule extends AbstractApexRule {

    private static final Set<String> SENSITIVE_METHODS = Set.of(
        "System.debug", "System.info", "System.warn", "System.error", "System.log"
    );

    public ApexSensitiveLoggingRule() {
        // Set high security priority
        setPriority(RulePriority.HIGH);
    }

    @Override
    protected RuleTargetSelector buildTargetSelector() {
        return RuleTargetSelector.forTypes(ASTUserClass.class);
    }

    @Override
    public Object visit(ASTUserClass node, Object data) {
        // Skip test or system classes
        if (Helper.isTestMethodOrClass(node) || Helper.isSystemLevelClass(node)) {
            return data;
        }

        for (ASTMethodCallExpression call : node.descendants(ASTMethodCallExpression.class)) {
            checkMethodCall(call, data);
        }

        return data;
    }

    private void checkMethodCall(ASTMethodCallExpression call, Object data) {
        String fullMethodName = Helper.getFullMethodName(call);
        if (!SENSITIVE_METHODS.contains(fullMethodName)) {
            return;
        }

        // Iterate over all variable expressions in the arguments
        for (ASTVariableExpression arg : call.descendants(ASTVariableExpression.class)) {
            String varType = arg.getTypeName(); // PMD 7+ uses getTypeName()
            if (isSensitiveType(varType)) {
                asCtx(data).addViolation(arg);
            }
        }
    }

    private boolean isSensitiveType(String typeName) {
        if (typeName == null) return false;
        String lower = typeName.toLowerCase();
        return lower.contains("sobject") || lower.contains("list") || lower.contains("set") || lower.contains("map");
    }
}
