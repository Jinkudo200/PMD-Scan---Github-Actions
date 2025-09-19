/*
 * BSD-style license; for more info see http://pmd.sourceforge.net/license.html
 */

package rules;

import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTUserClass;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;
import net.sourceforge.pmd.lang.apex.rule.internal.Helper;
import net.sourceforge.pmd.lang.rule.RulePriority;
import net.sourceforge.pmd.lang.rule.RuleTargetSelector;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Detects logging of sensitive data (e.g., DML objects, passwords, secrets)
 * via System.debug or custom logging calls.
 */
public class ApexSensitiveLoggingRule extends AbstractApexRule {

    public ApexSensitiveLoggingRule() {
        setName("ApexSensitiveLoggingRule");
        setPriority(RulePriority.HIGH); // High priority for security
    }

    @Override
    protected RuleTargetSelector buildTargetSelector() {
        return RuleTargetSelector.forTypes(ASTUserClass.class);
    }

    @Override
    public Object visit(ASTUserClass node, Object data) {

        // Use descendants() and filter manually
        List<ASTMethodCallExpression> methodCalls = node.descendants(ASTMethodCallExpression.class).toList();
        for (ASTMethodCallExpression call : methodCalls) {
            processMethodCall(call, data);
        }

        return data;
    }

    private void processMethodCall(ASTMethodCallExpression call, Object data) {
        String fullMethodName = call.getFullMethodName();

        if ("System.debug".equals(fullMethodName) || fullMethodName.endsWith(".log")) {

            // Collect all variable expressions inside the call
            List<ASTVariableExpression> args = call.descendants(ASTVariableExpression.class).toList();
            for (ASTVariableExpression arg : args) {
                String varName = arg.getImage();
                if (isSensitiveVariable(varName)) {
                    asCtx(data).addViolation(arg);
                }
            }
        }
    }

    private boolean isSensitiveVariable(String varName) {
        String lower = varName.toLowerCase();
        return lower.contains("password") || lower.contains("secret") || lower.contains("token") ||
               lower.contains("creditcard") || lower.contains("sobject") || lower.contains("dml");
    }
}
