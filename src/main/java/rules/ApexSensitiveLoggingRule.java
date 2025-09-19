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
        // Only visit method call expressions inside classes
        return RuleTargetSelector.forTypes(ASTUserClass.class);
    }

    @Override
    public Object visit(ASTUserClass node, Object data) {

        for (ASTMethodCallExpression call : node.findDescendantsOfType(ASTMethodCallExpression.class)) {
            processMethodCall(call, data);
        }

        return data;
    }

    private void processMethodCall(ASTMethodCallExpression call, Object data) {
        String fullMethodName = call.getFullMethodName();

        // Check System.debug or custom logging methods
        if ("System.debug".equals(fullMethodName) || fullMethodName.endsWith(".log")) {

            // Check all arguments passed to the method
            List<ASTVariableExpression> args = call.findDescendantsOfType(ASTVariableExpression.class);
            for (ASTVariableExpression arg : args) {
                // Detect if argument looks like a sensitive object
                String varName = arg.getImage();
                if (isSensitiveVariable(varName)) {
                    asCtx(data).addViolation(arg);
                }
            }
        }
    }

    /**
     * Simple heuristic for sensitive variables.
     * In a more advanced rule, you can enhance this by type inference.
     */
    private boolean isSensitiveVariable(String varName) {
        String lower = varName.toLowerCase();
        return lower.contains("password") || lower.contains("secret") || lower.contains("token") ||
               lower.contains("creditcard") || lower.contains("sobject") || lower.contains("dml");
    }
}
