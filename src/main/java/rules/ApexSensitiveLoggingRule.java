package rules;

import java.util.List;

import net.sourceforge.pmd.lang.apex.ast.ASTMethod;
import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTUserClass;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;
import net.sourceforge.pmd.lang.apex.rule.internal.Helper;
import net.sourceforge.pmd.lang.rule.RulePriority;
import net.sourceforge.pmd.lang.rule.RuleTargetSelector;

public class ApexSensitiveLoggingRule extends AbstractApexRule {

    public ApexSensitiveLoggingRule() {
        setPriority(RulePriority.HIGH); // High priority for security
    }

    @Override
    protected RuleTargetSelector buildTargetSelector() {
        return RuleTargetSelector.forTypes(ASTUserClass.class);
    }

    @Override
    public Object visit(ASTUserClass node, Object data) {

        for (ASTMethod m : node.descendants(ASTMethod.class)) {

            // Look for calls to any logging method
            for (ASTMethodCallExpression call : m.descendants(ASTMethodCallExpression.class)) {
                String methodName = call.getMethodName();
                if (methodName != null && methodName.toLowerCase().contains("log")) {

                    // Check all arguments of the log call
                    call.getArguments().forEach(arg -> {
                        for (ASTVariableExpression var : arg.descendants(ASTVariableExpression.class).toList()) {
                            // In PMD 7+, just flag all variables in logging calls
                            asCtx(data).addViolation(var);
                        }
                    });
                }
            }
        }

        return data;
    }
}
