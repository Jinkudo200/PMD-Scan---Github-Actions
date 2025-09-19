/*
 * BSD-style license; for more info see http://pmd.sourceforge.net/license.html
 */

package rules;

import net.sourceforge.pmd.RuleContext;
import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableDeclaration;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;
import net.sourceforge.pmd.lang.rule.RuleTargetSelector;
import net.sourceforge.pmd.lang.rule.properties.PropertyDescriptor;
import net.sourceforge.pmd.lang.rule.properties.StringProperty;
import net.sourceforge.pmd.lang.rule.RulePriority;

import java.util.List;
import java.util.Set;
import java.util.HashSet;

public class ApexSensitiveLoggingRule extends AbstractApexRule {

    private static final Set<String> SENSITIVE_METHODS = new HashSet<>(Set.of(
            "System.debug",
            "System.info",
            "System.warn",
            "System.error",
            "LoggingService.log" // add custom logging calls if needed
    ));

    public ApexSensitiveLoggingRule() {
        setRuleName("ApexSensitiveLoggingRule");
        setPriority(RulePriority.HIGH); // PMD 7+
    }

    @Override
    protected RuleTargetSelector buildTargetSelector() {
        return RuleTargetSelector.forTypes(ASTMethodCallExpression.class);
    }

    @Override
    public Object visit(ASTMethodCallExpression node, Object data) {
        String fullMethodName = node.getFullMethodName();

        if (SENSITIVE_METHODS.contains(fullMethodName)) {
            // Check child nodes for variables passed to the logging call
            List<ASTVariableExpression> vars = node.findDescendantsOfType(ASTVariableExpression.class);

            for (ASTVariableExpression var : vars) {
                // Report the variable being logged
                asCtx(data).addViolation(var);
            }
        }

        return data;
    }
}
