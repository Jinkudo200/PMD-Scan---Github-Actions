/*
 * BSD-style license; for more info see http://pmd.sourceforge.net/license.html
 */

package rules;

import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTUserClass;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;
import net.sourceforge.pmd.lang.rule.RuleTargetSelector;
import net.sourceforge.pmd.lang.apex.rule.internal.Helper;

public class ApexHardcodedSecretsNamedCredRule extends AbstractApexRule {

    public ApexHardcodedSecretsNamedCredRule() {
        setName("ApexHardcodedSecretsNamedCredRule");
        setMessage("Avoid hardcoding secrets; use Named Credentials instead.");
        setPriority(net.sourceforge.pmd.lang.rule.RulePriority.HIGH);
    }

    @Override
    protected RuleTargetSelector buildTargetSelector() {
        return RuleTargetSelector.forTypes(ASTUserClass.class);
    }

    @Override
    public Object visit(ASTUserClass node, Object data) {

        for (ASTMethodCallExpression call : node.descendants(ASTMethodCallExpression.class)) {

            // Only analyze certain method calls like HTTP request setEndpoint or setHeader
            String fullMethodName = call.getFullMethodName();
            if ("HTTPRequest.setEndpoint".equals(fullMethodName) ||
                "HTTPRequest.setHeader".equals(fullMethodName)) {

                // Check for literals (hardcoded secrets)
                if (call.firstChildOrNull(net.sourceforge.pmd.lang.apex.ast.ASTLiteralExpression.class) != null) {
                    asCtx(data).addViolation(call);
                }

                // Check for binary expressions (concatenated strings)
                else if (call.firstChildOrNull(net.sourceforge.pmd.lang.apex.ast.ASTBinaryExpression.class) != null) {
                    asCtx(data).addViolation(call);
                }

            }
        }

        return data;
    }
}
