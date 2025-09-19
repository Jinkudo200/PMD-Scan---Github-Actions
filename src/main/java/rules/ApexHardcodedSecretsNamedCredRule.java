/*
 * BSD-style license; for more info see http://pmd.sourceforge.net/license.html
 */

package rules;

import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTBinaryExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTUserClass;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;
import net.sourceforge.pmd.lang.apex.rule.internal.Helper;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.util.List;

public class ApexHardcodedSecretsNamedCredRule extends AbstractApexRule {

    public ApexHardcodedSecretsNamedCredRule() {
        setName("ApexHardcodedSecretsNamedCredRule");
        setDescription("Detect hardcoded secrets that should use Named Credentials");
        setMessage("Avoid hardcoding secrets, use Named Credentials instead.");
        setPriority(net.sourceforge.pmd.lang.rule.RulePriority.HIGH);
    }

    @Override
    protected @NonNull net.sourceforge.pmd.lang.rule.RuleTargetSelector buildTargetSelector() {
        return net.sourceforge.pmd.lang.rule.RuleTargetSelector.forTypes(ASTUserClass.class);
    }

    @Override
    public Object visit(ASTUserClass node, Object data) {

        // Skip test classes
        if (Helper.isTestMethodOrClass(node) || Helper.isSystemLevelClass(node)) {
            return data;
        }

        // Find all method calls in the class
        for (ASTMethodCallExpression call : node.descendants(ASTMethodCallExpression.class).toList()) {

            String fullMethodName = call.getFullMethodName();

            // Detect problematic methods
            if ("HttpRequest.setHeader".equalsIgnoreCase(fullMethodName) ||
                "HttpRequest.setEndpoint".equalsIgnoreCase(fullMethodName)) {

                // Check for string literals or variables
                List<ASTVariableExpression> args = call.descendants(ASTVariableExpression.class).toList();

                for (ASTVariableExpression arg : args) {
                    String argName = arg.getImage();
                    if (argName != null && !argName.isEmpty()) {
                        // Flag the variable
                        asCtx(data).addViolation(arg);
                    }
                }

                // Also detect binary expressions in arguments (concatenated strings)
                if (!call.descendants(ASTBinaryExpression.class).toList().isEmpty()) {
                    asCtx(data).addViolation(call);
                }
            }
        }

        return data;
    }
}
