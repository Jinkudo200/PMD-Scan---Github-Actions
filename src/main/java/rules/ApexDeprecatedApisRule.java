package rules;

import java.util.Arrays;
import java.util.List;

import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTUserClass;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;
import net.sourceforge.pmd.lang.rule.RulePriority;
import net.sourceforge.pmd.lang.rule.RuleTargetSelector;
import net.sourceforge.pmd.lang.apex.rule.internal.Helper;

/**
 * MEDIUM priority
 * Detects usage of deprecated or discouraged Apex/Platform APIs
 * (e.g., old SOAP APIs, insecure crypto methods, outdated HTTP libraries)
 * OWASP relevance: outdated/insecure APIs can contribute to A6:2021 – Vulnerable & Outdated Components
 */
public class ApexDeprecatedApisRule extends AbstractApexRule {

    // List of method names considered deprecated or insecure
    private static final List<String> DEPRECATED_METHODS = Arrays.asList(
        "Crypto.generateDigest",  // example: weak hashing
        "Crypto.encryptWithManagedIV", // outdated
        "Http.send",              // old synchronous send (could encourage poor practices)
        "Database.emptyRecycleBin", // discouraged
        "System.enqueueJobLegacy" // hypothetical old API
    );

    public ApexDeprecatedApisRule() {
        setPriority(RulePriority.MEDIUM);
    }

    @Override
    protected RuleTargetSelector buildTargetSelector() {
        return RuleTargetSelector.forTypes(ASTUserClass.class);
    }

    @Override
    public Object visit(ASTUserClass node, Object data) {

        // Ignore test classes and system classes
        if (Helper.isTestMethodOrClass(node) || Helper.isSystemLevelClass(node)) {
            return data;
        }

        // Scan all method calls in the class
        for (ASTMethodCallExpression call : node.descendants(ASTMethodCallExpression.class)) {
            String methodName = call.getMethodName();
            if (methodName != null && DEPRECATED_METHODS.contains(methodName)) {
                addViolationWithMessage(data, call,
                        "Use of deprecated or insecure API '" + methodName + "' detected. Consider updating to a secure alternative.");
            }
        }

        return data;
    }
}
