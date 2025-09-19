package rules;

import java.util.Set;
import java.util.HashSet;

import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTUserClass;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;
import net.sourceforge.pmd.lang.apex.rule.internal.Helper;
import net.sourceforge.pmd.lang.rule.RuleTargetSelector;

/**
 * MEDIUM priority rule
 * Detects usage of deprecated or unsafe APIs that can lead to:
 * - Broken access control
 * - Sensitive data exposure
 * - Use of vulnerable/unsupported components
 *
 * Aligns with OWASP Top 10: A1 (Broken Access Control), A3 (Sensitive Data Exposure), A6 (Vulnerable Components)
 */
public class ApexDeprecatedApisRule extends AbstractApexRule {

    private static final Set<String> DEPRECATED_METHODS = new HashSet<>();

    static {
        // Add known deprecated or unsafe Apex methods
        DEPRECATED_METHODS.add("Crypto.generateDigest");           // Weak hash
        DEPRECATED_METHODS.add("Crypto.encryptWithManagedIV");     // Legacy encryption
        DEPRECATED_METHODS.add("Http.send");                        // Old HTTP API
        DEPRECATED_METHODS.add("Database.emptyRecycleBin");        // Can delete sensitive data
        DEPRECATED_METHODS.add("System.enqueueJobLegacy");         // Legacy queueable
        DEPRECATED_METHODS.add("JSON.deserializeUntyped");         // Risky deserialization
        DEPRECATED_METHODS.add("JSON.deserialize");                // Unsafe if no validation
    }

    public ApexDeprecatedApisRule() {
        setPriority(net.sourceforge.pmd.lang.rule.RulePriority.MEDIUM);
    }

    @Override
    protected RuleTargetSelector buildTargetSelector() {
        return RuleTargetSelector.forTypes(ASTUserClass.class);
    }

    @Override
    public Object visit(ASTUserClass node, Object data) {
        // Skip test classes
        if (Helper.isTestMethodOrClass(node) || Helper.isSystemLevelClass(node)) {
            return data;
        }

        // Iterate over all method calls in the class
        for (ASTMethodCallExpression call : node.descendants(ASTMethodCallExpression.class)) {
            String methodName = call.getMethodName();
            String definingType = call.getDefiningType() != null ? call.getDefiningType() : "";

            // Build full method identifier
            String fullMethod = definingType.isEmpty() ? methodName : definingType + "." + methodName;

            // Lowercase for robust comparison
            String fullMethodLower = fullMethod.toLowerCase();
            String methodLower = methodName != null ? methodName.toLowerCase() : "";

            for (String deprecated : DEPRECATED_METHODS) {
                String depLower = deprecated.toLowerCase();

                if (depLower.equals(fullMethodLower) || depLower.equals(methodLower)) {
                    asCtx(data).addViolation(
                        call,
                        "Deprecated or unsafe API used: " + fullMethod +
                        ". Risk: sensitive data exposure or broken access control. " +
                        "Refer to OWASP Top 10 (A1, A3, A6). Consider updating to secure alternatives."
                    );
                    break;
                }
            }
        }

        return data;
    }
}
