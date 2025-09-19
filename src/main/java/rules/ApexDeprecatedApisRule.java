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
 * Aligns with OWASP Top 10: A1, A3, A6
 */
public class ApexDeprecatedApisRule extends AbstractApexRule {

    private static final Set<String> DEPRECATED_METHODS = new HashSet<>();

    static {
        // Known deprecated or unsafe Apex methods
        DEPRECATED_METHODS.add("generateDigest");           // Weak hash
        DEPRECATED_METHODS.add("encryptWithManagedIV");     // Legacy encryption
        DEPRECATED_METHODS.add("send");                     // Deprecated HTTP
        DEPRECATED_METHODS.add("emptyRecycleBin");          // Can delete sensitive data
        DEPRECATED_METHODS.add("enqueueJobLegacy");         // Legacy queueable
        DEPRECATED_METHODS.add("deserializeUntyped");       // Unsafe deserialization
        DEPRECATED_METHODS.add("deserialize");              // Unsafe if no validation
    }

    public ApexDeprecatedApisRule() {
        // Medium priority
        setPriority(RulePriority.MEDIUM);
    }

    @Override
    protected RuleTargetSelector buildTargetSelector() {
        return RuleTargetSelector.forTypes(ASTUserClass.class);
    }

    @Override
    public Object visit(ASTUserClass node, Object data) {
        // Skip test classes and system-level classes
        if (Helper.isTestMethodOrClass(node) || Helper.isSystemLevelClass(node)) {
            return data;
        }

        for (ASTMethodCallExpression call : node.descendants(ASTMethodCallExpression.class)) {
            String methodName = call.getMethodName() != null ? call.getMethodName() : "";
            String image = call.getImage() != null ? call.getImage() : "";

            for (String deprecated : DEPRECATED_METHODS) {
                // Match on method name or image text
                if (methodName.equalsIgnoreCase(deprecated) || image.contains(deprecated)) {
                    asCtx(data).addViolation(
                        call,
                        "Deprecated or unsafe API used: " + (image.isEmpty() ? methodName : image) +
                        ". Risk: sensitive data exposure or broken access control. " +
                        "Refer to OWASP Top 10 (A1, A3, A6). Update to secure alternatives."
                    );
                    break;
                }
            }
        }
        return data;
    }
}
