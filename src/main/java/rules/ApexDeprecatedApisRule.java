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
        // Add known deprecated or unsafe Apex methods
        DEPRECATED_METHODS.add("Crypto.generateDigest");           // Weak hash
        DEPRECATED_METHODS.add("Crypto.encryptWithManagedIV");     // Legacy encryption
        DEPRECATED_METHODS.add("Http.send");                        // Old HTTP API
        DEPRECATED_METHODS.add("Database.emptyRecycleBin");        // Can delete sensitive data
        DEPRECATED_METHODS.add("System.enqueueJobLegacy");         // Legacy queueable
        DEPRECATED_METHODS.add("JSON.deserializeUntyped");         // Risky deserialization
        DEPRECATED_METHODS.add("JSON.deserialize");                // If no validation, unsafe
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

        for (ASTMethodCallExpression call : node.descendants(ASTMethodCallExpression.class)) {
            String fullMethod = Helper.getFullMethodName(call);

            if (DEPRECATED_METHODS.contains(fullMethod)) {
                // Add violation with detailed OWASP guidance
                asCtx(data).addViolation(
                    call,
                    "Deprecated or unsafe API used: " + fullMethod +
                    ". Risk: sensitive data exposure or broken access control. " +
                    "Refer to OWASP Top 10 (A1, A3, A6). Consider updating to secure alternatives."
                );
            }
        }
        return data;
    }
}
