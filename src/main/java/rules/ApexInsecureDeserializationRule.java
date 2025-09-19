package rules;

import java.util.List;

import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTLiteralExpression;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;

/**
 * OWASP A08: Insecure Deserialization
 *
 * This rule flags:
 *   - Any use of JSON.deserialize / JSON.deserializeUntyped with untrusted input
 *   - Inputs from RestContext.request, HttpRequest.getBody(), method params, or variables
 *
 * Safe patterns:
 *   - Deserializing a constant trusted literal (e.g., hardcoded JSON for testing)
 *
 * Risk:
 *   Attackers can inject malicious objects or payloads that compromise integrity,
 *   leading to remote code execution or privilege escalation.
 */
public class ApexInsecureDeserializationRule extends AbstractApexRule {

    @Override
    public Object visit(ASTMethodCallExpression node, Object data) {

        String fullName = node.getFullMethodName();

        // Only interested in JSON.deserialize* methods
        if (fullName == null) {
            return super.visit(node, data);
        }

        if (fullName.equalsIgnoreCase("JSON.deserialize")
         || fullName.equalsIgnoreCase("JSON.deserializeUntyped")) {

            // Must have at least 1 argument
            if (node.getArity() > 0) {
                boolean isSafeLiteral = false;

                // Check if the first argument is a constant string literal
                List<ASTLiteralExpression> literals = node.findDescendantsOfType(ASTLiteralExpression.class);
                if (!literals.isEmpty()) {
                    ASTLiteralExpression first = literals.get(0);
                    if (first != null && first.isStringLiteral()) {
                        isSafeLiteral = true; // Example: JSON.deserializeUntyped("{\"ok\":1}")
                    }
                }

                // Flag only if NOT a safe literal (variables, params, req.getBody, etc.)
                if (!isSafeLiteral) {
                    addViolationWithMessage(data, node,
                        "OWASP A08 (Insecure Deserialization): Avoid deserializing untrusted input with "
                        + fullName +
                        ". Always validate or sanitize data before use.");
                }
            }
        }

        return super.visit(node, data);
    }
}
