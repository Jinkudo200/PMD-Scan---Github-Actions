package rules;

import java.util.List;

import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTLiteralExpression;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;

/**
 * OWASP A08: Insecure Deserialization
 *
 * Flags JSON.deserialize* calls with untrusted input.
 */
public class ApexInsecureDeserializationRule extends AbstractApexRule {

    @Override
    public Object visit(ASTMethodCallExpression node, Object data) {
        String methodName = node.getMethodName();

        if (methodName == null) {
            return super.visit(node, data);
        }

        // Match JSON.deserialize / JSON.deserializeUntyped
        if (methodName.startsWith("deserialize")) {

            // Collect literal arguments
            List<ASTLiteralExpression> literals = node.descendants(ASTLiteralExpression.class).toList();

            boolean hasSafeLiteral = false;
            if (!literals.isEmpty()) {
                ASTLiteralExpression first = literals.get(0);
                if (first.isString() && first.getImage() != null) {
                    hasSafeLiteral = true; // Example: JSON.deserializeUntyped("{\"ok\":1}")
                }
            }

            if (!hasSafeLiteral) {
                asCtx(data).addViolation(node,
                    "OWASP A08 (Insecure Deserialization): Avoid calling " + methodName +
                    " with untrusted input. Validate or sanitize before deserializing.");
            }
        }

        return super.visit(node, data);
    }
}
