/*
 * BSD-style license; for more info see http://pmd.sourceforge.net/license.html
 */

package rules;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import net.sourceforge.pmd.lang.apex.ast.ASTAssignmentExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTLiteralExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTUserClass;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableDeclaration;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;
import net.sourceforge.pmd.lang.rule.RulePriority;

/**
 * Detects hardcoded secrets and endpoints that should use Named Credentials.
 */
public class ApexHardcodedSecretsNamedCredRule extends AbstractApexRule {

    private final Set<String> trackedSecrets = new HashSet<>();

    public ApexHardcodedSecretsNamedCredRule() {
        // Set a high priority for security-critical issues
        setPriority(RulePriority.HIGH);
        setName("ApexHardcodedSecretsNamedCredRule");
        setMessage("Hardcoded secret or endpoint detected. Use Named Credentials instead.");
    }

    @Override
    public Object visit(ASTUserClass node, Object data) {

        // 1️⃣ Track hardcoded secrets in variable declarations
        for (ASTVariableDeclaration varDecl : node.descendants(ASTVariableDeclaration.class).toList()) {
            ASTLiteralExpression literal = varDecl.firstChild(ASTLiteralExpression.class);
            ASTVariableExpression var = varDecl.firstChild(ASTVariableExpression.class);

            if (literal != null && var != null && looksLikeSecret(literal.getImage())) {
                trackedSecrets.add(var.getImage());
                asCtx(data).addViolation(literal, "Hardcoded secret in variable declaration detected.");
            }
        }

        // 2️⃣ Track hardcoded secrets in assignments
        for (ASTAssignmentExpression assign : node.descendants(ASTAssignmentExpression.class).toList()) {
            ASTVariableExpression left = assign.firstChild(ASTVariableExpression.class);
            ASTLiteralExpression rightLiteral = assign.firstChild(ASTLiteralExpression.class);

            if (left != null && rightLiteral != null && looksLikeSecret(rightLiteral.getImage())) {
                trackedSecrets.add(left.getImage());
                asCtx(data).addViolation(rightLiteral, "Hardcoded secret in assignment detected.");
            }
        }

        // 3️⃣ Check method calls like setEndpoint or setHeader
        for (ASTMethodCallExpression call : node.descendants(ASTMethodCallExpression.class).toList()) {
            String methodName = call.getMethodName();

            // Check endpoints
            if ("setEndpoint".equals(methodName)) {
                ASTLiteralExpression literal = call.firstChild(ASTLiteralExpression.class);
                ASTVariableExpression var = call.firstChild(ASTVariableExpression.class);
                checkEndpoint(literal, var, data);
            }

            // Check headers for hardcoded secrets
            if ("setHeader".equals(methodName)) {
                List<ASTLiteralExpression> literals = call.descendants(ASTLiteralExpression.class).toList();
                List<ASTVariableExpression> vars = call.descendants(ASTVariableExpression.class).toList();
                checkHeader(literals, vars, data);
            }
        }

        return data;
    }

    private void checkEndpoint(ASTLiteralExpression literal, ASTVariableExpression var, Object data) {
        if (literal != null) {
            if (!isNamedCredential(literal) || looksLikeSecret(literal.getImage())) {
                asCtx(data).addViolation(literal, "Hardcoded endpoint or secret detected. Use Named Credential.");
            }
        }

        if (var != null && trackedSecrets.contains(var.getImage())) {
            asCtx(data).addViolation(var, "Variable used in endpoint contains a hardcoded secret.");
        }
    }

    private void checkHeader(List<ASTLiteralExpression> literals, List<ASTVariableExpression> vars, Object data) {
        for (ASTLiteralExpression lit : literals) {
            if (looksLikeSecret(lit.getImage())) {
                asCtx(data).addViolation(lit, "Hardcoded secret in HTTP header detected.");
            }
        }

        for (ASTVariableExpression var : vars) {
            if (trackedSecrets.contains(var.getImage())) {
                asCtx(data).addViolation(var, "Variable used in header contains a hardcoded secret.");
            }
        }
    }

    /**
     * Very basic heuristic for secrets. Can be extended.
     */
    private boolean looksLikeSecret(String value) {
        if (value == null) return false;
        String trimmed = value.trim();
        return trimmed.length() > 5 && (trimmed.matches(".*\\d.*") || trimmed.matches(".*[A-Za-z]{5,}.*"));
    }

    private boolean isNamedCredential(ASTLiteralExpression literal) {
        if (literal == null) return false;
        return literal.getImage().startsWith("callout:");
    }
}
