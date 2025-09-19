/*
 * BSD-style license; for more info see http://pmd.sourceforge.net/license.html
 */

package rules;

import net.sourceforge.pmd.lang.apex.ast.*;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;
import net.sourceforge.pmd.lang.rule.RuleTargetSelector;
import net.sourceforge.pmd.lang.apex.rule.internal.Helper;

import java.util.*;
import java.util.regex.Pattern;

public class ApexHardcodedSecretsNamedCredRule extends AbstractApexRule {

    // Sensitive header names to flag
    private static final Set<String> SENSITIVE_HEADERS = Set.of(
            "Authorization", "Api-Key", "X-API-KEY", "Bearer"
    );

    // Regex for detecting likely secrets
    private static final Pattern SECRET_PATTERN = Pattern.compile(
            ".*(password|secret|token|apikey|bearer).*", Pattern.CASE_INSENSITIVE
    );

    // Track variables that contain hardcoded secrets
    private final Set<String> trackedSecrets = new HashSet<>();

    public ApexHardcodedSecretsNamedCredRule() {
        setName("ApexHardcodedSecretsNamedCredRule");
        setPriority(net.sourceforge.pmd.lang.rule.RulePriority.HIGH);
    }

    @Override
    protected RuleTargetSelector buildTargetSelector() {
        return RuleTargetSelector.forTypes(ASTUserClass.class);
    }

    @Override
    public Object visit(ASTUserClass node, Object data) {

        // Track variable assignments for literals that look like secrets
        for (ASTVariableDeclaration varDecl : node.findDescendantsOfType(ASTVariableDeclaration.class)) {
            ASTLiteralExpression literal = varDecl.firstChild(ASTLiteralExpression.class);
            ASTVariableExpression var = varDecl.firstChild(ASTVariableExpression.class);

            if (literal != null && var != null && looksLikeSecret(literal.getImage())) {
                trackedSecrets.add(var.getImage());
            }
        }

        // Track assignment expressions
        for (ASTAssignmentExpression assign : node.findDescendantsOfType(ASTAssignmentExpression.class)) {
            ASTVariableExpression left = assign.firstChild(ASTVariableExpression.class);
            ASTLiteralExpression rightLiteral = assign.firstChild(ASTLiteralExpression.class);
            if (left != null && rightLiteral != null && looksLikeSecret(rightLiteral.getImage())) {
                trackedSecrets.add(left.getImage());
            }
        }

        // Check all method calls
        for (ASTMethodCallExpression call : node.findDescendantsOfType(ASTMethodCallExpression.class)) {
            String methodName = call.getMethodName();

            if ("setEndpoint".equals(methodName)) {
                checkEndpoint(call, data);
            }

            if ("setHeader".equals(methodName)) {
                checkHeader(call, data);
            }
        }

        trackedSecrets.clear(); // reset after class processed
        return data;
    }

    private void checkEndpoint(ASTMethodCallExpression call, Object data) {
        ASTLiteralExpression literal = call.firstChild(ASTLiteralExpression.class);
        ASTVariableExpression var = call.firstChild(ASTVariableExpression.class);

        // Literal endpoint
        if (literal != null) {
            String endpoint = literal.getImage();
            if (!isNamedCredential(endpoint) || looksLikeSecret(endpoint)) {
                asCtx(data).addViolation(literal, "Hardcoded endpoint or secret detected. Use Named Credential.");
            }
        }

        // Variable endpoint
        if (var != null && trackedSecrets.contains(var.getImage())) {
            asCtx(data).addViolation(var, "Variable used in endpoint contains a hardcoded secret.");
        }
    }

    private void checkHeader(ASTMethodCallExpression call, Object data) {
        List<ASTLiteralExpression> literals = call.findDescendantsOfType(ASTLiteralExpression.class);
        List<ASTVariableExpression> vars = call.findDescendantsOfType(ASTVariableExpression.class);

        // Check header name and value
        if (!literals.isEmpty()) {
            String headerName = literals.get(0).getImage();
            if (SENSITIVE_HEADERS.contains(headerName)) {
                if (literals.size() > 1 && looksLikeSecret(literals.get(1).getImage())) {
                    asCtx(data).addViolation(literals.get(1), "Hardcoded sensitive header value detected.");
                }
            }
        }

        // Check variables used as header value
        for (ASTVariableExpression var : vars) {
            if (trackedSecrets.contains(var.getImage())) {
                asCtx(data).addViolation(var, "Variable used as sensitive header contains a hardcoded secret.");
            }
        }
    }

    private boolean looksLikeSecret(String value) {
        if (value == null || value.isEmpty()) return false;
        return SECRET_PATTERN.matcher(value).matches();
    }

    private boolean isNamedCredential(ASTLiteralExpression literal) {
        if (literal == null) return false;
        return literal.getImage().startsWith("callout:");
    }
}
