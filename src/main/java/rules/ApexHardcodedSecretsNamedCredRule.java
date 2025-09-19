/*
 * BSD-style license; for more info see http://pmd.sourceforge.net/license.html
 */
package net.sourceforge.pmd.lang.apex.rule.security;

import java.util.Set;
import java.util.regex.Pattern;

import java.util.HashSet;
import net.sourceforge.pmd.lang.apex.ast.ASTFieldDeclaration;
import net.sourceforge.pmd.lang.apex.ast.ASTLiteralExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTUserClass;
import net.sourceforge.pmd.lang.apex.ast.ApexNode;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;
import net.sourceforge.pmd.lang.apex.rule.internal.Helper;
import net.sourceforge.pmd.lang.rule.RuleTargetSelector;

/**
 * HIGH priority
 * Detects:
 *  - suspicious long string literals (look like tokens)
 *  - fields/vars whose names contain SECRET/KEY/PASSWORD
 *  - HttpRequest.setEndpoint called with literal HTTP(S) URL instead of "callout:Named_Credential"
 */
public class ApexHardcodedSecretsNamedCredRule extends AbstractApexRule {

    private static final Pattern SUSPICIOUS_KEY = Pattern.compile("[A-Za-z0-9\\-_]{20,}");
    private static final Set<String> KEYWORDS = Set.of("apikey", "api_key", "secret", "password", "token", "clientsecret");

    private final Set<String> suspiciousVars = new HashSet<>();

    @Override
    protected RuleTargetSelector buildTargetSelector() {
        return RuleTargetSelector.forTypes(ASTUserClass.class);
    }

    @Override
    public Object visit(ASTUserClass node, Object data) {
        if (Helper.isTestMethodOrClass(node) || Helper.isSystemLevelClass(node)) return data;

        // literals and fields
        for (ASTLiteralExpression lit : node.descendants(ASTLiteralExpression.class)) {
            if (!lit.isString()) continue;
            String raw = lit.getImage() == null ? "" : lit.getImage().replaceAll("^['\"]|['\"]$", "");
            if (SUSPICIOUS_KEY.matcher(raw).find()) {
                asCtx(data).addViolation(lit);
            } else {
                // check context var/field name
                ASTVariableExpression var = lit.ancestors(ASTVariableExpression.class).first();
                if (var != null) {
                    String varName = var.getImage() == null ? "" : var.getImage().toLowerCase();
                    for (String kw : KEYWORDS) {
                        if (varName.contains(kw) || raw.toLowerCase().contains(kw)) {
                            asCtx(data).addViolation(lit);
                            break;
                        }
                    }
                }
            }
        }

        // HttpRequest.setEndpoint checks
        for (ASTMethodCallExpression call : node.descendants(ASTMethodCallExpression.class)) {
            if ("HttpRequest".equals(call.getDefiningType()) && "setEndpoint".equals(call.getMethodName())) {
                ASTLiteralExpression lit = call.firstChild(ASTLiteralExpression.class);
                if (lit != null && lit.isString()) {
                    String val = lit.getImage() == null ? "" : lit.getImage().toLowerCase();
                    if ((val.startsWith("'http") || val.startsWith("\"http")) && !val.contains("callout:")) {
                        asCtx(data).addViolation(call);
                    }
                } else if (call.hasDescendantOfType(net.sourceforge.pmd.lang.apex.ast.ASTBinaryExpression.class)) {
                    asCtx(data).addViolation(call);
                }
            }
        }

        return data;
    }
}
