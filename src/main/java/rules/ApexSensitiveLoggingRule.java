/*
 * BSD-style license; for more info see http://pmd.sourceforge.net/license.html
 */
package net.sourceforge.pmd.lang.apex.rule.security;

import java.util.Set;
import java.util.HashSet;

import net.sourceforge.pmd.lang.apex.ast.ASTCatchClause;
import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTTryStatement;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTUserClass;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;
import net.sourceforge.pmd.lang.apex.rule.internal.Helper;
import net.sourceforge.pmd.lang.rule.RuleTargetSelector;

/**
 * HIGH priority
 * - Flags System.debug (and other logger) calls that include credential-like variables or literals.
 * - Heuristic: warns if catch blocks around sensitive operations lack logging.
 */
public class ApexSensitiveLoggingRule extends AbstractApexRule {

    private static final Set<String> SENSITIVE_KEYWORDS = Set.of("password", "secret", "token", "apikey", "api_key");

    @Override
    protected RuleTargetSelector buildTargetSelector() {
        return RuleTargetSelector.forTypes(ASTUserClass.class);
    }

    @Override
    public Object visit(ASTUserClass node, Object data) {
        if (Helper.isTestMethodOrClass(node) || Helper.isSystemLevelClass(node)) return data;

        // System.debug / logging misuse
        for (ASTMethodCallExpression call : node.descendants(ASTMethodCallExpression.class)) {
            if ("System".equals(call.getDefiningType()) && "debug".equals(call.getMethodName())) {
                // literal check
                net.sourceforge.pmd.lang.apex.ast.ASTLiteralExpression lit = call.firstChild(net.sourceforge.pmd.lang.apex.ast.ASTLiteralExpression.class);
                if (lit != null && lit.isString()) {
                    String txt = lit.getImage() == null ? "" : lit.getImage().toLowerCase();
                    for (String kw : SENSITIVE_KEYWORDS) {
                        if (txt.contains(kw)) {
                            asCtx(data).addViolation(call);
                            break;
                        }
                    }
                }
                // variable name checks
                for (ASTVariableExpression v : call.descendants(ASTVariableExpression.class)) {
                    String name = v.getImage() == null ? "" : v.getImage().toLowerCase();
                    for (String kw : SENSITIVE_KEYWORDS) {
                        if (name.contains(kw)) {
                            asCtx(data).addViolation(v);
                            break;
                        }
                    }
                }
            }
        }

        // catch blocks missing logging when try contains DML or HttpRequest usages
        for (ASTTryStatement tryStmt : node.descendants(ASTTryStatement.class)) {
            boolean tryHasSensitive = !tryStmt.descendants(net.sourceforge.pmd.lang.apex.ast.ASTDmlStatement.class).toList().isEmpty()
                    || !tryStmt.descendants(ASTMethodCallExpression.class).filter(mc -> "HttpRequest".equals(mc.getDefiningType())).toList().isEmpty();

            if (!tryHasSensitive) continue;

            for (ASTCatchClause cc : tryStmt.children(ASTCatchClause.class)) {
                boolean hasLog = !cc.descendants(ASTMethodCallExpression.class)
                        .filter(mc -> "System".equals(mc.getDefiningType()) && ("debug".equals(mc.getMethodName()) || "error".equals(mc.getMethodName())))
                        .toList().isEmpty();
                if (!hasLog) {
                    asCtx(data).addViolation(cc);
                }
            }
        }

        return data;
    }
}
