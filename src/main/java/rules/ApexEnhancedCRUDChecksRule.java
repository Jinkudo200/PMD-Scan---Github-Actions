/*
 * BSD-style license; for more info see http://pmd.sourceforge.net/license.html
 */
package rules;

import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTSoqlExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTUserClass;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;
import net.sourceforge.pmd.lang.rule.RuleTargetSelector;
import net.sourceforge.pmd.lang.apex.rule.internal.Helper;
import java.util.Locale;

/**
 * MEDIUM priority
 * Complements built-in ApexCRUDViolationRule:
 * - encourages use of WITH SECURITY_ENFORCED on SOQL
 * - encourages checks like Schema.sObjectType.MyObject.isAccessible or explicit authorization calls before DML
 * This rule is intentionally gentle: it flags SOQL without WITH SECURITY_ENFORCED and DMLs without preceding obvious checks.
 */
public class ApexEnhancedCRUDChecksRule extends AbstractApexRule {

    @Override
    protected RuleTargetSelector buildTargetSelector() {
        return RuleTargetSelector.forTypes(ASTUserClass.class);
    }

    @Override
    public Object visit(ASTUserClass node, Object data) {
        if (Helper.isTestMethodOrClass(node) || Helper.isSystemLevelClass(node)) {
            return data;
        }

        // SOQL lacking WITH SECURITY_ENFORCED
        for (ASTSoqlExpression soql : node.descendants(ASTSoqlExpression.class)) {
            String q = soql.getQuery() == null ? "" : soql.getQuery();
            if (!q.toUpperCase(Locale.ROOT).contains("WITH SECURITY_ENFORCED")) {
                asCtx(data).addViolation(soql);
            }
        }

        // DML without trivial preceding checks - heuristic
        for (ASTMethodCallExpression dml : node.descendants(ASTMethodCallExpression.class)) {
            // if there is no Schema.sObjectType.<X>.isCreateable/isUpdateable call earlier in method - warn
            ASTMethodCallExpression prev = dml.ancestors(net.sourceforge.pmd.lang.apex.ast.ASTMethod.class).first()
                    .descendants(ASTMethodCallExpression.class)
                    .filter(mc -> mc.getImage() != null && mc.getImage().toLowerCase(Locale.ROOT).contains("iscreateable"))
                    .first();
            if (prev == null) {
                asCtx(data).addViolation(dml);
            }
        }

        return data;
    }
}
