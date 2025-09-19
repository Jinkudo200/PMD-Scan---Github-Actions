package rules;

import java.util.HashSet;
import java.util.Set;

import net.sourceforge.pmd.lang.apex.ast.*;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;
import net.sourceforge.pmd.lang.apex.rule.internal.Helper;
import net.sourceforge.pmd.lang.rule.RuleTargetSelector;

public class ApexTaintSoqlRule extends AbstractApexRule {

    private final Set<String> safeVars = new HashSet<>();

    public ApexTaintSoqlRule() {
        setPriority(2);
    }

    @Override
    protected RuleTargetSelector buildTargetSelector() {
        return RuleTargetSelector.forTypes(ASTUserClass.class);
    }

    @Override
    public Object visit(ASTUserClass node, Object data) {

        for (ASTMethod m : node.descendants(ASTMethod.class)) {

            for (ASTParameter p : m.children(ASTParameter.class)) {
                safeVars.add(Helper.getFQVariableName(p));
            }

            for (ASTMethodCallExpression call : m.descendants(ASTMethodCallExpression.class)) {
                if (call.getMethodName() != null && call.getMethodName().equalsIgnoreCase("Database.query")) {
                    for (ASTVariableExpression var : call.descendants(ASTVariableExpression.class).toList()) {
                        String fq = Helper.getFQVariableName(var);
                        if (!safeVars.contains(fq)) {
                            asCtx(data).addViolation(var);
                        }
                    }
                }
            }
        }

        return data;
    }
}
