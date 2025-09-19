package rules;

import java.util.HashSet;
import java.util.Set;

import net.sourceforge.pmd.lang.apex.ast.*;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;
import net.sourceforge.pmd.lang.apex.rule.internal.Helper;
import net.sourceforge.pmd.lang.rule.RuleTargetSelector;

public class ApexCommandScheduleInjectionRule extends AbstractApexRule {

    private final Set<String> safeVars = new HashSet<>();

    public ApexCommandScheduleInjectionRule() {
        setPriority(2); // High
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
                String name = call.getMethodName();
                if (name != null && (name.equalsIgnoreCase("System.schedule") || name.equalsIgnoreCase("System.enqueueJob"))) {
                    for (ASTVariableExpression var : call.descendants(ASTVariableExpression.class).toList()) {
                        String fq = Helper.getFQVariableName(var);
                        if (!safeVars.contains(fq)) {
                            asCtx(data).addViolation(var);
                        }
                    }
                }
            }
        }

        safeVars.clear();
        return data;
    }
}
