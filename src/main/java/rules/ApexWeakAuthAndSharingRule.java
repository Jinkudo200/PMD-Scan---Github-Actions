package rules;

import net.sourceforge.pmd.lang.apex.ast.*;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;
import net.sourceforge.pmd.lang.rule.RulePriority;
import net.sourceforge.pmd.lang.rule.RuleTargetSelector;

public class ApexWeakAuthAndSharingRule extends AbstractApexRule {

    public ApexWeakAuthAndSharingRule() {
        setPriority(RulePriority.MEDIUM);
    }

    @Override
    protected RuleTargetSelector buildTargetSelector() {
        return RuleTargetSelector.forTypes(ASTUserClass.class);
    }

    @Override
    public Object visit(ASTUserClass node, Object data) {
        boolean withSharing = node.getImage() != null && node.getImage().contains("with sharing");

        for (ASTMethod method : node.descendants(ASTMethod.class)) {

            // Skip test methods (look for @IsTest annotation)
            boolean isTest = false;
            for (ASTAnnotation ann : method.descendants(ASTAnnotation.class)) {
                String annName = ann.getImage() == null ? "" : ann.getImage().toLowerCase();
                if (annName.equals("istest")) {
                    isTest = true;
                    break;
                }
            }
            if (isTest) continue;

            // Detect method visibility modifiers
            boolean isPublic = false;
            boolean isGlobal = false;
            for (ASTModifier mod : method.descendants(ASTModifier.class)) {
                String modName = mod.getImage() == null ? "" : mod.getImage().toLowerCase();
                if (modName.equals("public")) isPublic = true;
                if (modName.equals("global")) isGlobal = true;
            }

            // 1. Global/Public methods without 'with sharing'
            if (!withSharing && (isPublic || isGlobal)) {
                asCtx(data).addViolation(method,
                    "Global/Public method in class without 'with sharing' may expose sensitive data. [OWASP A01]");
            }

            // 2. Webservice / REST methods missing auth check
            for (ASTAnnotation ann : method.descendants(ASTAnnotation.class)) {
                String name = ann.getImage() == null ? "" : ann.getImage();
                if (name.equalsIgnoreCase("RestResource") || name.equalsIgnoreCase("WebService")) {
                    if (!hasAuthCheck(method)) {
                        asCtx(data).addViolation(method,
                            "Webservice/REST method missing authentication check. [OWASP A01/A05]");
                    }
                }
            }

            // 3. SObject access without sharing enforcement
            for (ASTMethodCallExpression call : method.descendants(ASTMethodCallExpression.class)) {
                String def = call.getDefiningType() == null ? "" : call.getDefiningType();
                String m = call.getMethodName() == null ? "" : call.getMethodName();
                if ("Database".equals(def) && (m.equals("query") || m.equals("update") || m.equals("insert") || m.equals("delete"))) {
                    if (!withSharing) {
                        asCtx(data).addViolation(call,
                            "SObject access without sharing enforcement detected. [OWASP A01]");
                    }
                }
            }
        }
        return data;
    }

    private boolean hasAuthCheck(ASTMethod method) {
        for (ASTMethodCallExpression call : method.descendants(ASTMethodCallExpression.class)) {
            String name = call.getMethodName() == null ? "" : call.getMethodName().toLowerCase();
            if (name.contains("isuserauthorized") || name.contains("checkaccess") || name.contains("haspermission")) {
                return true;
            }
        }
        return false;
    }
}
