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
        // Target user classes
        return RuleTargetSelector.forTypes(ASTUserClass.class);
    }

    @Override
    public Object visit(ASTUserClass node, Object data) {
        boolean withSharing = node.getImage() != null && node.getImage().contains("with sharing");

        for (ASTMethod method : node.descendants(ASTMethod.class)) {

            // Skip test methods or system-level
            if (method.isTestMethod() || method.isTestAnnotationPresent()) {
                continue;
            }

            // 1. Detect Global/Public methods without 'with sharing'
            if (!withSharing && (method.isPublic() || method.isGlobal())) {
                asCtx(data).addViolation(method, 
                    "Global/Public method in class without 'with sharing' may expose sensitive data. [OWASP A01]");
            }

            // 2. Detect webservice / REST methods missing auth
            for (ASTAnnotation ann : method.descendants(ASTAnnotation.class)) {
                String name = ann.getImage() == null ? "" : ann.getImage();
                if (name.equalsIgnoreCase("RestResource") || name.equalsIgnoreCase("WebService")) {
                    if (!hasAuthCheck(method)) {
                        asCtx(data).addViolation(method,
                            "Webservice/REST method missing authentication check. [OWASP A01/A05]");
                    }
                }
            }

            // 3. Detect SObject access without sharing enforcement
            for (ASTMethodCallExpression call : method.descendants(ASTMethodCallExpression.class)) {
                String def = call.getDefiningType() == null ? "" : call.getDefiningType();
                String m = call.getMethodName() == null ? "" : call.getMethodName();
                if ("Database".equals(def) && (m.equals("query") || m.equals("update") || m.equals("insert") || m.equals("delete"))) {
                    if (!withSharing) {
                        asCtx(data).addViolation(call, "SObject access without sharing enforcement detected. [OWASP A01]");
                    }
                }
            }
        }
        return data;
    }

    /**
     * Simple heuristic: check if method contains calls to authentication checks.
     * Could be improved to detect real Auth patterns in Apex.
     */
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
